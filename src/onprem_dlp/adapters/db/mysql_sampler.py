"""MySQL column sampler (``pip install 'onprem-dlp[mysql]'``).

The connector import is lazy and the session starts a read-only transaction before
any metadata or sample query. Table/column names must first exist in
``information_schema``; only those server-returned identifiers are quoted into SQL.
TLS certificate and host verification default on. Use the sampler as a context
manager (or call ``close``) to roll back and release the owned connection.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from contextlib import suppress
from typing import Any, Literal
from urllib.parse import parse_qs, unquote, urlsplit

from ...netguard import read_env_setting

_PASSWORD_ENV = "ONPREM_DLP_MYSQL_PASSWORD"


def _quote_mysql_identifier(value: str) -> str:
    return "`" + value.replace("`", "``") + "`"


def _password(dsn_password: str | None) -> str:
    """Resolve the connection password, reading the environment in three states.

    A password in the DSN userinfo wins, including a deliberately empty one
    (``mysql://reader:@host/db``), so a genuinely passwordless server stays expressible.
    Otherwise ``ONPREM_DLP_MYSQL_PASSWORD`` decides, and the two states that
    ``os.environ.get(name, "")`` would collapse are kept separate:

    * **unset**: no credential was configured anywhere, so none is sent. This is the documented
      default, and it grants nothing: the server still decides whether to admit the connection.
    * **set and empty**: an intent WAS expressed and it names no secret, which is what a
      misprovisioned secret key looks like. Refusing here is the difference between a loud
      configuration error and a silent passwordless read of a production table full of raw PII.
    """
    if dsn_password is not None:
        return unquote(dsn_password)
    setting = read_env_setting(_PASSWORD_ENV).require_not_configured_empty(
        "a password (unset the variable to connect without one, or supply the secret)"
    )
    # The three-state decision uses the stripped view, but the secret itself is delivered raw:
    # whitespace an operator deliberately made part of a password is not silently cut.
    return setting.raw if setting.has_value and setting.raw is not None else ""


def _parse_bool_option(name: str, values: list[str]) -> bool:
    if len(values) != 1 or values[0].lower() not in {"true", "false"}:
        raise ValueError(f"MySQL DSN option {name} must appear once as true or false")
    return values[0].lower() == "true"


class MySqlSampler:
    def __init__(
        self,
        dsn: str,
        *,
        connection_factory: Callable[..., Any] | None = None,
    ) -> None:
        parsed = urlsplit(dsn)
        if parsed.scheme.lower() != "mysql":
            raise ValueError("MySQL DSN must use mysql://")
        database = unquote(parsed.path.lstrip("/"))
        if not parsed.hostname or not database or "/" in database:
            raise ValueError("MySQL DSN must include one host and database")
        options = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
        allowed_options = {"ssl_ca", "ssl_verify_cert", "ssl_verify_identity"}
        unknown_options = sorted(set(options) - allowed_options)
        if unknown_options:
            raise ValueError(f"unsupported MySQL DSN option(s): {', '.join(unknown_options)}")
        ssl_ca_values = options.get("ssl_ca", [])
        if len(ssl_ca_values) > 1 or ssl_ca_values == [""]:
            raise ValueError("MySQL DSN option ssl_ca must be one non-empty path")
        self._connection_kwargs: dict[str, Any] = {
            "host": parsed.hostname,
            "port": parsed.port or 3306,
            "user": unquote(parsed.username or ""),
            "password": _password(parsed.password),
            "database": database,
            # Connector/Python negotiates TLS by default. Verification is explicit
            # and secure by default; an adopter must deliberately opt out.
            "ssl_verify_cert": _parse_bool_option(
                "ssl_verify_cert", options.get("ssl_verify_cert", ["true"])
            ),
            "ssl_verify_identity": _parse_bool_option(
                "ssl_verify_identity", options.get("ssl_verify_identity", ["true"])
            ),
        }
        if ssl_ca_values:
            self._connection_kwargs["ssl_ca"] = ssl_ca_values[0]
        self.database = database
        self._connection_factory = connection_factory
        self._conn: Any | None = None

    @property
    def source_name(self) -> str:
        return f"mysql:{self.database}"

    def _connection(self):
        if self._conn is None:
            factory = self._connection_factory
            if factory is None:
                import mysql.connector  # lazy: optional dependency

                factory = mysql.connector.connect
            connection = factory(**self._connection_kwargs)
            # Fail closed when the server/driver cannot establish a read-only
            # transaction; never silently fall back to a writable session.
            try:
                connection.start_transaction(readonly=True)
            except Exception:
                with suppress(Exception):
                    connection.close()
                raise
            self._conn = connection
        return self._conn

    def __enter__(self) -> MySqlSampler:
        self._connection()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> Literal[False]:
        try:
            self.close()
        except Exception:
            if exc_type is None:
                raise
        return False

    def close(self) -> None:
        """Roll back the read-only transaction and release its connection."""
        connection, self._conn = self._conn, None
        if connection is None:
            return
        try:
            connection.rollback()
        finally:
            connection.close()

    def tables(self) -> Sequence[str]:
        with self._connection().cursor() as cur:
            cur.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = %s AND table_type = 'BASE TABLE' "
                "ORDER BY BINARY table_name, table_name",
                (self.database,),
            )
            return tuple(row[0] for row in cur.fetchall())

    def columns(self, table: str) -> Sequence[str]:
        with self._connection().cursor() as cur:
            cur.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = %s AND table_name = %s "
                "ORDER BY ordinal_position, BINARY column_name, column_name",
                (self.database, table),
            )
            return tuple(row[0] for row in cur.fetchall())

    def sample(self, table: str, column: str, limit: int) -> Sequence[str | None]:
        limit = int(limit)
        if limit < 0:
            raise ValueError("sample limit must be non-negative")
        if table not in self.tables() or column not in self.columns(table):
            raise ValueError(f"unknown MySQL column {table}.{column}")
        query = (
            f"SELECT {_quote_mysql_identifier(column)} "
            f"FROM {_quote_mysql_identifier(table)} "
            f"ORDER BY {_quote_mysql_identifier(column)} IS NULL, "
            f"SHA2(CAST({_quote_mysql_identifier(column)} AS BINARY), 256), "
            f"OCTET_LENGTH(CAST({_quote_mysql_identifier(column)} AS BINARY)), "
            f"HEX(CAST({_quote_mysql_identifier(column)} AS BINARY)) LIMIT %s"
        )
        with self._connection().cursor() as cur:
            cur.execute(query, (limit,))
            return tuple(None if row[0] is None else str(row[0]) for row in cur.fetchall())
