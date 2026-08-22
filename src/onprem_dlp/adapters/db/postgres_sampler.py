"""PostgreSQL sampler (``pip install 'onprem-dlp[postgres]'``).

Read-only by construction: it issues only ``information_schema`` lookups and bounded
``SELECT col FROM table LIMIT n`` samples, and sets the transaction read-only.
"""

from __future__ import annotations

from collections.abc import Sequence
from urllib.parse import parse_qs, urlsplit


class PostgresSampler:
    def __init__(self, dsn: str, schema: str = "public") -> None:
        parsed = urlsplit(dsn)
        query = parse_qs(parsed.query, keep_blank_values=True)
        if query.get("sslmode") != ["verify-full"]:
            raise ValueError("PostgreSQL DSN must set sslmode=verify-full")
        if len(query.get("sslrootcert", [])) != 1 or not query["sslrootcert"][0].strip():
            raise ValueError("PostgreSQL DSN must name a non-empty sslrootcert trust anchor")
        self.dsn = dsn
        self.schema = schema
        self._conn = None

    @property
    def source_name(self) -> str:
        return f"postgres:{self.schema}"

    def _connection(self):
        if self._conn is None:
            import psycopg  # lazy: optional dependency

            self._conn = psycopg.connect(self.dsn, autocommit=False)
            with self._conn.cursor() as cur:
                cur.execute("SET default_transaction_read_only = on")
        return self._conn

    def tables(self) -> Sequence[str]:
        with self._connection().cursor() as cur:
            cur.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = %s AND table_type = 'BASE TABLE' ORDER BY table_name",
                (self.schema,),
            )
            return tuple(r[0] for r in cur.fetchall())

    def columns(self, table: str) -> Sequence[str]:
        with self._connection().cursor() as cur:
            cur.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = %s AND table_name = %s ORDER BY ordinal_position",
                (self.schema, table),
            )
            return tuple(r[0] for r in cur.fetchall())

    def sample(self, table: str, column: str, limit: int) -> Sequence[str | None]:
        from psycopg import sql  # lazy: optional dependency

        query = sql.SQL("SELECT {col} FROM {schema}.{tbl} LIMIT {lim}").format(
            col=sql.Identifier(column),
            schema=sql.Identifier(self.schema),
            tbl=sql.Identifier(table),
            lim=sql.Literal(int(limit)),
        )
        with self._connection().cursor() as cur:
            cur.execute(query)
            return tuple(None if r[0] is None else str(r[0]) for r in cur.fetchall())
