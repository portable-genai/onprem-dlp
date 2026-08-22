"""Database adapters stay read-only, deterministic, and SDK-free until first I/O."""

from types import SimpleNamespace

import pytest

from onprem_dlp.adapters.db import BigQuerySampler, MySqlSampler, PostgresSampler
from onprem_dlp.netguard import ConfiguredEmptyError


def test_postgres_requires_verified_tls_and_a_trust_anchor():
    with pytest.raises(ValueError, match="sslmode=verify-full"):
        PostgresSampler("postgresql://reader@db.example/core")
    with pytest.raises(ValueError, match="sslrootcert"):
        PostgresSampler("postgresql://reader@db.example/core?sslmode=verify-full")
    sampler = PostgresSampler(
        "postgresql://reader@db.example/core?sslmode=verify-full&sslrootcert=/etc/ssl/certs/ca.pem"
    )
    assert "sslmode=verify-full" in sampler.dsn


class FakeMySqlCursor:
    def __init__(self, connection):
        self.connection = connection
        self._rows = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, query, params):
        self.connection.queries.append((query, params))
        if "information_schema.tables" in query:
            self._rows = [("accounts",)]
        elif "information_schema.columns" in query:
            self._rows = [("email",), ("balance",)]
        else:
            self._rows = [("a@example.test",), ("z@example.test",), (None,)]

    def fetchall(self):
        return self._rows


class FakeMySqlConnection:
    def __init__(self):
        self.readonly = False
        self.queries = []
        self.rolled_back = False
        self.closed = False

    def start_transaction(self, *, readonly):
        self.readonly = readonly

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True

    def cursor(self):
        return FakeMySqlCursor(self)


def test_mysql_sampler_starts_read_only_and_orders_bounded_sample():
    connection = FakeMySqlConnection()
    sampler = MySqlSampler(
        "mysql://reader:secret@db.example:3307/core",
        connection_factory=lambda **kwargs: connection,
    )

    assert sampler.tables() == ("accounts",)
    assert sampler.columns("accounts") == ("email", "balance")
    assert sampler.sample("accounts", "email", 3) == (
        "a@example.test",
        "z@example.test",
        None,
    )
    assert connection.readonly is True
    query, params = connection.queries[-1]
    assert (
        "ORDER BY `email` IS NULL, SHA2(CAST(`email` AS BINARY), 256), "
        "OCTET_LENGTH(CAST(`email` AS BINARY)), "
        "HEX(CAST(`email` AS BINARY)) LIMIT %s"
    ) in query
    assert params == (3,)
    assert "ORDER BY BINARY table_name, table_name" in connection.queries[0][0]
    assert "ORDER BY ordinal_position, BINARY column_name, column_name" in connection.queries[1][0]


def test_mysql_sampler_rejects_unknown_identifier_before_sample_query():
    connection = FakeMySqlConnection()
    sampler = MySqlSampler(
        "mysql://reader@db.example/core",
        connection_factory=lambda **kwargs: connection,
    )
    with pytest.raises(ValueError, match="unknown MySQL column"):
        sampler.sample("accounts", "password", 2)
    assert not any(query.startswith("SELECT `") for query, _ in connection.queries)


def test_mysql_password_can_be_injected_without_putting_it_in_the_dsn(monkeypatch):
    monkeypatch.setenv("ONPREM_DLP_MYSQL_PASSWORD", "injected-secret")
    connection = FakeMySqlConnection()
    received = {}

    def connect(**kwargs):
        received.update(kwargs)
        return connection

    MySqlSampler("mysql://reader@db.example/core", connection_factory=connect).tables()
    assert received["password"] == "injected-secret"


def test_an_explicitly_empty_mysql_password_refuses_instead_of_connecting_without_one(monkeypatch):
    """A blank Secret key must not look identical to never having configured a password."""
    monkeypatch.setenv("ONPREM_DLP_MYSQL_PASSWORD", "")
    with pytest.raises(ConfiguredEmptyError, match="ONPREM_DLP_MYSQL_PASSWORD"):
        MySqlSampler("mysql://reader@db.example/core")


def test_an_unset_mysql_password_still_connects_without_one(monkeypatch):
    """Absence grants nothing: no credential is sent and the server decides."""
    monkeypatch.delenv("ONPREM_DLP_MYSQL_PASSWORD", raising=False)
    received = {}

    def connect(**kwargs):
        received.update(kwargs)
        return FakeMySqlConnection()

    MySqlSampler("mysql://reader@db.example/core", connection_factory=connect).tables()
    assert received["password"] == ""


def test_the_dsn_password_wins_and_is_the_only_one_percent_decoded(monkeypatch):
    monkeypatch.setenv("ONPREM_DLP_MYSQL_PASSWORD", "ignored")
    received = {}

    def connect(**kwargs):
        received.update(kwargs)
        return FakeMySqlConnection()

    MySqlSampler("mysql://reader:a%20b@db.example/core", connection_factory=connect).tables()
    assert received["password"] == "a b"

    # A deliberately empty DSN password is an expressed intent and still beats the environment.
    MySqlSampler("mysql://reader:@db.example/core", connection_factory=connect).tables()
    assert received["password"] == ""


def test_an_environment_password_is_delivered_verbatim(monkeypatch):
    """Percent signs and inner whitespace are part of the secret, not encoding to undo."""
    monkeypatch.setenv("ONPREM_DLP_MYSQL_PASSWORD", "a%20b c")
    received = {}

    def connect(**kwargs):
        received.update(kwargs)
        return FakeMySqlConnection()

    MySqlSampler("mysql://reader@db.example/core", connection_factory=connect).tables()
    assert received["password"] == "a%20b c"


def test_mysql_tls_options_are_strict_typed_and_secure_by_default():
    received = {}
    connection = FakeMySqlConnection()

    def connect(**kwargs):
        received.update(kwargs)
        return connection

    sampler = MySqlSampler(
        "mysql://reader@db.example/core"
        "?ssl_ca=%2Fetc%2Fmysql%2Fca.pem"
        "&ssl_verify_cert=true&ssl_verify_identity=false",
        connection_factory=connect,
    )
    sampler.tables()
    assert received["ssl_ca"] == "/etc/mysql/ca.pem"
    assert received["ssl_verify_cert"] is True
    assert received["ssl_verify_identity"] is False

    defaults = {}
    MySqlSampler(
        "mysql://reader@db.example/core",
        connection_factory=lambda **kwargs: defaults.update(kwargs) or FakeMySqlConnection(),
    ).tables()
    assert defaults["ssl_verify_cert"] is True
    assert defaults["ssl_verify_identity"] is True


@pytest.mark.parametrize(
    "query",
    [
        "connect_timeout=10",
        "ssl_verify_cert=yes",
        "ssl_verify_identity=",
        "ssl_ca=",
        "ssl_ca=/a&ssl_ca=/b",
    ],
)
def test_mysql_rejects_unknown_or_malformed_tls_options(query):
    with pytest.raises(ValueError):
        MySqlSampler(f"mysql://reader@db.example/core?{query}")


def test_mysql_connection_is_not_retained_and_is_closed_if_read_only_start_fails():
    class FailingConnection(FakeMySqlConnection):
        def start_transaction(self, *, readonly):
            raise RuntimeError("read-only unavailable")

    failed = FailingConnection()
    recovered = FakeMySqlConnection()
    attempts = iter((failed, recovered))
    sampler = MySqlSampler(
        "mysql://reader@db.example/core",
        connection_factory=lambda **kwargs: next(attempts),
    )

    with pytest.raises(RuntimeError, match="read-only unavailable"):
        sampler.tables()
    assert failed.closed is True
    assert sampler.tables() == ("accounts",)
    assert recovered.readonly is True


def test_mysql_context_rolls_back_and_closes_successful_connection():
    connection = FakeMySqlConnection()
    with MySqlSampler(
        "mysql://reader@db.example/core",
        connection_factory=lambda **kwargs: connection,
    ) as sampler:
        assert sampler.tables() == ("accounts",)
        assert connection.closed is False
    assert connection.rolled_back is True
    assert connection.closed is True


class FakeBigQueryResult:
    def __init__(self, rows):
        self._rows = rows

    def result(self):
        return self._rows


class FakeBigQueryClient:
    def __init__(self):
        self.queries = []

    def list_tables(self, dataset):
        assert dataset == "sample-project.customer_data"
        return [SimpleNamespace(table_id="customers"), SimpleNamespace(table_id="accounts")]

    def get_table(self, table):
        assert table.endswith(".customers")
        return SimpleNamespace(
            schema=[SimpleNamespace(name="email"), SimpleNamespace(name="customer_id")]
        )

    def query(self, query):
        self.queries.append(query)
        return FakeBigQueryResult([("a@example.test",), ("z@example.test",), (None,)])


def test_bigquery_sampler_sorts_metadata_and_orders_bounded_sample():
    client = FakeBigQueryClient()
    sampler = BigQuerySampler("sample-project", "customer_data", client=client)

    assert sampler.tables() == ("accounts", "customers")
    assert sampler.columns("customers") == ("email", "customer_id")
    assert sampler.sample("customers", "email", 3) == (
        "a@example.test",
        "z@example.test",
        None,
    )
    assert client.queries == [
        "SELECT `email` FROM `sample-project.customer_data.customers` "
        "ORDER BY TO_JSON_STRING(`email`) LIMIT 3"
    ]


@pytest.mark.parametrize(
    "uri",
    [
        "bigquery://user:top-secret@sample-project/customer_data",
        "bigquery://sample-project/customer_data?token=top-secret",
        "bigquery://sample-project/customer_data?",
        "bigquery://sample-project/customer_data#top-secret",
        "bigquery://sample-project/customer_data#",
        "bigquery://sample-project:443/customer_data",
        "bigquery://sample-project/customer_data/extra",
        "bigquery://sample-project/customer_data%2Fextra",
        "bigquery:///customer_data",
        "bigquery://sample-project/",
    ],
)
def test_bigquery_uri_rejects_ambiguous_or_secret_bearing_components(uri):
    with pytest.raises(ValueError) as error:
        BigQuerySampler.from_uri(uri)
    assert "top-secret" not in str(error.value)


def test_bigquery_uri_decodes_exactly_one_dataset_component():
    sampler = BigQuerySampler.from_uri("bigquery://sample-project/customer_data")
    assert sampler.project == "sample-project"
    assert sampler.dataset == "customer_data"
    assert sampler.source_name == "bigquery:sample-project.customer_data"


def test_bigquery_uri_accepts_domain_scoped_legacy_project_without_treating_it_as_port():
    sampler = BigQuerySampler.from_uri("bigquery://example.com:legacy-project/customer_data")
    assert sampler.project == "example.com:legacy-project"
    assert sampler.dataset == "customer_data"
    assert sampler.source_name == "bigquery:example.com:legacy-project.customer_data"


@pytest.mark.parametrize("limit", [-1, -20])
def test_remote_samplers_reject_negative_limits(limit):
    with pytest.raises(ValueError, match="non-negative"):
        BigQuerySampler("sample-project", "customer_data", client=FakeBigQueryClient()).sample(
            "customers", "email", limit
        )
    with pytest.raises(ValueError, match="non-negative"):
        MySqlSampler(
            "mysql://reader@db.example/core",
            connection_factory=lambda **kwargs: FakeMySqlConnection(),
        ).sample("accounts", "email", limit)
