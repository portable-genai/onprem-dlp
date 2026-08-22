"""BigQuery column sampler (``pip install 'onprem-dlp[bigquery]'``).

The Google SDK is imported only when the adapter first connects. Metadata is sorted
and sample rows are ordered by their JSON representation so a replay over unchanged
data returns the same bounded values.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any
from urllib.parse import unquote, urlsplit


def _safe_bigquery_identifier(value: str, *, component: str) -> str:
    project_id = r"[a-z][a-z0-9-]{4,28}[a-z0-9]"
    patterns = {
        "project": rf"(?:{project_id}|[a-z0-9][a-z0-9.-]*\.[a-z]{{2,}}:{project_id})",
        "dataset": r"[A-Za-z_][A-Za-z0-9_]*",
        "table": r"[A-Za-z0-9_]+",
        "column": r"[A-Za-z_][A-Za-z0-9_]*",
    }
    if not re.fullmatch(patterns[component], value):
        raise ValueError(f"invalid BigQuery {component}")
    return value


class BigQuerySampler:
    def __init__(self, project: str, dataset: str, *, client: Any | None = None) -> None:
        self.project = _safe_bigquery_identifier(project, component="project")
        self.dataset = _safe_bigquery_identifier(dataset, component="dataset")
        self._client = client

    @classmethod
    def from_uri(cls, uri: str) -> BigQuerySampler:
        try:
            parsed = urlsplit(uri)
        except ValueError as exc:
            raise ValueError("invalid BigQuery source URI") from exc
        if parsed.scheme.lower() != "bigquery":
            raise ValueError("BigQuery source must use bigquery://project/dataset")
        project = parsed.netloc
        # Domain-scoped legacy project IDs are shaped like
        # ``example.com:legacy-project``. A numeric suffix, however, is a TCP
        # port and is never part of a BigQuery project identifier.
        numeric_port = ":" in project and project.rsplit(":", 1)[1].isdigit()
        if (
            parsed.username is not None
            or parsed.password is not None
            or "@" in parsed.netloc
            or numeric_port
            or parsed.query
            or parsed.fragment
            or "?" in uri
            or "#" in uri
        ):
            raise ValueError(
                "BigQuery source URI must not contain userinfo, port, query, or fragment"
            )
        decoded_path = unquote(parsed.path)
        if (
            not project
            or not decoded_path.startswith("/")
            or decoded_path == "/"
            or "/" in decoded_path[1:]
        ):
            raise ValueError("BigQuery source must use bigquery://project/dataset")
        return cls(project, decoded_path[1:])

    @property
    def source_name(self) -> str:
        return f"bigquery:{self.project}.{self.dataset}"

    def _connection(self):
        if self._client is None:
            from google.cloud import bigquery  # lazy: optional dependency

            self._client = bigquery.Client(project=self.project)
        return self._client

    @property
    def _dataset_ref(self) -> str:
        return f"{self.project}.{self.dataset}"

    def tables(self) -> Sequence[str]:
        names = (item.table_id for item in self._connection().list_tables(self._dataset_ref))
        return tuple(sorted(names))

    def columns(self, table: str) -> Sequence[str]:
        table = _safe_bigquery_identifier(table, component="table")
        schema = self._connection().get_table(f"{self._dataset_ref}.{table}").schema
        return tuple(field.name for field in schema)

    def sample(self, table: str, column: str, limit: int) -> Sequence[str | None]:
        limit = int(limit)
        if limit < 0:
            raise ValueError("sample limit must be non-negative")
        table = _safe_bigquery_identifier(table, component="table")
        column = _safe_bigquery_identifier(column, component="column")
        if table not in self.tables() or column not in self.columns(table):
            raise ValueError(f"unknown BigQuery column {table}.{column}")
        table_ref = f"{self._dataset_ref}.{table}"
        query = (
            f"SELECT `{column}` FROM `{table_ref}` "
            f"ORDER BY TO_JSON_STRING(`{column}`) LIMIT {limit}"
        )
        rows = self._connection().query(query).result()
        return tuple(None if row[0] is None else str(row[0]) for row in rows)
