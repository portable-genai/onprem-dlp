"""Structured-source samplers with zero dependencies: CSV files and SQLite."""

from __future__ import annotations

import csv
import os
import sqlite3
from collections.abc import Sequence


class CsvSampler:
    """Treats one CSV file as a single table named after the file."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._table = os.path.splitext(os.path.basename(path))[0]

    @property
    def source_name(self) -> str:
        return self.path

    def tables(self) -> Sequence[str]:
        return (self._table,)

    def columns(self, table: str) -> Sequence[str]:  # noqa: ARG002
        with open(self.path, newline="", encoding="utf-8-sig") as fh:
            reader = csv.reader(fh)
            return tuple(next(reader, []))

    def sample(self, table: str, column: str, limit: int) -> Sequence[str | None]:  # noqa: ARG002
        out: list[str | None] = []
        with open(self.path, newline="", encoding="utf-8-sig") as fh:
            for row in csv.DictReader(fh):
                if len(out) >= limit:
                    break
                out.append(row.get(column))
        return out


class InlineSampler:
    """Wraps an in-memory ``{column: [values]}`` mapping — used by the REST API and
    anywhere a caller already holds the sample and just wants a classification."""

    def __init__(self, columns: dict[str, list[str | None]], name: str = "inline") -> None:
        self._columns = columns
        self._name = name

    @property
    def source_name(self) -> str:
        return self._name

    def tables(self) -> Sequence[str]:
        return (self._name,)

    def columns(self, table: str) -> Sequence[str]:  # noqa: ARG002
        return tuple(self._columns.keys())

    def sample(self, table: str, column: str, limit: int) -> Sequence[str | None]:  # noqa: ARG002
        return tuple(self._columns.get(column, ())[:limit])


def _quote_ident(name: str) -> str:
    """Quote a SQLite identifier, doubling embedded double-quotes. SQLite cannot
    parameter-bind identifiers, so table/column names are interpolated — this closes
    the quote-breakout even for an adversarially-named column."""
    return '"' + str(name).replace('"', '""') + '"'


class SqliteSampler:
    """Samples every user table in a SQLite database file."""

    def __init__(self, path: str) -> None:
        self.path = path

    @property
    def source_name(self) -> str:
        return self.path

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(f"file:{self.path}?mode=ro", uri=True)

    def tables(self) -> Sequence[str]:
        with self._connect() as con:
            rows = con.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        return tuple(r[0] for r in rows)

    def columns(self, table: str) -> Sequence[str]:
        with self._connect() as con:
            rows = con.execute(f"PRAGMA table_info({_quote_ident(table)})").fetchall()
        return tuple(r[1] for r in rows)

    def sample(self, table: str, column: str, limit: int) -> Sequence[str | None]:
        with self._connect() as con:
            rows = con.execute(
                f"SELECT {_quote_ident(column)} FROM {_quote_ident(table)} LIMIT ?",
                (int(limit),),
            ).fetchall()
        return tuple(None if r[0] is None else str(r[0]) for r in rows)
