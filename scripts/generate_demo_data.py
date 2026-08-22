"""Regenerate the synthetic demo dataset (demo/customers.csv + demo/customers.db).

All identifiers are synthetic but CHECKSUM-VALID (NRIC/phone/email formats), so the
demo exercises the real validators. Deterministic: same seed -> same files.
"""

from __future__ import annotations

import csv
import random
import sqlite3
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEMO = REPO / "demo"

_ST_TABLE = "JZIHGFEDCBA"
_WEIGHTS = (2, 7, 6, 5, 4, 3, 2)

FIRST = [
    "Wei Ming",
    "Aiko",
    "Priya",
    "Liam",
    "Mei Lin",
    "Kenji",
    "Sarah",
    "Rajesh",
    "Hannah",
    "Daniel",
    "Yuki",
    "Nurul",
    "Marcus",
    "Ananya",
    "Chloe",
    "Hiroshi",
    "Grace",
    "Arjun",
    "Isabelle",
    "Takeshi",
]
LAST = [
    "Tan",
    "Sato",
    "Sharma",
    "O'Connor",
    "Lim",
    "Yamamoto",
    "Lee",
    "Iyer",
    "Wong",
    "Nakamura",
    "Ng",
    "Rahman",
    "Chen",
    "Patel",
    "Goh",
    "Suzuki",
    "Ho",
    "Krishnan",
    "Teo",
    "Kobayashi",
]
NATIONALITIES = ["SG", "JP", "IN", "MY", "AU"]
CONDITIONS = ["none", "hypertension", "diabetes-t2", "asthma", "none"]
PRODUCTS = ["SAV-01", "CHQ-02", "FD-12", "LOAN-77"]
BRANCHES = ["BR001", "BR002", "BR003"]


def make_nric(rng: random.Random) -> str:
    digits = f"{rng.randrange(0, 10_000_000):07d}"
    s = sum(int(d) * w for d, w in zip(digits, _WEIGHTS, strict=True))
    return f"S{digits}{_ST_TABLE[s % 11]}"


def main() -> None:
    rng = random.Random(42)
    DEMO.mkdir(exist_ok=True)
    rows = []
    for i in range(1, 41):
        first, last = rng.choice(FIRST), rng.choice(LAST)
        rows.append(
            {
                "customer_id": f"CUST{i:05d}",
                "full_name": f"{first} {last}",
                "email": (
                    f"{first.split()[0].lower()}.{last.lower().replace(chr(39), '')}{i}@example.com"
                ),
                "phone": f"+65 9{rng.randrange(100, 1000)} {rng.randrange(1000, 10000)}",
                "nric": make_nric(rng),
                "date_of_birth": (
                    f"{rng.randrange(1955, 2003)}-{rng.randrange(1, 13):02d}"
                    f"-{rng.randrange(1, 29):02d}"
                ),
                "gender": rng.choice(["F", "M"]),
                "postal_code": f"{rng.randrange(100000, 800000):06d}",
                "nationality": rng.choice(NATIONALITIES),
                "salary_sgd": str(rng.randrange(38, 240) * 1000),
                "health_condition": rng.choice(CONDITIONS),
                "account_balance": f"{rng.randrange(1000, 900000)}.{rng.randrange(0, 100):02d}",
                "product_code": rng.choice(PRODUCTS),
                "branch_code": rng.choice(BRANCHES),
            }
        )

    csv_path = DEMO / "customers.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    db_path = DEMO / "customers.db"
    db_path.unlink(missing_ok=True)
    con = sqlite3.connect(db_path)
    cols = ", ".join(f'"{c}" TEXT' for c in rows[0])
    con.execute(f"CREATE TABLE customers ({cols})")
    con.executemany(
        f"INSERT INTO customers VALUES ({', '.join('?' for _ in rows[0])})",
        [tuple(r.values()) for r in rows],
    )
    con.commit()
    con.close()
    print(f"wrote {csv_path} and {db_path} ({len(rows)} rows)")


if __name__ == "__main__":
    main()
