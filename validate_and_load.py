"""
validate_and_load.py
Stage: Data Validation -> Feature Engineering -> Load to SQL Server
Input : cleaned_cic_ids2017.csv  (output of Data_Transformation.py)

Examples (PowerShell):
    # 1) Dry run: validate + build features + save validated_features.csv (no DB needed)
    python validate_and_load.py

    # 2) Quick upload test with 1000 rows
    python validate_and_load.py --upload --sample 1000 --server "localhost\\SQLEXPRESS" --database SecurityDB

    # 3) Full upload
    python validate_and_load.py --upload --server "localhost\\SQLEXPRESS" --database SecurityDB

SQL login (optional): set env vars SQL_USER and SQL_PASSWORD.
If they are not set, Windows Authentication is used.
"""
import argparse
import os
import sys
from urllib.parse import quote_plus

import numpy as np
import pandas as pd

REQUIRED_COLUMNS = [
    "timestamp", "label", "destination_port", "flow_duration",
    "total_fwd_packets", "total_backward_packets",
    "total_length_of_fwd_packets", "total_length_of_bwd_packets",
]

ATTACK_CATEGORY = {
    "BENIGN": "Benign",
    "DOS HULK": "DoS",
    "DOS GOLDENEYE": "DoS",
    "DDOS": "DDoS",
    "PORTSCAN": "PortScan",
    "FTP-PATATOR": "Brute Force",
    "SSH-PATATOR": "Brute Force",
    "BOT": "Botnet",
}

# These columns legitimately contain -1 in CIC-IDS2017, so don't flag them.
NEGATIVE_ALLOWED = {"init_win_bytes_forward", "init_win_bytes_backward"}

FLAG_COLUMNS = [
    "fin_flag_count", "syn_flag_count", "rst_flag_count", "psh_flag_count",
    "ack_flag_count", "urg_flag_count", "cwe_flag_count", "ece_flag_count",
]


# ---------------------------------------------------------------- 1. Validation
def validate(df: pd.DataFrame) -> pd.DataFrame:
    errors, warnings = [], []

    if df.empty:
        sys.exit("ERROR: the dataset is empty")

    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        sys.exit(f"ERROR: missing required columns: {missing}")

    # Nulls
    null_counts = df.isna().sum()
    null_counts = null_counts[null_counts > 0]
    if not null_counts.empty:
        errors.append(f"null values found: {null_counts.to_dict()}")

    # Inf
    num_cols = df.select_dtypes(include=[np.number]).columns
    inf_count = int(np.isinf(df[num_cols]).sum().sum())
    if inf_count:
        errors.append(f"{inf_count} infinite values found")

    # Timestamp
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    bad_ts = int(df["timestamp"].isna().sum())
    if bad_ts:
        errors.append(f"{bad_ts} unparsable timestamps")

    # Port range
    bad_port = int((~df["destination_port"].between(0, 65535)).sum())
    if bad_port:
        errors.append(f"{bad_port} rows with destination_port outside 0-65535")

    # Labels
    unknown = sorted(set(df["label"].unique()) - set(ATTACK_CATEGORY))
    if unknown:
        warnings.append(f"labels not in the known list: {unknown}")

    # Negative values (suspicious in counts/lengths/durations)
    check_cols = [c for c in num_cols if c not in NEGATIVE_ALLOWED]
    neg = (df[check_cols] < 0).sum()
    neg = neg[neg > 0]
    if not neg.empty:
        warnings.append(f"negative values in: {neg.to_dict()}")

    # Duplicates (ignoring the simulated timestamp)
    dup = int(df.drop(columns=["timestamp"]).duplicated().sum())
    if dup:
        warnings.append(f"{dup} duplicate rows (ignoring timestamp) - kept, not removed")

    # Constant columns
    constant = [c for c in num_cols if df[c].nunique() <= 1]
    if constant:
        warnings.append(f"{len(constant)} constant columns (no information): {constant}")

    # Redundant duplicate column from the original CSV ("Fwd Header Length.1")
    if "fwd_header_length_1" in df.columns and "fwd_header_length" in df.columns:
        if df["fwd_header_length_1"].equals(df["fwd_header_length"]):
            df = df.drop(columns=["fwd_header_length_1"])
            warnings.append("dropped fwd_header_length_1 (identical copy of fwd_header_length)")

    print(f"Validation: {len(errors)} error(s), {len(warnings)} warning(s)")
    for w in warnings:
        print("  WARNING:", w)
    for e in errors:
        print("  ERROR:  ", e)
    if errors:
        sys.exit("Validation failed - fix the errors above before loading.")
    return df


# ------------------------------------------------------- 2. Feature Engineering
def add_features(df: pd.DataFrame) -> pd.DataFrame:
    df["total_packets"] = df["total_fwd_packets"] + df["total_backward_packets"]
    df["total_bytes"] = df["total_length_of_fwd_packets"] + df["total_length_of_bwd_packets"]
    df["bytes_per_packet"] = (
        df["total_bytes"] / df["total_packets"].replace(0, np.nan)
    ).fillna(0)
    df["fwd_bwd_packet_ratio"] = df["total_fwd_packets"] / (df["total_backward_packets"] + 1)

    # CIC-IDS2017 flow_duration is in microseconds
    df["flow_duration_sec"] = df["flow_duration"].clip(lower=0) / 1_000_000

    present_flags = [c for c in FLAG_COLUMNS if c in df.columns]
    df["total_flag_count"] = df[present_flags].sum(axis=1)

    df["is_well_known_port"] = (df["destination_port"] < 1024).astype(int)

    df["is_attack"] = (df["label"] != "BENIGN").astype(int)
    df["attack_category"] = df["label"].map(ATTACK_CATEGORY).fillna("Other")

    df["hour"] = df["timestamp"].dt.hour
    df["day_of_week"] = df["timestamp"].dt.day_name()
    return df


# --------------------------------------------------------- 3. Load to SQL Server
def get_engine(server: str, database: str, driver: str):
    from sqlalchemy import create_engine  # imported lazily: dry run doesn't need it

    user, pwd = os.getenv("SQL_USER"), os.getenv("SQL_PASSWORD")
    auth = f"UID={user};PWD={pwd};" if user and pwd else "Trusted_Connection=yes;"
    conn_str = (
        f"DRIVER={{{driver}}};SERVER={server};DATABASE={database};"
        f"{auth}TrustServerCertificate=yes;"
    )
    return create_engine(
        f"mssql+pyodbc:///?odbc_connect={quote_plus(conn_str)}",
        fast_executemany=True,
    )


def upload(df: pd.DataFrame, engine, table: str, if_exists: str) -> None:
    from sqlalchemy import text
    from sqlalchemy.dialects.mssql import DATETIME2
    from sqlalchemy.types import String

    dtypes = {
        "timestamp": DATETIME2(0),
        "label": String(50),
        "attack_category": String(50),
        "day_of_week": String(20),
    }
    df.to_sql(table, engine, if_exists=if_exists, index=False,
              chunksize=2000, dtype=dtypes)
    with engine.connect() as conn:
        n = conn.execute(text(f"SELECT COUNT(*) FROM [{table}]")).scalar()
    print(f"Uploaded {len(df)} rows. Table [{table}] now has {n} rows.")


# ------------------------------------------------------------------------ main
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", default="cleaned_cic_ids2017.csv")
    p.add_argument("--output", default="validated_features.csv")
    p.add_argument("--sample", type=int, default=None, help="use only first N rows")
    p.add_argument("--upload", action="store_true", help="upload to SQL Server")
    p.add_argument("--server", default="localhost\\SQLEXPRESS")
    p.add_argument("--database", default="SecurityDB")
    p.add_argument("--table", default="security_logs")
    p.add_argument("--driver", default="ODBC Driver 17 for SQL Server")
    p.add_argument("--if-exists", default="append", choices=["append", "replace", "fail"])
    args = p.parse_args()

    df = pd.read_csv(args.input)
    if args.sample:
        df = df.head(args.sample)
    print(f"Loaded {df.shape[0]} rows x {df.shape[1]} columns")

    df = validate(df)
    df = add_features(df)
    print(f"After feature engineering: {df.shape[1]} columns")

    df.to_csv(args.output, index=False)
    print(f"Saved {args.output}")

    if args.upload:
        engine = get_engine(args.server, args.database, args.driver)
        upload(df, engine, args.table, args.if_exists)
    else:
        print("Dry run only (add --upload to load into SQL Server).")


if __name__ == "__main__":
    main()