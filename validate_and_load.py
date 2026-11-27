"""
validate_and_load.py
Stage: Data Validation -> Feature Engineering -> Load to SQL Server (via pyodbc)
Input : cleaned_cic_ids2017.csv  (output of Data_Transformation.py)

Target schema (created by CICIDS2017_Tables.sql):
    [CICIDS2017 Database].dbo.Dim_Label          (label, Label_ID IDENTITY)
    [CICIDS2017 Database].dbo.Fact_Network_Flows (Flow_ID IDENTITY, ..., Label_ID FK)

Examples (PowerShell):
    # 1) Dry run: validate + build features + save validated_features.csv (no DB needed)
    py -3.13 validate_and_load.py

    # 2) Check the data against the SQL table types only (nothing is written)
    py -3.13 validate_and_load.py --check-only --server "localhost"

    # 3) Quick upload test with 1000 rows
    py -3.13 validate_and_load.py --upload --sample 1000 --truncate --server "localhost"

    # 4) Full upload
    py -3.13 validate_and_load.py --upload --truncate --server "localhost"

SQL login (optional): set env vars SQL_USER and SQL_PASSWORD.
If they are not set, Windows Authentication is used.
"""
import argparse
import os
import sys

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

# ---- SQL Server target schema
SCHEMA = "dbo"
FACT_TABLE = "Fact_Network_Flows"
DIM_TABLE = "Dim_Label"

INT_RANGES = {
    "bit": (0, 1),
    "tinyint": (0, 255),
    "smallint": (-32768, 32767),
    "int": (-(2 ** 31), 2 ** 31 - 1),
    "bigint": (-(2 ** 63), 2 ** 63 - 1),
}


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
    df["label"] = df["label"].astype(str).str.strip()
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

    # Redundant duplicate column from the original CSV ("Fwd Header Length.1").
    # Kept on purpose: Fact_Network_Flows has fwd_header_length_1 as NOT NULL.
    if "fwd_header_length_1" in df.columns and "fwd_header_length" in df.columns:
        if df["fwd_header_length_1"].equals(df["fwd_header_length"]):
            warnings.append(
                "fwd_header_length_1 is an identical copy of fwd_header_length "
                "(kept, because the SQL table has this column)"
            )

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
def get_pyodbc_conn(server: str, database: str, driver: str):
    import pyodbc

    user, pwd = os.getenv("SQL_USER"), os.getenv("SQL_PASSWORD")
    auth = f"UID={user};PWD={pwd};" if user and pwd else "Trusted_Connection=yes;"
    conn_str = (
        f"DRIVER={{{driver}}};SERVER={server};DATABASE={database};"
        f"{auth}TrustServerCertificate=yes;"
    )
    conn = pyodbc.connect(conn_str, autocommit=False)
    return conn


def fetch_table_schema(cursor, table: str) -> pd.DataFrame:
    q = """
        SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, NUMERIC_PRECISION, NUMERIC_SCALE,
               COLUMNPROPERTY(OBJECT_ID(TABLE_SCHEMA + '.' + TABLE_NAME),
                              COLUMN_NAME, 'IsIdentity') AS IS_IDENTITY
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?
        ORDER BY ORDINAL_POSITION
    """
    cursor.execute(q, (SCHEMA, table))
    rows = [tuple(r) for r in cursor.fetchall()]
    if not rows:
        sys.exit(
            f"ERROR: table {SCHEMA}.{table} not found. "
            "Create the database and run CICIDS2017_Tables.sql first."
        )
    return pd.DataFrame(
        rows,
        columns=["COLUMN_NAME", "DATA_TYPE", "IS_NULLABLE",
                 "NUMERIC_PRECISION", "NUMERIC_SCALE", "IS_IDENTITY"],
    )


def smallest_fit(lo, hi) -> str:
    for name in ("tinyint", "smallint", "int", "bigint"):
        a, b = INT_RANGES[name]
        if a <= lo and hi <= b:
            return name
    return "bigint"


def check_against_schema(df: pd.DataFrame, schema: pd.DataFrame):
    """Compare the dataframe with the SQL table. Returns (columns_to_insert, problems)."""
    cols = schema[schema["IS_IDENTITY"] != 1]
    db_cols = cols["COLUMN_NAME"].tolist()

    missing = [c for c in db_cols if c not in df.columns and c != "Label_ID"]
    if missing:
        sys.exit(f"ERROR: columns in the SQL table but not in the data: {missing}")

    problems = []
    for _, c in cols.iterrows():
        name, typ = c["COLUMN_NAME"], c["DATA_TYPE"]
        if name == "Label_ID":
            continue
        s = df[name]

        if c["IS_NULLABLE"] == "NO" and s.isna().any():
            problems.append(f"{name}: has NULLs but the column is NOT NULL")

        if typ in INT_RANGES or typ == "decimal":
            if not pd.api.types.is_numeric_dtype(s):
                problems.append(f"{name} ({typ}): data is not numeric")
                continue

        if typ in INT_RANGES:
            lo_t, hi_t = INT_RANGES[typ]
            lo, hi = s.min(), s.max()
            if pd.notna(lo) and pd.notna(hi):
                if lo < lo_t or hi > hi_t:
                    bad = int(((s < lo_t) | (s > hi_t)).sum())
                    problems.append(
                        f"{name} ({typ}): {bad} rows out of range, data range is "
                        f"[{lo}, {hi}] -> needs at least {smallest_fit(lo, hi)}"
                    )
                elif (s.dropna() % 1 != 0).any():
                    problems.append(f"{name} ({typ}): has fractional values")
        elif typ == "decimal" and pd.notna(c["NUMERIC_PRECISION"]) and pd.notna(c["NUMERIC_SCALE"]):
            limit = 10 ** (int(c["NUMERIC_PRECISION"]) - int(c["NUMERIC_SCALE"]))
            max_abs = s.abs().max()
            if pd.notna(max_abs) and max_abs >= limit:
                problems.append(
                    f"{name} (decimal({int(c['NUMERIC_PRECISION'])},{int(c['NUMERIC_SCALE'])})): "
                    f"max abs value {max_abs} does not fit"
                )
    return db_cols, problems


def sync_dim_label(cursor, labels) -> dict:
    """Insert labels missing from Dim_Label, return {label: Label_ID}."""
    def read():
        cursor.execute(f"SELECT label, Label_ID FROM {SCHEMA}.{DIM_TABLE}")
        return {str(r[0]).strip(): r[1] for r in cursor.fetchall()}

    clean_labels = sorted({str(lbl).strip() for lbl in labels if pd.notna(lbl)})
    mapping = read()
    new = [lbl for lbl in clean_labels if lbl not in mapping]
    if new:
        cursor.executemany(
            f"INSERT INTO {SCHEMA}.{DIM_TABLE} (label) VALUES (?)",
            [(lbl,) for lbl in new],
        )
        print(f"Dim_Label: inserted {len(new)} new label(s): {new}")
        mapping = read()
    return mapping


def _to_pyodbc_val(val):
    if pd.isna(val):
        return None
    if isinstance(val, (pd.Timestamp, np.datetime64)):
        return pd.Timestamp(val).to_pydatetime()
    if isinstance(val, (np.integer,)):
        return int(val)
    if isinstance(val, (np.floating,)):
        return float(val)
    if isinstance(val, (np.bool_,)):
        return bool(val)
    return val


def load(df: pd.DataFrame, conn, check_only: bool, truncate: bool) -> None:
    fact = f"{SCHEMA}.{FACT_TABLE}"
    cursor = conn.cursor()
    cursor.fast_executemany = True

    try:
        schema = fetch_table_schema(cursor, FACT_TABLE)
        db_cols, problems = check_against_schema(df, schema)
        if problems:
            print("Schema check FAILED - the data does not fit Fact_Network_Flows:")
            for p in problems:
                print("  -", p)
            conn.rollback()
            sys.exit("Fix the schema or data types above, then rerun.")
        print(f"Schema check passed ({len(db_cols)} columns match {fact}).")
        if check_only:
            conn.rollback()
            return

        before = cursor.execute(f"SELECT COUNT(*) FROM {fact}").fetchone()[0]
        if before and not truncate:
            conn.rollback()
            sys.exit(
                f"ERROR: {fact} already has {before} rows. "
                "Add --truncate to replace them (avoids duplicate loads)."
            )
        if truncate and before:
            cursor.execute(f"TRUNCATE TABLE {fact}")
            print(f"Truncated {fact} ({before} old rows removed).")
            before = 0

        mapping = sync_dim_label(cursor, df["label"].unique())
        out = df.copy()
        out["Label_ID"] = out["label"].map(mapping)
        if out["Label_ID"].isna().any():
            raise RuntimeError("some labels could not be mapped to a Label_ID")

        out = out[db_cols]
        col_list = ", ".join(f"[{c}]" for c in db_cols)
        placeholders = ", ".join("?" for _ in db_cols)
        insert_sql = f"INSERT INTO {fact} ({col_list}) VALUES ({placeholders})"

        chunk_size = 5000
        for start in range(0, len(out), chunk_size):
            chunk = out.iloc[start:start + chunk_size]
            rows = [tuple(_to_pyodbc_val(v) for v in row) for row in chunk.itertuples(index=False, name=None)]
            cursor.executemany(insert_sql, rows)

        after = cursor.execute(f"SELECT COUNT(*) FROM {fact}").fetchone()[0]
        if after - before != len(out):
            raise RuntimeError(
                f"row count mismatch: sent {len(out)}, table grew by {after - before}"
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()

    print(f"Uploaded {len(out)} rows. {fact} now has {after} rows.")


# ------------------------------------------------------------------------ main
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", default="cleaned_cic_ids2017.csv")
    p.add_argument("--output", default="validated_features.csv")
    p.add_argument("--sample", type=int, default=None, help="use only first N rows")
    p.add_argument("--upload", action="store_true", help="upload to SQL Server")
    p.add_argument("--check-only", action="store_true",
                   help="compare the data with the SQL table types, write nothing")
    p.add_argument("--truncate", action="store_true",
                   help="empty Fact_Network_Flows before loading")
    p.add_argument("--server", default="localhost")
    p.add_argument("--database", default="CICIDS2017 Database")
    p.add_argument("--driver", default="ODBC Driver 17 for SQL Server")
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

    if args.upload or args.check_only:
        conn = get_pyodbc_conn(args.server, args.database, args.driver)
        try:
            load(df, conn, check_only=args.check_only, truncate=args.truncate)
        finally:
            conn.close()
    else:
        print("Dry run only (add --upload to load into SQL Server).")


if __name__ == "__main__":
    main()