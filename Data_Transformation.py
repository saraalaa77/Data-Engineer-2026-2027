import numpy as np
import pandas as pd

def clean_and_prepare_security_logs(input_file, output_file):
    print("🚀 Starting Advanced Data Cleaning & ETL Pipeline...")

    df = pd.read_csv(input_file)

    df.columns = (
        df.columns.str.strip()
        .str.lower()
        .str.replace(" ", "_")
        .str.replace("/", "_per_")
        .str.replace(".", "_")
        .str.replace("[^a-z0-9_]", "", regex=True)
    )

    df = df.loc[:, ~df.columns.duplicated()]

    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df[numeric_cols] = df[numeric_cols].fillna(0)

    non_numeric_cols = df.select_dtypes(exclude=[np.number]).columns
    df[non_numeric_cols] = df[non_numeric_cols].fillna("UNKNOWN")

    if "label" in df.columns:
        df["label"] = df["label"].astype(str).str.strip().str.upper()

    print("⏰ Generating simulated timestamps for Power BI time-series analysis...")
    start_time = pd.Timestamp("2026-10-01 08:00:00")
    df["timestamp"] = [
        start_time + pd.Timedelta(seconds=i * 2) for i in range(len(df))
    ]

    cols = ["timestamp"] + [c for c in df.columns if c != "timestamp"]
    df = df[cols]

    df.to_csv(output_file, index=False)
    print(f"💾 Fully cleaned and enriched dataset saved to: '{output_file}'")

    return df


if __name__ == "__main__":
    clean_and_prepare_security_logs(
        input_file="CIC_IDS2017_generated_sample.csv",
        output_file="cleaned_cic_ids2017.csv",
    )