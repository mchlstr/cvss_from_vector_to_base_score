import pandas as pd
from cvss import CVSS3, CVSS2
from pathlib import Path
import sys

def parse_cvss_vector(vector):
    """Parse a CVSS vector string (v3.1/v3.0/v2.0) and return metrics."""
    vector = str(vector).strip()
    if not vector or not vector.startswith("CVSS:"):
        return pd.Series({
            "cvss_version": None,
            "cvss_base_score": None,
            "exploitability_subscore": None,
            "impact_subscore": None,
            "AV": None, "AC": None, "PR": None, "UI": None,
            "S": None, "C": None, "I": None, "A": None
        })

    try:
        if vector.startswith("CVSS:3"):
            c = CVSS3(vector)
        elif vector.startswith("CVSS:2"):
            c = CVSS2(vector)
        else:
            return pd.Series({
                "cvss_version": None,
                "cvss_base_score": None
            })

        return pd.Series({
            "cvss_version": c.vector.split("/")[0].replace("CVSS:", ""),
            "cvss_base_score": c.scores()[0],
            "exploitability_subscore": c.scores()[1] if hasattr(c, "scores") else None,
            "impact_subscore": c.scores()[2] if hasattr(c, "scores") else None,
            "AV": c.metrics.get('AV'),
            "AC": c.metrics.get('AC'),
            "PR": c.metrics.get('PR'),
            "UI": c.metrics.get('UI'),
            "S": c.metrics.get('S'),
            "C": c.metrics.get('C'),
            "I": c.metrics.get('I'),
            "A": c.metrics.get('A')
        })
    except Exception:
        return pd.Series({
            "cvss_version": None,
            "cvss_base_score": None,
            "exploitability_subscore": None,
            "impact_subscore": None,
            "AV": None, "AC": None, "PR": None, "UI": None,
            "S": None, "C": None, "I": None, "A": None
        })


def severity_from_score(score):
    """Return severity rating based on CVSS score."""
    if score is None:
        return "None"
    try:
        score = float(score)
        if score == 0.0:
            return "None"
        elif 0.1 <= score <= 3.9:
            return "Low"
        elif 4.0 <= score <= 6.9:
            return "Medium"
        elif 7.0 <= score <= 8.9:
            return "High"
        elif 9.0 <= score <= 10.0:
            return "Critical"
        else:
            return "Unknown"
    except:
        return "Unknown"


def main():
    if len(sys.argv) != 2:
        print("Usage: python enrich_cvss_vectors.py <input_file.xlsx>")
        sys.exit(1)

    input_file = Path(sys.argv[1])
    if not input_file.exists():
        print(f"File not found: {input_file}")
        sys.exit(1)

    # Read Excel
    df = pd.read_excel(input_file)
    vector_col = "Vector String"
    if vector_col not in df.columns:
        print(f"Column '{vector_col}' not found in the file.")
        sys.exit(1)

    df[vector_col] = df[vector_col].astype(str).str.strip()

    # Parse vectors
    metrics_df = df[vector_col].apply(parse_cvss_vector)
    df = pd.concat([df, metrics_df], axis=1)

    # Compute severity
    df["Severity"] = df["cvss_base_score"].apply(severity_from_score)

    # Save enriched file
    output_file = input_file.with_name(f"{input_file.stem}_enriched.xlsx")
    df.to_excel(output_file, index=False, engine="openpyxl")
    print(f"Enriched file written to: {output_file}")


if __name__ == "__main__":
    main()
