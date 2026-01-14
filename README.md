# CVSS Vector Enrichment Script

This Python script reads an Excel file containing CVSS vector strings, parses each vector, calculates the **base score** and all **base metrics**, and adds a **severity rating**. The output is a new enriched Excel file.

---

## Features

- Supports **CVSS v3.1, v3.0, and v2.0 vectors**
- Calculates:
  - Base Score
  - Exploitability Subscore
  - Impact Subscore
  - All base metrics: AV, AC, PR, UI, S, C, I, A
- Adds **Severity rating** based on base score:

| Rating   | CVSS Score  |
|----------|------------|
| None     | 0.0        |
| Low      | 0.1 - 3.9  |
| Medium   | 4.0 - 6.9  |
| High     | 7.0 - 8.9  |
| Critical | 9.0 - 10.0 |

- Fully **command-line driven**
- Works with **large Excel files**
- Handles **invalid or missing vectors** gracefully

---

## Requirements
- Python 3.8+
- Packages:

```bash
pip install pandas openpyxl cvss
```

## Usage
```python enrich_cvss_vectors.py <input_file.xlsx>```

- <input_file.xlsx>: Path to your Excel file with a column named Vector String containing CVSS vectors.

## Example:
```python enrich_cvss_vectors.py cvss_vectors.xlsx```

## Output
Generates a new Excel file in the same folder:
```<original_file_name>_enriched.xlsx```

Adds the following columns to the original file:
- `cvss_version`
- `cvss_base_score`
- `exploitability_subscore`
- `impact_subscore`
- `AV`, `AC`, `PR`, `UI`, `S`, `C`, `I`, `A`
- `Severity`

