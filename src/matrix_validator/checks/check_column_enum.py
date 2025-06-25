"""Polars-based validator check."""

import json

import polars as pl
from polars import DataFrame


def validate(df: DataFrame, column, values: list):
    """Validate range."""
    violations_df = df.select(
        [
            pl.when(pl.col(column).str.contains(f"^({'|'.join(values)})$").or_(pl.col(column).is_null()))
            .then(pl.col(column))
            .otherwise(pl.lit(None))
            .alias(f"invalid_column_enum_{column}"),
        ]
    ).filter(pl.col(f"invalid_column_enum_{column}").is_not_null())

    # Count total violations
    total_violations = len(violations_df)
    if total_violations == 0:
        return ""

    # Get unique violations and limit to 10 examples
    unique_violations = violations_df.unique()
    examples = unique_violations.get_column(f"invalid_column_enum_{column}").head(10).to_list()

    # Create a summary report
    report = {
        "total_violations": total_violations,
        "unique_violations": len(unique_violations),
        "examples": examples,
    }

    # Format output as a single JSON string
    result = {f"invalid_column_enum_{column}_summary": report}

    return json.dumps(result, indent=2)
