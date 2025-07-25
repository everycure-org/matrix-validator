"""Polars-based validator check."""

import json

import polars as pl

from matrix_validator.checks import NO_LEADING_WHITESPACE


def validate(df, column):
    """Validate column - no leading whitespace."""
    violations_df = df.select(
        [
            pl.when(~pl.col(column).str.contains(NO_LEADING_WHITESPACE))
            .then(pl.col(column))
            .otherwise(pl.lit(None))
            .alias(f"invalid_no_leading_whitespace_{column}"),
        ]
    ).filter(pl.col(f"invalid_no_leading_whitespace_{column}").is_not_null())

    # Count total violations
    total_violations = len(violations_df)
    if total_violations == 0:
        return ""

    # Get unique violations and limit to 10 examples
    unique_violations = violations_df.unique().head(10)
    examples = unique_violations.get_column(f"invalid_no_leading_whitespace_{column}").to_list()

    # Create a summary report
    report = {"total_violations": total_violations, "unique_violations": len(unique_violations), "examples": examples}

    # Format output as a single JSON string
    result = {f"invalid_no_leading_whitespace_{column}_summary": report}

    return json.dumps(result, indent=2)
