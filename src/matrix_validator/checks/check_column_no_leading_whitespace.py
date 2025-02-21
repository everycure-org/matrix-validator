"""Polars-based validator check."""

import polars as pl

from matrix_validator.checks import NO_LEADING_WHITESPACE


def validate(column, file):
    """Validate column - no leading whitespace."""
    violations_df = (
        pl.scan_csv(file, separator="\t", truncate_ragged_lines=True, has_header=True, ignore_errors=True)
        .select(
            [
                pl.when(~pl.col(column).str.contains(NO_LEADING_WHITESPACE))
                .then(pl.col(column))
                .otherwise(pl.lit(None))
                .alias(f"invalid_no_leading_whitespace_{column}"),
            ]
        )
        .filter(pl.col(f"invalid_no_leading_whitespace_{column}").is_not_null())
        .collect()
    )
    return violations_df.write_ndjson()
