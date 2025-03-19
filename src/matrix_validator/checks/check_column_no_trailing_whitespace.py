"""Polars-based validator check."""

import polars as pl

from matrix_validator.checks import NO_TRAILING_WHITESPACE


def validate(df, column):
    """Validate column - no trailing whitespace."""
    violations_df = (
        df.select(
            [
                pl.when(~pl.col(column).str.contains(NO_TRAILING_WHITESPACE))
                .then(pl.col(column))
                .otherwise(pl.lit(None))
                .alias(f"invalid_no_trailing_whitespace_{column}"),
            ]
        )
        .filter(pl.col(f"invalid_no_trailing_whitespace_{column}").is_not_null())
        .unique()
    )
    return violations_df.write_ndjson()
