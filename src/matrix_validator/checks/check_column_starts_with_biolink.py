"""Polars-based validator check."""

import polars as pl

from matrix_validator.checks import STARTS_WITH_BIOLINK_REGEX


def validate(df, column):
    """Validate column to start with biolink:."""
    violations_df = (
        df.select(
            [
                pl.when(~pl.col(column).str.contains(STARTS_WITH_BIOLINK_REGEX))
                .then(pl.col(column))
                .otherwise(pl.lit(None))
                .alias(f"invalid_starts_with_biolink_{column}"),
            ]
        )
        .filter(pl.col(f"invalid_starts_with_biolink_{column}").is_not_null())
        .unique()
    )
    return violations_df.write_ndjson()
