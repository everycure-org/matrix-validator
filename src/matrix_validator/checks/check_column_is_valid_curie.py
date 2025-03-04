"""Polars-based validator check."""

import polars as pl

from matrix_validator.checks import CURIE_REGEX


def validate(df, column):
    """Validate column to be a valid CURIE."""
    violations_df = (
        df.select(
            [
                pl.when(~pl.col(column).str.contains(CURIE_REGEX))
                .then(pl.col(column))
                .otherwise(pl.lit(None))
                .alias(f"invalid_curie_{column}"),
            ]
        )
        .filter(pl.col(f"invalid_curie_{column}").is_not_null())
        .unique()
    )
    return violations_df.write_ndjson()
