"""Polars-based validator check."""

import polars as pl

from matrix_validator.checks import DELIMITED_BY_PIPES


def validate(df, column):
    """Validate Array to be delimited by pipes."""
    violations_df = (
        df.select(
            [
                pl.when(~pl.col(column).str.contains(DELIMITED_BY_PIPES))
                .then(pl.col(column))
                .otherwise(pl.lit(None))
                .alias(f"invalid_delimited_by_pipes_{column}"),
            ]
        )
        .filter(pl.col(f"invalid_delimited_by_pipes_{column}").is_not_null())
        .unique()
    )
    return violations_df.write_ndjson()
