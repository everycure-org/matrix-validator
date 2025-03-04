"""Polars-based validator check."""

import polars as pl


def validate(df, column, bm_prefixes: list):
    """Validate contains Biolink Model prefix."""
    violations_df = (
        df.select(
            [
                pl.when(~pl.col(column).str.contains_any(bm_prefixes, ascii_case_insensitive=True))
                .then(pl.col(column))
                .otherwise(pl.lit(None))
                .alias(f"invalid_contains_biolink_model_prefix_{column}"),
            ]
        )
        .filter(pl.col(f"invalid_contains_biolink_model_prefix_{column}").is_not_null())
        .unique()
    )
    return violations_df.write_ndjson()
