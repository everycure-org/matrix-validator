"""Polars-based validator check."""

import polars as pl
from polars import DataFrame


def validate(df: DataFrame, column, bm_agent_types: list):
    """Validate contains Biolink Model Agent Type."""
    violations_df = (
        df.select(
            [
                pl.when(~pl.col(column).str.contains_any(bm_agent_types))
                .then(pl.col(column))
                .otherwise(pl.lit(None))
                .alias(f"invalid_contains_biolink_model_agent_type_{column}"),
            ]
        )
        .filter(pl.col(f"invalid_contains_biolink_model_agent_type_{column}").is_not_null())
        .unique()
    )
    return violations_df.write_ndjson()
