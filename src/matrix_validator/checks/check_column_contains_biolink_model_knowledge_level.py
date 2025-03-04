"""Polars-based validator check."""

import polars as pl


def validate(df, column, bm_knowledge_levels: list):
    """Validate contains Biolink Model Knowledge Level."""
    violations_df = (
        df.select(
            [
                pl.when(~pl.col(column).str.contains_any(bm_knowledge_levels))
                .then(pl.col(column))
                .otherwise(pl.lit(None))
                .alias(f"invalid_contains_biolink_model_knowledge_level_{column}"),
            ]
        )
        .filter(pl.col(f"invalid_contains_biolink_model_knowledge_level_{column}").is_not_null())
        .unique()
    )
    return violations_df.write_ndjson()
