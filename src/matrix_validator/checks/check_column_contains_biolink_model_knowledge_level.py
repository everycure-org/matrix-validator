"""Polars-based validator check."""

import polars as pl


def validate(column, bm_knowledge_levels: list, file):
    """Validate contains Biolink Model Knowledge Level."""
    violations_df = (
        pl.scan_csv(file, separator="\t", truncate_ragged_lines=True, has_header=True, ignore_errors=True)
        .select(
            [
                pl.when(~pl.col(column).str.contains_any(bm_knowledge_levels))
                .then(pl.col(column))
                .otherwise(pl.lit(None))
                .alias(f"invalid_contains_biolink_model_knowledge_level_{column}"),
            ]
        )
        .filter(pl.col(f"invalid_contains_biolink_model_knowledge_level_{column}").is_not_null())
        .collect()
    )
    return violations_df.write_ndjson()
