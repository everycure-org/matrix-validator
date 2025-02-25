"""Polars-based validator check."""

import polars as pl

from matrix_validator.checks import DELIMITED_BY_PIPES

def validate(column, bm_prefixes: list, file):
    """Validate contains Biolink Model prefix."""
    violations_df = (
        pl.scan_csv(file, separator="\t", truncate_ragged_lines=True, has_header=True, ignore_errors=True)
        .select(
            [
                pl.when(~pl.col(column).str.contains_any(bm_prefixes))
                .then(pl.col(column))
                .otherwise(pl.lit(None))
                .alias(f"invalid_contains_biolink_model_prefix_{column}"),
            ]
        )
        .filter(pl.col(f"invalid_contains_biolink_model_prefix_{column}").is_not_null())
        .collect()
    )
    return violations_df.write_ndjson()
