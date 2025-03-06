"""Polars-based validator check."""

import polars as pl


def validate(df, edge_ids: list, file):
    """Validate contains Edge subject/object exist in Nodes."""
    column = "id"
    violations_df = df.select(
        [
            pl.when(~pl.col(column).str.contains_any(edge_ids))
            .then(pl.col(column))
            .otherwise(pl.lit(None))
            .alias("invalid_edge_ids_in_node_ids"),
        ]
    ).filter(pl.col("invalid_edge_ids_in_node_ids").is_not_null())
    return violations_df.write_ndjson()
