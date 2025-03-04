"""Polars-based validator check."""

import polars as pl


def validate(edge_ids: list, file):
    """Validate contains Edge subject/object exist in Nodes."""
    column = "id"
    violations_df = (
        pl.scan_csv(file, separator="\t", truncate_ragged_lines=True, has_header=True, ignore_errors=True)
        .select(
            [
                pl.when(~pl.col(column).str.contains_any(edge_ids))
                .then(pl.col(column))
                .otherwise(pl.lit(None))
                .alias("invalid_edge_ids_in_node_ids"),
            ]
        )
        .filter(pl.col("invalid_edge_ids_in_node_ids").is_not_null())
        .collect()
    )
    return violations_df.write_ndjson()
