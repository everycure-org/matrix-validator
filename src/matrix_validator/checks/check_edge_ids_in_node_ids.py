"""Polars-based validator check."""

import json
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

    # Count total violations
    total_violations = len(violations_df)
    if total_violations == 0:
        return ""

    # Group violations by prefix (extract prefix from before the colon)
    with_prefix = violations_df.with_columns(pl.col("invalid_edge_ids_in_node_ids").str.split(":").list.first().alias("prefix"))

    # Group by prefix and count
    prefix_counts = (
        with_prefix.group_by("prefix")
        .agg(pl.count().alias("count"), pl.col("invalid_edge_ids_in_node_ids").head(3).alias("examples"))
        .sort("count", descending=True)
    )

    # Create a summary report
    report = {"total_violations": total_violations, "prefix_violations": prefix_counts.to_dicts()}

    # Format output as a single JSON string
    result = {"invalid_edge_ids_in_node_ids_summary": report}

    return json.dumps(result, indent=2)
