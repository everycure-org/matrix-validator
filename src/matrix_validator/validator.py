"""Main python file."""

import json
import logging
from typing import Optional

import polars as pl

from matrix_validator.datamodels import MatrixEdgeSchema, MatrixNodeSchema

logger = logging.getLogger(__name__)

CURIE_REGEX = r"^[A-Za-z_\.]+:.+$"
STARTS_WITH_BIOLINK_REGEX = r"^biolink:.+$"


def format_schema_error(error: dict) -> str:
    """Format Pandera schema validation errors for better readability."""
    formatted_messages = []

    if "SCHEMA" in error:
        for issue_type, issues in error["SCHEMA"].items():
            for issue in issues:
                formatted_messages.append(
                    f"  - ❌ **{issue_type.replace('_', ' ').title()}**\n"
                    f"    - Schema: `{issue.get('schema', 'Unknown')}`\n"
                    f"    - Column: `{issue.get('column', 'Unknown')}`\n"
                    f"    - Error: {issue.get('error', 'No details')}\n"
                )

    return "\n".join(formatted_messages) if formatted_messages else str(error)


def validate_kg(
    nodes: Optional[str],
    edges: Optional[str],
    output_format: str,
    report_file: str,
    invalid_edges_output_file=None,
    invalid_nodes_output_file=None,
    batch_size=10_000,
):
    """Validate a knowledge graph using optional nodes and edges TSV files."""
    validation_reports = []
    invalid_edges = []
    invalid_nodes = []

    if not invalid_edges_output_file:
        invalid_edges_output_file = f"{report_file}_invalid_edges.tsv"

    if not invalid_nodes_output_file:
        invalid_nodes_output_file = f"{report_file}_invalid_nodes.tsv"

    # Validate nodes if provided
    if nodes:
        logging.warning(f"🔍 Validating Nodes TSV: {nodes}")

        try:
            reader = pl.read_csv_batched(nodes, separator="\t", infer_schema_length=0, batch_size=batch_size)
            node_batches = list(reader.next_batches(5))  # Store batches to avoid generator exhaustion

            if not node_batches:
                validation_reports.append("⚠️ **Nodes Validation Failed**: No data found in the nodes file.")
            else:
                # validated_nodes = [MatrixNodeSchema.validate(df, lazy=True) for df in node_batches]
                # validation_reports.append("✅ **Nodes Validation Passed**")
                validated_nodes = []
                for df in node_batches:
                    try:
                        validated_nodes.append(MatrixNodeSchema.validate(df, lazy=True))
                    except Exception:
                        logging.warning("❌ Node validation failed for a batch.")
                        invalid_nodes.append(df)

                validation_reports.append("✅ **Edges Validation Passed**")
        except Exception as e:
            error_message = json.loads(str(e)) if "SCHEMA" in str(e) else str(e)
            validation_reports.append(f"❌ **Nodes Validation Failed**:\n{format_schema_error(error_message)}")

    # Validate edges if provided
    if edges:
        logging.warning(f"🔍 Validating Edges TSV: {edges}")

        try:
            reader = pl.read_csv_batched(edges, separator="\t", infer_schema_length=0, batch_size=batch_size)
            edge_batches = list(reader.next_batches(5))  # Store batches to prevent multiple iterations

            if not edge_batches:
                validation_reports.append("⚠️ **Edges Validation Failed**: No data found in the edges file.")
            else:
                validated_edges = []
                for df in edge_batches:
                    try:
                        validated_edges.append(MatrixEdgeSchema.validate(df, lazy=True))
                    except Exception:
                        logging.warning("❌ Edge validation failed for a batch.")
                        invalid_edges.append(df)  # Capture invalid rows

                validation_reports.append("✅ **Edges Validation Passed**")

        except Exception as e:
            error_message = json.loads(str(e)) if "SCHEMA" in str(e) else str(e)
            validation_reports.append(f"❌ **Edges Validation Failed**:\n{format_schema_error(error_message)}")

    # Write invalid rows to a file
    if invalid_edges:
        invalid_data = pl.concat(invalid_edges)
        invalid_data.write_csv(invalid_edges_output_file, separator="\t")
        logging.warning(f"⚠️ Invalid edges written to {invalid_edges_output_file}")

    if invalid_nodes:
        invalid_data = pl.concat(invalid_nodes)
        invalid_data.write_csv(invalid_nodes_output_file, separator="\t")
        logging.warning(f"⚠️ Invalid nodes written to {invalid_nodes_output_file}")

    # Write validation report
    logging.info(f"📄 Validation report written to {report_file}")
    write_report(output_format, report_file, validation_reports)


def validate_kg_nodes(nodes, output_format, report_file):
    """Validate a knowledge graph using optional nodes TSV files."""
    validation_reports = []

    logger.info("Validating nodes TSV...")

    counts_df = (
        pl.scan_csv(nodes, separator="\t", truncate_ragged_lines=True, has_header=True, ignore_errors=True)
        .select(
            [
                pl.col("id").str.contains(CURIE_REGEX).sum().alias("valid_curie_id_count"),
                (~pl.col("id").str.contains(CURIE_REGEX)).sum().alias("invalid_curie_id_count"),
                pl.col("category").str.contains(STARTS_WITH_BIOLINK_REGEX).sum().alias("valid_starts_with_biolink_category_count"),
                (~pl.col("category").str.contains(STARTS_WITH_BIOLINK_REGEX)).sum().alias("invalid_starts_with_biolink_category_count"),
            ]
        )
        .collect()
    )

    validation_reports.append(counts_df.write_ndjson())

    if counts_df.get_column("invalid_curie_id_count").item(0) > 0:
        violations_df = (
            pl.scan_csv(nodes, separator="\t", truncate_ragged_lines=True, has_header=True, ignore_errors=True)
            .select(
                [
                    pl.when(~pl.col("id").str.contains(CURIE_REGEX)).then(pl.col("id")).otherwise(pl.lit(None)).alias("invalid_curie_id"),
                ]
            )
            .filter(pl.col("invalid_curie_id").is_not_null())
            .collect()
        )
        validation_reports.append(violations_df.write_ndjson())

    if counts_df.get_column("invalid_starts_with_biolink_category_count").item(0) > 0:
        violations_df = (
            pl.scan_csv(nodes, separator="\t", truncate_ragged_lines=True, has_header=True, ignore_errors=True)
            .select(
                [
                    pl.when(~pl.col("category").str.contains(CURIE_REGEX))
                    .then(pl.col("category"))
                    .otherwise(pl.lit(None))
                    .alias("invalid_starts_with_biolink_category"),
                ]
            )
            .filter(pl.col("invalid_starts_with_biolink_category").is_not_null())
            .collect()
        )
        validation_reports.append(violations_df.write_ndjson())

    # Write validation report
    write_report(output_format, report_file, validation_reports)
    logging.info(f"Validation report written to {report_file}")


def validate_kg_edges(edges, output_format, report_file):
    """Validate a knowledge graph using optional edges TSV files."""
    validation_reports = []

    logger.info("Validating edges TSV...")

    counts_df = (
        pl.scan_csv(edges, separator="\t", truncate_ragged_lines=True, has_header=True, ignore_errors=True)
        .select(
            [
                pl.col("subject").str.contains(CURIE_REGEX).sum().alias("valid_curie_subject_count"),
                (~pl.col("subject").str.contains(CURIE_REGEX)).sum().alias("invalid_curie_subject_count"),
                pl.col("predicate").str.contains(STARTS_WITH_BIOLINK_REGEX).sum().alias("valid_starts_with_biolink_predicate_count"),
                (~pl.col("predicate").str.contains(STARTS_WITH_BIOLINK_REGEX)).sum().alias("invalid_starts_with_biolink_predicate_count"),
                pl.col("object").str.contains(CURIE_REGEX).sum().alias("valid_curie_object_count"),
                (~pl.col("object").str.contains(CURIE_REGEX)).sum().alias("invalid_curie_object_count"),
            ]
        )
        .collect()
    )

    validation_reports.append(counts_df.write_ndjson())

    if counts_df.get_column("invalid_curie_subject_count").item(0) > 0:
        violations_df = (
            pl.scan_csv(edges, separator="\t", truncate_ragged_lines=True, has_header=True, ignore_errors=True)
            .select(
                [
                    pl.when(~pl.col("subject").str.contains(CURIE_REGEX))
                    .then(pl.col("subject"))
                    .otherwise(pl.lit(None))
                    .alias("invalid_curie_subject"),
                ]
            )
            .filter(pl.col("invalid_curie_subject").is_not_null())
            .collect()
        )
        validation_reports.append(violations_df.write_ndjson())

    if counts_df.get_column("invalid_curie_object_count").item(0) > 0:
        violations_df = (
            pl.scan_csv(edges, separator="\t", truncate_ragged_lines=True, has_header=True, ignore_errors=True)
            .select(
                [
                    pl.when(~pl.col("object").str.contains(CURIE_REGEX))
                    .then(pl.col("object"))
                    .otherwise(pl.lit(None))
                    .alias("invalid_curie_object"),
                ]
            )
            .filter(pl.col("invalid_curie_object").is_not_null())
            .collect()
        )
        validation_reports.append(violations_df.write_ndjson())

    if counts_df.get_column("invalid_starts_with_biolink_predicate_count").item(0) > 0:
        violations_df = (
            pl.scan_csv(edges, separator="\t", truncate_ragged_lines=True, has_header=True, ignore_errors=True)
            .select(
                [
                    pl.when(~pl.col("predicate").str.contains(STARTS_WITH_BIOLINK_REGEX))
                    .then(pl.col("predicate"))
                    .otherwise(pl.lit(None))
                    .alias("invalid_starts_with_biolink_predicate"),
                ]
            )
            .filter(pl.col("invalid_starts_with_biolink_predicate").is_not_null())
            .collect()
        )
        validation_reports.append(violations_df.write_ndjson())

    # Write validation report
    write_report(output_format, report_file, validation_reports)
    logging.info(f"Validation report written to {report_file}")


def write_report(output_format, report_file, validation_reports):
    """Write the validation report to a file."""
    if report_file:

        with open(report_file, "w") as report:
            if output_format == "txt":
                report.write("\n".join(validation_reports))
            elif output_format == "md":
                report.write("\n\n".join([f"## {line}" for line in validation_reports]))
