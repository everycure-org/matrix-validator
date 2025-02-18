"""Main python file."""

import logging
import polars as pl
from matrix_validator.datamodels import EdgeSchema, NodeSchema
from matrix_validator.util import read_tsv_as_strings

logger = logging.getLogger(__name__)


def validate_kg(nodes, edges, output_format, report_file):
    """Validate a knowledge graph using optional nodes and edges TSV files."""
    validation_reports = []

    # Validate nodes if provided
    if nodes:
        logger.info("Validating nodes TSV...")
        nodes_df = read_tsv_as_strings(nodes)
        logger.debug(f"Nodes DataFrame: {nodes_df.head()}")
        node_validation = NodeSchema.validate(nodes_df)
        validation_reports.append(f"Nodes Validation Passed: {node_validation}")

    # Validate edges if provided
    if edges:
        logger.info("Validating edges TSV...")
        edges_df = read_tsv_as_strings(edges)
        logger.debug(f"Edges DataFrame: {edges_df.head()}")
        edge_validation = EdgeSchema.validate(edges_df)
        validation_reports.append(f"Edges Validation Passed: {edge_validation}")

    # Write validation report
    write_report(output_format, report_file, validation_reports)
    logging.info(f"Validation report written to {report_file}")


def validate_kg_nodes(nodes, output_format, report_file):
    """Validate a knowledge graph using optional nodes TSV files."""
    validation_reports = []

    logger.info("Validating nodes TSV...")
        
    curie_regex = "^[A-Za-z_\.]+:.+$"
    starts_with_biolink_regex = "^biolink:.+$"

    counts_df = pl.scan_csv(nodes, separator='\t', truncate_ragged_lines=True, has_header=True, ignore_errors=True).select([
        pl.col("id").str.contains(curie_regex).sum().alias("valid_curie_id_count"),
        (~pl.col("id").str.contains(curie_regex)).sum().alias("invalid_curie_id_count"),
        pl.col("category").str.contains(starts_with_biolink_regex).sum().alias("valid_starts_with_biolink_category_count"),
        (~pl.col("category").str.contains(starts_with_biolink_regex)).sum().alias("invalid_starts_with_biolink_category_count")
    ]).collect()

    validation_reports.append(counts_df.write_ndjson())
    
    if counts_df.get_column("invalid_curie_id_count").item(0) > 0:
        violations_df = pl.scan_csv(nodes, separator='\t', truncate_ragged_lines=True, has_header=True, ignore_errors=True).select([
            pl.when(~pl.col("id").str.contains(curie_regex)).then(pl.col("id")).otherwise(pl.lit(None)).alias("invalid_curie_id"),
        ]).filter(pl.col("invalid_curie_id").is_null().not_()).collect()
        validation_reports.append(violations_df.write_ndjson())

    if counts_df.get_column("invalid_starts_with_biolink_category_count").item(0) > 0:
        violations_df = pl.scan_csv(nodes, separator='\t', truncate_ragged_lines=True, has_header=True, ignore_errors=True).select([
            pl.when(~pl.col("category").str.contains(curie_regex)).then(pl.col("category")).otherwise(pl.lit(None)).alias("invalid_starts_with_biolink_category"),
        ]).filter(pl.col("invalid_starts_with_biolink_category").is_null().not_()).collect()
        validation_reports.append(violations_df.write_ndjson())

    # Write validation report
    write_report(output_format, report_file, validation_reports)
    logging.info(f"Validation report written to {report_file}")

def validate_kg_edges(edges, output_format, report_file):
    """Validate a knowledge graph using optional edges TSV files."""
    validation_reports = []

    logger.info("Validating edges TSV...")

    curie_regex = "^[A-Za-z_\.]+:.+$"
    starts_with_biolink_regex = "^biolink:.+$"

    counts_df = pl.scan_csv(edges, separator='\t', truncate_ragged_lines=True, has_header=True, ignore_errors=True).select([
        pl.col("subject").str.contains(curie_regex).sum().alias("valid_curie_subject_count"),
        (~pl.col("subject").str.contains(curie_regex)).sum().alias("invalid_curie_subject_count"),
        pl.col("predicate").str.contains(starts_with_biolink_regex).sum().alias("valid_starts_with_biolink_predicate_count"),
        (~pl.col("predicate").str.contains(starts_with_biolink_regex)).sum().alias("invalid_starts_with_biolink_predicate_count"),
        pl.col("object").str.contains(curie_regex).sum().alias("valid_curie_object_count"),
        (~pl.col("object").str.contains(curie_regex)).sum().alias("invalid_curie_object_count"),
    ]).collect()

    validation_reports.append(counts_df.write_ndjson())

    if counts_df.get_column("invalid_curie_subject_count").item(0) > 0:
        violations_df = pl.scan_csv(edges, separator='\t', truncate_ragged_lines=True, has_header=True, ignore_errors=True).select([
            pl.when(~pl.col("subject").str.contains(curie_regex)).then(pl.col("id")).otherwise(pl.lit(None)).alias("invalid_curie_subject"),
        ]).filter(pl.col("invalid_curie_subject").is_null().not_()).collect()
        validation_reports.append(violations_df.write_ndjson())

    if counts_df.get_column("invalid_curie_object_count").item(0) > 0:
        violations_df = pl.scan_csv(edges, separator='\t', truncate_ragged_lines=True, has_header=True, ignore_errors=True).select([
            pl.when(~pl.col("object").str.contains(curie_regex)).then(pl.col("id")).otherwise(pl.lit(None)).alias("invalid_curie_object"),
        ]).filter(pl.col("invalid_curie_object").is_null().not_()).collect()
        validation_reports.append(violations_df.write_ndjson())

    if counts_df.get_column("invalid_starts_with_biolink_predicate_count").item(0) > 0:
        violations_df = pl.scan_csv(edges, separator='\t', truncate_ragged_lines=True, has_header=True, ignore_errors=True).select([
            pl.when(~pl.col("predicate").str.contains(curie_regex)).then(pl.col("predicate")).otherwise(pl.lit(None)).alias("invalid_starts_with_biolink_predicate"),
        ]).filter(pl.col("invalid_starts_with_biolink_predicate").is_null().not_()).collect()
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
