"""Polars-based validator implementation."""

import logging

import polars as pl

from matrix_validator.validator import Validator
from matrix_validator.checks import DELIMITED_BY_PIPES, CURIE_REGEX, STARTS_WITH_BIOLINK_REGEX

logger = logging.getLogger(__name__)

class ValidatorPolarsImpl(Validator):
    """Polars-based validator implementation."""

    def __init__(self):
        """Create a new instance of the polars-based validator."""
        super().__init__()

    def validate(self, nodes_file_path, edges_file_file_path):
        """Validate a knowledge graph as nodes and edges KGX TSV files."""
        if nodes_file_path:
            validate_kg_nodes(nodes_file_path, self.output_format, self.get_report_file())

        if edges_file_file_path:
            validate_kg_edges(edges_file_file_path, self.output_format, self.get_report_file())


def validate_kg_nodes(nodes, output_format, report_file):
    """Validate a knowledge graph using optional nodes TSV files."""

    logger.info("Validating nodes TSV...")

    counts_df = (
        pl.scan_csv(nodes, separator="\t", truncate_ragged_lines=True, has_header=True, ignore_errors=True)
        .select(
            [
                pl.col("id").str.contains(CURIE_REGEX).sum().alias("valid_curie_id_count"),
                (~pl.col("id").str.contains(CURIE_REGEX)).sum().alias("invalid_curie_id_count"),
                pl.col("category").str.contains(STARTS_WITH_BIOLINK_REGEX).sum().alias("valid_starts_with_biolink_category_count"),
                (~pl.col("category").str.contains(STARTS_WITH_BIOLINK_REGEX)).sum().alias("invalid_starts_with_biolink_category_count"),
                pl.col("category").str.contains(DELIMITED_BY_PIPES).sum().alias("valid_delimited_by_pipes_category_count"),
                (~pl.col("category").str.contains(DELIMITED_BY_PIPES)).sum().alias("invalid_delimited_by_pipes_category_count"),
            ]
        )
        .collect()
    )
    
    validation_reports = []

    if counts_df.get_column("invalid_curie_id_count").item(0) > 0:
        from matrix_validator.checks.check_column_is_valid_curie import validate
        validation_reports.append(validate("id", nodes))

    if counts_df.get_column("invalid_starts_with_biolink_category_count").item(0) > 0:
        from matrix_validator.checks.check_column_starts_with_biolink import validate
        validation_reports.append(validate("category", nodes))

    if counts_df.get_column("invalid_delimited_by_pipes_category_count").item(0) > 0:
        from matrix_validator.checks.check_column_is_delimited_by_pipes import validate
        validation_reports.append(validate("category", nodes))

    # Write validation report
    write_report(output_format, report_file, validation_reports)
    logging.info(f"Validation report written to {report_file}")


def validate_kg_edges(edges, output_format, report_file):
    """Validate a knowledge graph using optional edges TSV files."""

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

    validation_reports = []

    if counts_df.get_column("invalid_curie_subject_count").item(0) > 0:
        from matrix_validator.checks.check_column_is_valid_curie import validate
        validation_reports.append(validate("subject", edges))

    if counts_df.get_column("invalid_curie_object_count").item(0) > 0:
        from matrix_validator.checks.check_column_is_valid_curie import validate
        validation_reports.append(validate("object", edges))

    if counts_df.get_column("invalid_starts_with_biolink_predicate_count").item(0) > 0:
        from matrix_validator.checks.check_column_starts_with_biolink import validate
        validation_reports.append(validate("predicate", edges))

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
