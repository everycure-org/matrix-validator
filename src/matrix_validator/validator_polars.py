"""Polars-based validator implementation."""

from matrix_validator.validator import Validator

NCNAME_PATTERN = r"[A-Za-z_][A-Za-z0-9\.\-_]*"
LOCAL_UNIQUE_IDENTIFIER_PATTERN = r"(/[^\s/][^\s]*|[^\s/][^\s]*|[^\s]?)"

CURIE_REGEX = rf"^({NCNAME_PATTERN}?:)?{LOCAL_UNIQUE_IDENTIFIER_PATTERN}$"
STARTS_WITH_BIOLINK_REGEX = rf"^biolink:{LOCAL_UNIQUE_IDENTIFIER_PATTERN}$"


class ValidatorPolarsImpl(Validator):
    """Polars-based validator implementation."""

    def __init__(self):
        """Create a new instance of the polars-based validator."""
        super().__init__()

    def validate(self, nodes_file_path, edges_file_file_path):
        """Validate a knowledge graph as nodes and edges KGX TSV files."""
        if nodes_file_path:
            validate_kg_nodes(nodes_file_path, self.output_format, self.report_file)

        if edges_file_file_path:
            validate_kg_edges(edges_file_file_path, self.output_format, self.report_file)


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
