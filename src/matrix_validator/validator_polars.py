"""Polars-based validator implementation."""

import logging

import polars as pl
import yaml
from yaml import SafeLoader
from importlib import resources as il_resources
from matrix_validator.checks import (
    CURIE_REGEX,
    DELIMITED_BY_PIPES,
    NO_LEADING_WHITESPACE,
    NO_TRAILING_WHITESPACE,
    STARTS_WITH_BIOLINK_REGEX,
)
from matrix_validator.checks.check_column_is_delimited_by_pipes import validate as check_column_is_delimited_by_pipes
from matrix_validator.checks.check_column_contains_biolink_model_knowledge_level import (
    validate as check_column_contains_biolink_model_knowledge_level,
)
from matrix_validator.checks.check_column_contains_biolink_model_agent_type import (
    validate as check_column_contains_biolink_model_agent_type,
)
from matrix_validator.checks.check_column_is_valid_curie import validate as check_column_is_valid_curie
from matrix_validator.checks.check_column_contains_biolink_model_prefix import validate as check_column_contains_biolink_model_prefix
from matrix_validator.checks.check_column_no_leading_whitespace import validate as check_column_no_leading_whitespace
from matrix_validator.checks.check_column_no_trailing_whitespace import validate as check_column_no_trailing_whitespace
from matrix_validator.checks.check_column_starts_with_biolink import validate as check_column_starts_with_biolink
from matrix_validator.validator import Validator
from yaml import SafeLoader

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


def get_biolink_model_prefix_keys():
    from . import resources

    with il_resources.open_text(resources, "biolink-model.yaml") as file:
        bl_model_data = list(yaml.load_all(file, Loader=SafeLoader))
    return list(bl_model_data[0]["prefixes"].keys())


def get_biolink_model_knowledge_level_keys():
    from . import resources

    with il_resources.open_text(resources, "biolink-model.yaml") as file:
        bl_model_data = list(yaml.load_all(file, Loader=SafeLoader))
    return list(bl_model_data[0]["enums"]["KnowledgeLevelEnum"]["permissible_values"].keys())


def get_biolink_model_agent_type_keys():
    from . import resources

    with il_resources.open_text(resources, "biolink-model.yaml") as file:
        bl_model_data = list(yaml.load_all(file, Loader=SafeLoader))
    return list(bl_model_data[0]["enums"]["AgentTypeEnum"]["permissible_values"].keys())


def validate_kg_nodes(nodes, output_format, report_file):
    """Validate a knowledge graph using optional nodes TSV files."""
    logger.info("Validating nodes TSV...")

    bm_prefixes = get_biolink_model_prefix_keys()

    counts_df = (
        pl.scan_csv(nodes, separator="\t", truncate_ragged_lines=True, has_header=True, ignore_errors=True)
        .select(
            [
                # we only really care about the invalids
                # pl.col("id").str.contains(CURIE_REGEX).sum().alias("valid_curie_id_count"),
                (~pl.col("id").str.contains(CURIE_REGEX)).sum().alias("invalid_curie_id_count"),
                # pl.col("id").str.contains_any(bm_prefixes).sum().alias("valid_contains_biolink_model_prefix_id_count"),
                (~pl.col("id").str.contains_any(bm_prefixes)).sum().alias("invalid_contains_biolink_model_prefix_id_count"),
                # pl.col("category").str.contains(STARTS_WITH_BIOLINK_REGEX).sum().alias("valid_starts_with_biolink_category_count"),
                (~pl.col("category").str.contains(STARTS_WITH_BIOLINK_REGEX)).sum().alias("invalid_starts_with_biolink_category_count"),
                # pl.col("category").str.contains(DELIMITED_BY_PIPES).sum().alias("valid_delimited_by_pipes_category_count"),
                (~pl.col("category").str.contains(DELIMITED_BY_PIPES)).sum().alias("invalid_delimited_by_pipes_category_count"),
                # pl.col("category").str.contains(NO_LEADING_WHITESPACE).sum().alias("valid_no_leading_whitespace_category_count"),
                (~pl.col("category").str.contains(NO_LEADING_WHITESPACE)).sum().alias("invalid_no_leading_whitespace_category_count"),
                # pl.col("category").str.contains(NO_TRAILING_WHITESPACE).sum().alias("valid_no_trailing_whitespace_category_count"),
                (~pl.col("category").str.contains(NO_TRAILING_WHITESPACE)).sum().alias("invalid_no_trailing_whitespace_category_count"),
            ]
        )
        .collect()
    )
    # print(counts_df.write_json())
    validation_reports = []

    if counts_df.get_column("invalid_curie_id_count").item(0) > 0:
        validation_reports.append(check_column_is_valid_curie("id", nodes))

    if counts_df.get_column("invalid_contains_biolink_model_prefix_id_count").item(0) > 0:
        validation_reports.append(check_column_contains_biolink_model_prefix("id", bm_prefixes, nodes))

    if counts_df.get_column("invalid_no_leading_whitespace_category_count").item(0) > 0:
        validation_reports.append(check_column_no_leading_whitespace("category", nodes))

    if counts_df.get_column("invalid_no_trailing_whitespace_category_count").item(0) > 0:
        validation_reports.append(check_column_no_trailing_whitespace("category", nodes))

    if counts_df.get_column("invalid_starts_with_biolink_category_count").item(0) > 0:
        validation_reports.append(check_column_starts_with_biolink("category", nodes))

    if counts_df.get_column("invalid_delimited_by_pipes_category_count").item(0) > 0:
        validation_reports.append(check_column_is_delimited_by_pipes("category", nodes))

    # Write validation report
    write_report(output_format, report_file, validation_reports)
    logging.info(f"Validation report written to {report_file}")


def validate_kg_edges(edges, output_format, report_file):
    """Validate a knowledge graph using optional edges TSV files."""
    logger.info("Validating edges TSV...")

    bm_prefixes = get_biolink_model_prefix_keys()
    bm_knowledge_level_keys = get_biolink_model_knowledge_level_keys()
    bm_agent_type_keys = get_biolink_model_agent_type_keys()

    counts_df = (
        pl.scan_csv(edges, separator="\t", truncate_ragged_lines=True, has_header=True, ignore_errors=True)
        .select(
            [
                # we only really care about the invalids
                # pl.col("subject").str.contains(CURIE_REGEX).sum().alias("valid_curie_subject_count"),
                (~pl.col("subject").str.contains(CURIE_REGEX)).sum().alias("invalid_curie_subject_count"),
                # pl.col("subject").str.contains_any(bm_prefixes).sum().alias("valid_contains_biolink_model_prefix_subject_count"),
                (~pl.col("subject").str.contains_any(bm_prefixes)).sum().alias("invalid_contains_biolink_model_prefix_subject_count"),
                # pl.col("predicate").str.contains(STARTS_WITH_BIOLINK_REGEX).sum().alias("valid_starts_with_biolink_predicate_count"),
                (~pl.col("predicate").str.contains(STARTS_WITH_BIOLINK_REGEX)).sum().alias("invalid_starts_with_biolink_predicate_count"),
                # pl.col("object").str.contains(CURIE_REGEX).sum().alias("valid_curie_object_count"),
                (~pl.col("object").str.contains(CURIE_REGEX)).sum().alias("invalid_curie_object_count"),
                # pl.col("object").str.contains_any(bm_prefixes).sum().alias("valid_contains_biolink_model_prefix_object_count"),
                (~pl.col("object").str.contains_any(bm_prefixes)).sum().alias("invalid_contains_biolink_model_prefix_object_count"),
                # pl.col("knowledge_level").str.contains_any(bm_knowledge_level_keys).sum().alias("valid_contains_biolink_model_knowledge_level_count"),
                (~pl.col("knowledge_level").str.contains_any(bm_knowledge_level_keys))
                .sum()
                .alias("invalid_contains_biolink_model_knowledge_level_count"),
                # pl.col("agent_type").str.contains_any(bm_knowledge_level_keys).sum().alias("valid_contains_biolink_model_agent_type_count"),
                (~pl.col("agent_type").str.contains_any(bm_knowledge_level_keys))
                .sum()
                .alias("invalid_contains_biolink_model_agent_type_count"),
            ]
        )
        .collect()
    )

    validation_reports = []

    if counts_df.get_column("invalid_curie_subject_count").item(0) > 0:
        validation_reports.append(check_column_is_valid_curie("subject", edges))

    if counts_df.get_column("invalid_contains_biolink_model_prefix_subject_count").item(0) > 0:
        validation_reports.append(check_column_contains_biolink_model_prefix("subject", bm_prefixes, edges))

    if counts_df.get_column("invalid_curie_object_count").item(0) > 0:
        validation_reports.append(check_column_is_valid_curie("object", edges))

    if counts_df.get_column("invalid_contains_biolink_model_prefix_object_count").item(0) > 0:
        validation_reports.append(check_column_contains_biolink_model_prefix("object", bm_prefixes, edges))

    if counts_df.get_column("invalid_starts_with_biolink_predicate_count").item(0) > 0:
        validation_reports.append(check_column_starts_with_biolink("predicate", edges))

    if counts_df.get_column("invalid_contains_biolink_model_knowledge_level_count").item(0) > 0:
        validation_reports.append(check_column_contains_biolink_model_knowledge_level("knowledge_level", bm_knowledge_level_keys, edges))

    if counts_df.get_column("invalid_contains_biolink_model_agent_type_count").item(0) > 0:
        validation_reports.append(check_column_contains_biolink_model_agent_type("agent_type", bm_agent_type_keys, edges))

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
