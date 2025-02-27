"""Polars-based validator implementation."""

import logging

import polars as pl

from matrix_validator.checks import (
    CURIE_REGEX,
    DELIMITED_BY_PIPES,
    NO_LEADING_WHITESPACE,
    NO_TRAILING_WHITESPACE,
    STARTS_WITH_BIOLINK_REGEX,
)
from matrix_validator.checks.check_column_contains_biolink_model_agent_type import (
    validate as check_column_contains_biolink_model_agent_type,
)
from matrix_validator.checks.check_column_contains_biolink_model_knowledge_level import (
    validate as check_column_contains_biolink_model_knowledge_level,
)
from matrix_validator.checks.check_column_contains_biolink_model_prefix import validate as check_column_contains_biolink_model_prefix
from matrix_validator.checks.check_column_is_delimited_by_pipes import validate as check_column_is_delimited_by_pipes
from matrix_validator.checks.check_column_is_valid_curie import validate as check_column_is_valid_curie
from matrix_validator.checks.check_column_no_leading_whitespace import validate as check_column_no_leading_whitespace
from matrix_validator.checks.check_column_no_trailing_whitespace import validate as check_column_no_trailing_whitespace
from matrix_validator.checks.check_column_starts_with_biolink import validate as check_column_starts_with_biolink
from matrix_validator.checks.check_edge_ids_in_node_ids import validate as check_edge_ids_in_node_ids
from matrix_validator.validator import Validator

logger = logging.getLogger(__name__)


class ValidatorPolarsImpl(Validator):
    """Polars-based validator implementation."""

    def __init__(self):
        """Create a new instance of the polars-based validator."""
        super().__init__()

    def validate(self, nodes_file_path, edges_file_path):
        """Validate a knowledge graph as nodes and edges KGX TSV files."""
        validation_reports = []

        bm_prefixes = self.get_biolink_model_prefix_keys()
        bm_knowledge_level_keys = self.get_biolink_model_knowledge_level_keys()
        bm_agent_type_keys = self.get_biolink_model_agent_type_keys()

        if nodes_file_path:
            validation_reports.extend(validate_kg_nodes(bm_prefixes, nodes_file_path))

        if edges_file_path:
            validation_reports.extend(validate_kg_edges(bm_prefixes, bm_knowledge_level_keys, bm_agent_type_keys, edges_file_path))

        if nodes_file_path and edges_file_path:
            validation_reports.extend(validate_node_ids_in_edges(nodes_file_path, edges_file_path))

        # Write validation report
        self.write_report(validation_reports)
        logging.info(f"Validation report written to {self.get_report_file()}")


def validate_node_ids_in_edges(nodes, edges):
    """Validate a knowledge graph nodes vs edges."""
    logger.info("Validating nodes & edges")

    edges_df = (
        pl.scan_csv(edges, separator="\t", truncate_ragged_lines=True, has_header=True, ignore_errors=True)
        .select([pl.col("subject"), pl.col("object")])
        .collect()
    )
    edge_ids = pl.concat([edges_df.select(pl.col("subject").alias("id")), edges_df.select(pl.col("object").alias("id"))]).get_column("id")

    counts_df = (
        pl.scan_csv(nodes, separator="\t", truncate_ragged_lines=True, has_header=True, ignore_errors=True)
        .select([(~pl.col("id").str.contains_any(edge_ids)).sum().alias("invalid_edge_ids_in_node_ids_count")])
        .collect()
    )

    validation_reports = []

    if counts_df.get_column("invalid_edge_ids_in_node_ids_count").item(0) > 0:
        validation_reports.append(check_edge_ids_in_node_ids(edge_ids, nodes))

    return validation_reports


def validate_kg_nodes(bm_prefixes, nodes):
    """Validate a knowledge graph using optional nodes TSV files."""
    logger.info("Validating nodes TSV...")

    counts_df = (
        pl.scan_csv(nodes, separator="\t", truncate_ragged_lines=True, has_header=True, ignore_errors=True)
        .select(
            [
                (~pl.col("id").str.contains(CURIE_REGEX)).sum().alias("invalid_curie_id_count"),
                (~pl.col("id").str.contains_any(bm_prefixes)).sum().alias("invalid_contains_biolink_model_prefix_id_count"),
                (~pl.col("category").str.contains(STARTS_WITH_BIOLINK_REGEX)).sum().alias("invalid_starts_with_biolink_category_count"),
                (~pl.col("category").str.contains(DELIMITED_BY_PIPES)).sum().alias("invalid_delimited_by_pipes_category_count"),
                (~pl.col("category").str.contains(NO_LEADING_WHITESPACE)).sum().alias("invalid_no_leading_whitespace_category_count"),
                (~pl.col("category").str.contains(NO_TRAILING_WHITESPACE)).sum().alias("invalid_no_trailing_whitespace_category_count"),
            ]
        )
        .collect()
    )

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

    return validation_reports


def validate_kg_edges(bm_prefixes, bm_knowledge_level_keys, bm_agent_type_keys, edges):
    """Validate a knowledge graph using optional edges TSV files."""
    logger.info("Validating edges TSV...")

    counts_df = (
        pl.scan_csv(edges, separator="\t", truncate_ragged_lines=True, has_header=True, ignore_errors=True)
        .select(
            [
                (~pl.col("subject").str.contains(CURIE_REGEX)).sum().alias("invalid_curie_subject_count"),
                (~pl.col("subject").str.contains_any(bm_prefixes)).sum().alias("invalid_contains_biolink_model_prefix_subject_count"),
                (~pl.col("predicate").str.contains(STARTS_WITH_BIOLINK_REGEX)).sum().alias("invalid_starts_with_biolink_predicate_count"),
                (~pl.col("object").str.contains(CURIE_REGEX)).sum().alias("invalid_curie_object_count"),
                (~pl.col("object").str.contains_any(bm_prefixes)).sum().alias("invalid_contains_biolink_model_prefix_object_count"),
                (~pl.col("knowledge_level").str.contains_any(bm_knowledge_level_keys))
                .sum()
                .alias("invalid_contains_biolink_model_knowledge_level_count"),
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

    return validation_reports
