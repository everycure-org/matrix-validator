"""Polars-based validator implementation."""

import json
import logging
from typing import Optional

import pandera.errors
import polars as pl
from biolink_model.datamodel.model import KnowledgeLevelEnum
from patito.exceptions import _display_error_loc
from polars import DataFrame

from matrix_validator import util
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
from matrix_validator.datamodels import MatrixEdgeSchema
from matrix_validator.validator import Validator

logger = logging.getLogger(__name__)

from typing import Literal

import patito as pt

BIOLINK_PREFIX_KEYS = util.get_biolink_model_prefix_keys()
BIOLINK_KNOWLEDGE_LEVEL_KEYS = util.get_biolink_model_prefix_keys()
BIOLINK_AGENT_TYPE_KEYS = util.get_biolink_model_prefix_keys()


class EdgeSchema(pt.Model):
    subject: str = pt.Field(constraints=[pt.field.str.contains(CURIE_REGEX), pt.field.str.contains_any(BIOLINK_PREFIX_KEYS)])
    predicate: str = pt.Field(constraints=[pt.field.str.contains(STARTS_WITH_BIOLINK_REGEX)])
    object: str = pt.Field(constraints=[pt.field.str.contains(CURIE_REGEX), pt.field.str.contains_any(BIOLINK_PREFIX_KEYS)])
    knowledge_level: Optional[str] = pt.Field(constraints=[pt.field.str.contains_any(BIOLINK_KNOWLEDGE_LEVEL_KEYS)])
    agent_type: Optional[str] = pt.Field(constraints=[pt.field.str.contains_any(BIOLINK_AGENT_TYPE_KEYS)])
    primary_knowledge_source: Optional[str]
    aggregator_knowledge_source: Optional[str]
    publications: Optional[str]
    subject_aspect_qualifier: Optional[str]
    subject_direction_qualifier: Optional[str]
    object_aspect_qualifier: Optional[str]
    object_direction_qualifier: Optional[str]
    upstream_data_source: Optional[str]


class NodeSchema(pt.Model):
    id: str = pt.Field(constraints=[pt.field.str.contains(CURIE_REGEX), pt.field.str.contains_any(util.get_biolink_model_prefix_keys())])
    name: Optional[str]
    category: str = pt.Field(
        constraints=[
            pt.field.str.contains(STARTS_WITH_BIOLINK_REGEX),
            pt.field.str.contains(DELIMITED_BY_PIPES),
            pt.field.str.contains(NO_LEADING_WHITESPACE),
            pt.field.str.contains(NO_TRAILING_WHITESPACE),
        ]
    )
    description: Optional[str]
    equivalent_identifiers: Optional[str]
    all_categories: Optional[str]
    publications: Optional[str]
    labels: Optional[str]
    international_resource_identifier: Optional[str]


class ValidatorPolarsImpl(Validator):
    """Polars-based validator implementation."""

    def __init__(self):
        """Create a new instance of the polars-based validator."""
        super().__init__()

    def validate(self, nodes_file_path, edges_file_path, limit: int | None = None):
        """Validate a knowledge graph as nodes and edges KGX TSV files."""
        validation_reports = []

        if nodes_file_path:
            validation_reports.extend(validate_kg_nodes(nodes_file_path, limit))

        if edges_file_path:
            validation_reports.extend(validate_kg_edges(edges_file_path, limit))

        if nodes_file_path and edges_file_path:
            validation_reports.extend(validate_nodes_and_edges(nodes_file_path, edges_file_path))

        # Write validation report
        self.write_report(validation_reports)
        logging.info(f"Validation report written to {self.get_report_file()}")


def validate_nodes_and_edges(nodes, edges):
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


def validate_kg_nodes(nodes, limit):
    """Validate a knowledge graph using optional nodes TSV files."""
    logger.info("Validating nodes TSV...")

    validation_reports = []

    main_df = pl.scan_csv(nodes, separator="\t", truncate_ragged_lines=True, has_header=True, ignore_errors=True, low_memory=True).select(
        [pl.col("id"), pl.col("category")]
    )

    if limit:
        df = main_df.limit(limit).collect()
    else:
        df = main_df.collect()

    try:
        NodeSchema.validate(df)
    except pt.exceptions.DataFrameValidationError as ex:
        validation_reports.append("\n".join(f"{e['msg']}: {_display_error_loc(e)}" for e in ex.errors()))

    counts_df = df.select(
        [
            (~pl.col("id").str.contains(CURIE_REGEX)).sum().alias("invalid_curie_id_count"),
            (~pl.col("id").str.contains_any(BIOLINK_PREFIX_KEYS)).sum().alias("invalid_contains_biolink_model_prefix_id_count"),
            (~pl.col("category").str.contains(STARTS_WITH_BIOLINK_REGEX)).sum().alias("invalid_starts_with_biolink_category_count"),
            (~pl.col("category").str.contains(DELIMITED_BY_PIPES)).sum().alias("invalid_delimited_by_pipes_category_count"),
            (~pl.col("category").str.contains(NO_LEADING_WHITESPACE)).sum().alias("invalid_no_leading_whitespace_category_count"),
            (~pl.col("category").str.contains(NO_TRAILING_WHITESPACE)).sum().alias("invalid_no_trailing_whitespace_category_count"),
        ]
    )

    if counts_df.get_column("invalid_curie_id_count").item(0) > 0:
        validation_reports.append(check_column_is_valid_curie(df, "id"))

    if counts_df.get_column("invalid_contains_biolink_model_prefix_id_count").item(0) > 0:
        validation_reports.append(check_column_contains_biolink_model_prefix(df, "id", BIOLINK_PREFIX_KEYS))

    if counts_df.get_column("invalid_no_leading_whitespace_category_count").item(0) > 0:
        validation_reports.append(check_column_no_leading_whitespace(df, "category"))

    if counts_df.get_column("invalid_no_trailing_whitespace_category_count").item(0) > 0:
        validation_reports.append(check_column_no_trailing_whitespace(df, "category"))

    if counts_df.get_column("invalid_starts_with_biolink_category_count").item(0) > 0:
        validation_reports.append(check_column_starts_with_biolink(df, "category"))

    if counts_df.get_column("invalid_delimited_by_pipes_category_count").item(0) > 0:
        validation_reports.append(check_column_is_delimited_by_pipes(df, "category"))

    return validation_reports


def validate_kg_edges(edges, limit):
    """Validate a knowledge graph using optional edges TSV files."""
    logger.info("Validating edges TSV...")

    validation_reports = []

    columns = pl.scan_csv(edges, separator="\t", truncate_ragged_lines=True, has_header=True, ignore_errors=True, low_memory=True).limit(1).collect().columns

    usable_columns = [pl.col("subject"), pl.col("predicate"), pl.col("object")]

    if "knowledge_level" in columns and "agent_type" in columns:
        usable_columns.append(pl.col("knowledge_level"))
        usable_columns.append(pl.col("agent_type"))

    main_df = pl.scan_csv(edges, separator="\t", truncate_ragged_lines=True, has_header=True, ignore_errors=True, low_memory=True).select(usable_columns)

    if limit:
        df = main_df.limit(limit).collect()
    else:
        df = main_df.collect()

    try:
        EdgeSchema.validate(df)
    except pt.exceptions.DataFrameValidationError as ex:
        validation_reports.append("\n".join(f"{e['msg']}: {_display_error_loc(e)}" for e in ex.errors()))

    counts_df = df.select(
        [
            (~pl.col("subject").str.contains(CURIE_REGEX)).sum().alias("invalid_curie_subject_count"),
            (~pl.col("subject").str.contains_any(BIOLINK_PREFIX_KEYS)).sum().alias("invalid_contains_biolink_model_prefix_subject_count"),
            (~pl.col("predicate").str.contains(STARTS_WITH_BIOLINK_REGEX)).sum().alias("invalid_starts_with_biolink_predicate_count"),
            (~pl.col("object").str.contains(CURIE_REGEX)).sum().alias("invalid_curie_object_count"),
            (~pl.col("object").str.contains_any(BIOLINK_PREFIX_KEYS)).sum().alias("invalid_contains_biolink_model_prefix_object_count"),
            # (~pl.col("knowledge_level").str.contains_any(BIOLINK_KNOWLEDGE_LEVEL_KEYS))
            # .sum()
            # .alias("invalid_contains_biolink_model_knowledge_level_count"),
            # (~pl.col("agent_type").str.contains_any(BIOLINK_AGENT_TYPE_KEYS))
            # .sum()
            # .alias("invalid_contains_biolink_model_agent_type_count"),
        ]
    )

    if counts_df.get_column("invalid_curie_subject_count").item(0) > 0:
        validation_reports.append(check_column_is_valid_curie(df, "subject"))

    if counts_df.get_column("invalid_contains_biolink_model_prefix_subject_count").item(0) > 0:
        validation_reports.append(check_column_contains_biolink_model_prefix(df, "subject", BIOLINK_PREFIX_KEYS))

    if counts_df.get_column("invalid_curie_object_count").item(0) > 0:
        validation_reports.append(check_column_is_valid_curie(df, "object"))

    if counts_df.get_column("invalid_contains_biolink_model_prefix_object_count").item(0) > 0:
        validation_reports.append(check_column_contains_biolink_model_prefix(df, "object", BIOLINK_PREFIX_KEYS))

    if counts_df.get_column("invalid_starts_with_biolink_predicate_count").item(0) > 0:
        validation_reports.append(check_column_starts_with_biolink(df, "predicate"))

    # if counts_df.get_column("invalid_contains_biolink_model_knowledge_level_count").item(0) > 0:
    #     validation_reports.append(check_column_contains_biolink_model_knowledge_level(df, "knowledge_level", BIOLINK_KNOWLEDGE_LEVEL_KEYS))
    #
    # if counts_df.get_column("invalid_contains_biolink_model_agent_type_count").item(0) > 0:
    #     validation_reports.append(check_column_contains_biolink_model_agent_type(df, "agent_type", BIOLINK_AGENT_TYPE_KEYS))

    return validation_reports
