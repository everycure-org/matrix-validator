"""Polars-based validator implementation."""

import json
import logging
import os
from typing import Optional

import patito as pt
import polars as pl
from patito.exceptions import _display_error_loc

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
from matrix_validator.checks.check_column_enum import validate as check_column_enum
from matrix_validator.checks.check_column_is_delimited_by_pipes import validate as check_column_is_delimited_by_pipes
from matrix_validator.checks.check_column_is_valid_curie import validate as check_column_is_valid_curie
from matrix_validator.checks.check_column_no_leading_whitespace import validate as check_column_no_leading_whitespace
from matrix_validator.checks.check_column_no_trailing_whitespace import validate as check_column_no_trailing_whitespace
from matrix_validator.checks.check_column_range import validate as check_column_range
from matrix_validator.checks.check_column_starts_with_biolink import validate as check_column_starts_with_biolink
from matrix_validator.checks.check_edge_ids_in_node_ids import validate as check_edge_ids_in_node_ids
from matrix_validator.checks.check_node_id_and_category_with_biolink_preferred_prefixes import (
    validate as check_node_id_and_category_with_biolink_preferred_prefixes,
)
from matrix_validator.validator import Validator

logger = logging.getLogger(__name__)

BIOLINK_KNOWLEDGE_LEVEL_KEYS = util.get_biolink_model_knowledge_level_keys()
BIOLINK_AGENT_TYPE_KEYS = util.get_biolink_model_agent_type_keys()


def create_edge_schema(prefixes: list[str]):
    """Create a EdgeSchema with a dynamic list of allowed prefixes."""

    class EdgeSchema(pt.Model):
        """EdgeSchema derived from Patito."""

        subject: str = pt.Field(constraints=[pt.field.str.contains(CURIE_REGEX), pt.field.str.contains_any(prefixes)])
        predicate: str = pt.Field(constraints=[pt.field.str.contains(STARTS_WITH_BIOLINK_REGEX)])
        object: str = pt.Field(constraints=[pt.field.str.contains(CURIE_REGEX), pt.field.str.contains_any(prefixes)])
        knowledge_level: str = pt.Field(constraints=[pt.field.str.contains_any(BIOLINK_KNOWLEDGE_LEVEL_KEYS)])
        agent_type: str = pt.Field(constraints=[pt.field.str.contains_any(BIOLINK_AGENT_TYPE_KEYS)])
        primary_knowledge_source: str
        aggregator_knowledge_source: str
        original_subject: str
        original_object: str
        publications: Optional[str]
        subject_aspect_qualifier: Optional[str]
        subject_direction_qualifier: Optional[str]
        object_aspect_qualifier: Optional[str]
        object_direction_qualifier: Optional[str]
        upstream_data_source: Optional[str]

    return EdgeSchema


def create_node_schema(prefixes: list[str]):
    """Create a NodeSchema with a dynamic list of allowed prefixes."""

    class NodeSchema(pt.Model):
        """NodeSchema derived from Patito."""

        id: str = pt.Field(constraints=[pt.field.str.contains(CURIE_REGEX), pt.field.str.contains_any(prefixes)])
        category: str = pt.Field(
            constraints=[
                pt.field.str.contains(STARTS_WITH_BIOLINK_REGEX),
                pt.field.str.contains(DELIMITED_BY_PIPES),
                pt.field.str.contains(NO_LEADING_WHITESPACE),
                pt.field.str.contains(NO_TRAILING_WHITESPACE),
            ]
        )
        name: Optional[str]
        description: Optional[str]
        equivalent_identifiers: Optional[str]
        all_categories: Optional[str]
        publications: Optional[str]
        labels: Optional[str]
        international_resource_identifier: Optional[str]

    return NodeSchema


class ValidatorPolarsImpl(Validator):
    """Polars-based validator implementation."""

    def __init__(self, config=None):
        """Create a new instance of the polars-based validator."""
        super().__init__(config)
        # Set a default report directory if none is provided
        if not self.get_report_dir():
            self.set_report_dir("output")

    def validate(self, nodes_file_path, edges_file_path, limit: int | None = None):
        """Validate a knowledge graph as nodes and edges KGX TSV files."""
        validation_reports = []

        if nodes_file_path:
            tmp_val_violations = self.validate_kg_nodes(nodes_file_path, limit)
            validation_reports.extend(tmp_val_violations)

        if edges_file_path:
            validation_reports.extend(self.validate_kg_edges(edges_file_path, limit))

        if nodes_file_path and edges_file_path:
            validation_reports.extend(self.validate_nodes_and_edges(nodes_file_path, edges_file_path, limit))

        # Create report directory if it doesn't exist
        if self.get_report_dir() and not os.path.exists(self.get_report_dir()):
            os.makedirs(self.get_report_dir())

        # Write validation report
        self.write_report(validation_reports)
        logging.info(f"Validation report written to {self.get_report_file()}")

    def validate_kg_nodes(self, nodes, limit):
        """Validate a knowledge graph using optional nodes TSV files."""
        logger.info("Validating nodes TSV...")

        validation_reports = []

        # do an initial schema check
        schema_df = pl.scan_csv(nodes, separator="\t", has_header=True, ignore_errors=True, low_memory=True).limit(10).collect()
        superfluous_columns = []

        node_schema = create_node_schema(self.prefixes)

        try:
            node_schema.validate(schema_df, allow_missing_columns=True, allow_superfluous_columns=False)
        except pt.exceptions.DataFrameValidationError as ex:
            superfluous_columns.extend([_display_error_loc(e) for e in ex.errors() if e["type"] == "type_error.superfluouscolumns"])

        try:
            node_schema.validate(schema_df, allow_missing_columns=True, allow_superfluous_columns=True)
        except pt.exceptions.DataFrameValidationError as ex:
            logger.warning(f"number of schema violations: {len(ex.errors())}")
            validation_reports.append("\n".join(f"{e['msg']}: {_display_error_loc(e)}" for e in ex.errors()))
            return validation_reports

        # and if schema check is good, move on to data checks
        if not validation_reports:
            # usable_columns = [pl.col("id"), pl.col("category")]
            # main_df = pl.scan_csv(nodes, separator="\t", has_header=True, ignore_errors=True, low_memory=True).select(usable_columns)
            main_df = pl.scan_csv(nodes, separator="\t", has_header=True, ignore_errors=True, low_memory=True)

            if limit:
                df = main_df.limit(limit).collect()
            else:
                df = main_df.collect()

            column_names = df.collect_schema().names()
            logger.debug(f"{column_names}")

            if self.config_contents and "nodes_attribute_checks" in self.config_contents:
                for check in self.config_contents["nodes_attribute_checks"]["checks"]:
                    if "range" in check:
                        if check["range"]["column"] in column_names:
                            validation_reports.append(
                                check_column_range(df, check["range"]["column"], int(check["range"]["min"]), int(check["range"]["max"]))
                            )
                    if "enum" in check:
                        if check["enum"]["column"] in column_names:
                            validation_reports.append(check_column_enum(df, check["range"]["column"], list(check["range"]["values"])))

            try:
                logger.info("collecting node counts")

                counts_df = df.select(
                    [
                        (~pl.col("id").str.contains(CURIE_REGEX)).sum().alias("invalid_curie_id_count"),
                        (~pl.col("id").str.contains_any(self.prefixes)).sum().alias("invalid_contains_biolink_model_prefix_id_count"),
                        (~pl.col("category").str.contains(STARTS_WITH_BIOLINK_REGEX))
                        .sum()
                        .alias("invalid_starts_with_biolink_category_count"),
                        (~pl.col("category").str.contains(DELIMITED_BY_PIPES)).sum().alias("invalid_delimited_by_pipes_category_count"),
                        (~pl.col("category").str.contains(NO_LEADING_WHITESPACE))
                        .sum()
                        .alias("invalid_no_leading_whitespace_category_count"),
                        (~pl.col("category").str.contains(NO_TRAILING_WHITESPACE))
                        .sum()
                        .alias("invalid_no_trailing_whitespace_category_count"),
                    ]
                )

                logger.debug(counts_df.head())

                if counts_df.get_column("invalid_curie_id_count").item(0) > 0:
                    validation_reports.append(check_column_is_valid_curie(df, "id"))

                if counts_df.get_column("invalid_contains_biolink_model_prefix_id_count").item(0) > 0:
                    validation_reports.append(check_column_contains_biolink_model_prefix(df, "id", self.prefixes))

                if counts_df.get_column("invalid_no_leading_whitespace_category_count").item(0) > 0:
                    validation_reports.append(check_column_no_leading_whitespace(df, "category"))

                if counts_df.get_column("invalid_no_trailing_whitespace_category_count").item(0) > 0:
                    validation_reports.append(check_column_no_trailing_whitespace(df, "category"))

                if counts_df.get_column("invalid_starts_with_biolink_category_count").item(0) > 0:
                    validation_reports.append(check_column_starts_with_biolink(df, "category"))

                if counts_df.get_column("invalid_delimited_by_pipes_category_count").item(0) > 0:
                    validation_reports.append(check_column_is_delimited_by_pipes(df, "category"))

                for violation in check_node_id_and_category_with_biolink_preferred_prefixes(self.class_prefix_map, df):
                    validation_reports.append(violation)

                logger.debug(f"number of total violations: {len(validation_reports)}")

            except pl.exceptions.ColumnNotFoundError as ex:
                logger.error(f"missing required column: {repr(ex)}")
                validation_reports.append(f"Missing required column: {repr(ex)}")
                return validation_reports
            except Exception as ex:
                logger.exception(ex)

            if superfluous_columns:
                logger.warning(
                    "The following columns are not recognised by the biolink model. "
                    + "This is not an error but consider suggesting these to be added to "
                    + f"biolink at https://github.com/biolink/biolink-model/issues.: {','.join(superfluous_columns)}"
                )

        return validation_reports

    def validate_kg_edges(self, edges, limit):
        """Validate a knowledge graph using optional edges TSV files."""
        logger.info("Validating edges TSV...")

        validation_reports = []

        # do an initial schema check
        schema_df = pl.scan_csv(edges, separator="\t", has_header=True, ignore_errors=True, low_memory=True).limit(10).collect()

        superfluous_columns = []

        edge_schema = create_edge_schema(self.prefixes)

        try:
            edge_schema.validate(schema_df, allow_missing_columns=True, allow_superfluous_columns=False)
        except pt.exceptions.DataFrameValidationError as ex:
            superfluous_columns.extend([_display_error_loc(e) for e in ex.errors() if e["type"] == "type_error.superfluouscolumns"])

        try:
            edge_schema.validate(schema_df, allow_missing_columns=True, allow_superfluous_columns=True)
        except pt.exceptions.DataFrameValidationError as ex:
            validation_reports.append("\n".join(f"{e['msg']}: {_display_error_loc(e)}" for e in ex.errors()))

        # and if schema check is good, move on to data checks
        if not validation_reports:
            # usable_columns = [pl.col("subject"), pl.col("predicate"), pl.col("object"), pl.col("knowledge_level"), pl.col("agent_type")]
            # main_df = pl.scan_csv(edges, separator="\t", has_header=True, ignore_errors=True, low_memory=True).select(usable_columns)

            main_df = pl.scan_csv(edges, separator="\t", has_header=True, ignore_errors=True, low_memory=True)

            if limit:
                df = main_df.limit(limit).collect()
            else:
                df = main_df.collect()

            column_names = df.collect_schema().names()
            logger.debug(f"{column_names}")
            if self.config_contents and "edges_attribute_checks" in self.config_contents:
                for check in self.config_contents["edges_attribute_checks"]["checks"]:
                    if "range" in check:
                        if check["range"]["column"] in column_names:
                            validation_reports.append(
                                check_column_range(df, check["range"]["column"], int(check["range"]["min"]), int(check["range"]["max"]))
                            )
                    if "enum" in check:
                        if check["enum"]["column"] in column_names:
                            validation_reports.append(check_column_enum(df, check["range"]["column"], list(check["range"]["values"])))

            try:
                logger.info("collecting edge counts")

                counts_df = df.select(
                    [
                        (~pl.col("subject").str.contains(CURIE_REGEX)).sum().alias("invalid_curie_subject_count"),
                        (~pl.col("subject").str.contains_any(self.prefixes))
                        .sum()
                        .alias("invalid_contains_biolink_model_prefix_subject_count"),
                        (~pl.col("predicate").str.contains(STARTS_WITH_BIOLINK_REGEX))
                        .sum()
                        .alias("invalid_starts_with_biolink_predicate_count"),
                        (~pl.col("object").str.contains(CURIE_REGEX)).sum().alias("invalid_curie_object_count"),
                        (~pl.col("object").str.contains_any(self.prefixes))
                        .sum()
                        .alias("invalid_contains_biolink_model_prefix_object_count"),
                        (~pl.col("knowledge_level").str.contains_any(BIOLINK_KNOWLEDGE_LEVEL_KEYS))
                        .sum()
                        .alias("invalid_contains_biolink_model_knowledge_level_count"),
                        (~pl.col("agent_type").str.contains_any(BIOLINK_AGENT_TYPE_KEYS))
                        .sum()
                        .alias("invalid_contains_biolink_model_agent_type_count"),
                    ]
                )

                logger.info(counts_df.head())

                if counts_df.get_column("invalid_curie_subject_count").item(0) > 0:
                    validation_reports.append(check_column_is_valid_curie(df, "subject"))

                if counts_df.get_column("invalid_contains_biolink_model_prefix_subject_count").item(0) > 0:
                    validation_reports.append(check_column_contains_biolink_model_prefix(df, "subject", self.prefixes))

                if counts_df.get_column("invalid_curie_object_count").item(0) > 0:
                    validation_reports.append(check_column_is_valid_curie(df, "object"))

                if counts_df.get_column("invalid_contains_biolink_model_prefix_object_count").item(0) > 0:
                    validation_reports.append(check_column_contains_biolink_model_prefix(df, "object", self.prefixes))

                if counts_df.get_column("invalid_starts_with_biolink_predicate_count").item(0) > 0:
                    validation_reports.append(check_column_starts_with_biolink(df, "predicate"))

                if counts_df.get_column("invalid_contains_biolink_model_knowledge_level_count").item(0) > 0:
                    validation_reports.append(
                        check_column_contains_biolink_model_knowledge_level(df, "knowledge_level", BIOLINK_KNOWLEDGE_LEVEL_KEYS)
                    )

                if counts_df.get_column("invalid_contains_biolink_model_agent_type_count").item(0) > 0:
                    validation_reports.append(check_column_contains_biolink_model_agent_type(df, "agent_type", BIOLINK_AGENT_TYPE_KEYS))

            except pl.exceptions.ColumnNotFoundError as ex:
                logger.error(f"missing required column: {repr(ex)}")
                validation_reports.append(f"Missing required column: {repr(ex)}")
                return validation_reports

            if superfluous_columns:
                logger.warning(
                    "The following columns are not recognised by the biolink model. "
                    + "This is not an error but consider suggesting these to be added to "
                    + f"biolink at https://github.com/biolink/biolink-model/issues.: {','.join(superfluous_columns)}"
                )

        return validation_reports

    def validate_nodes_and_edges(self, nodes, edges, limit):
        """Validate a knowledge graph nodes vs edges."""
        logger.info("Validating nodes & edges")

        edges_df = (
            pl.scan_csv(edges, separator="\t", has_header=True, ignore_errors=False, low_memory=True)
            .select([pl.col("subject"), pl.col("predicate"), pl.col("object")])
            .collect()
        )
        unique_edge_ids = (
            pl.concat(
                items=[edges_df.select(pl.col("subject").alias("id")), edges_df.select(pl.col("object").alias("id"))],
                how="vertical",
                parallel=True,
            )
            .unique()
            .get_column("id")
            .to_list()
        )

        logger.info("collecting counts")

        # Load node data
        nodes_df = pl.scan_csv(nodes, separator="\t", has_header=True, ignore_errors=False, low_memory=True)

        # If limit is specified, apply it to both nodes and edges
        if limit:
            nodes_df = nodes_df.limit(limit)

        # Collect node data
        nodes_df = nodes_df.collect()

        # Check if all edge IDs exist in node IDs
        counts_df = nodes_df.select([(~pl.col("id").str.contains_any(unique_edge_ids)).sum().alias("invalid_edge_ids_in_node_ids_count")])

        logger.info(counts_df.head())

        validation_reports = []

        # Check if there are missing node IDs referenced in edges
        if counts_df.get_column("invalid_edge_ids_in_node_ids_count").item(0) > 0:
            validation_reports.append(check_edge_ids_in_node_ids(nodes_df, unique_edge_ids, "id"))

        # Analyze edge types
        logger.info("Analyzing edge types")
        try:
            # Log the DataFrame structures for debugging
            logger.debug(f"Nodes DataFrame columns: {nodes_df.columns}")
            logger.debug(f"Edges DataFrame columns: {edges_df.columns}")

            edge_type_analysis = util.analyze_edge_types(nodes_df, edges_df)
            logger.info(f"Edge type analysis results shape: {edge_type_analysis.shape}")

            # Get counts of valid and invalid edge types
            valid_edges = edge_type_analysis.filter(pl.col("valid"))
            invalid_edges = edge_type_analysis.filter(~pl.col("valid"))

            # Count unique edge types and edge instances
            unique_valid_types = len(valid_edges)
            unique_invalid_types = len(invalid_edges)
            total_unique_types = unique_valid_types + unique_invalid_types

            valid_count = valid_edges.select(pl.sum("count")).item(0, 0) if not valid_edges.is_empty() else 0
            invalid_count = invalid_edges.select(pl.sum("count")).item(0, 0) if not invalid_edges.is_empty() else 0
            total_count = valid_count + invalid_count

            logger.info(f"Valid edges: {valid_count} ({unique_valid_types} unique types)")
            logger.info(f"Invalid edges: {invalid_count} ({unique_invalid_types} unique types)")
            logger.info(f"Total: {total_count} ({total_unique_types} unique types)")

            # Calculate percentages
            valid_percent = (valid_count / total_count * 100) if total_count > 0 else 0
            invalid_percent = (invalid_count / total_count * 100) if total_count > 0 else 0

            # Create a JSON report for edge type analysis
            edge_type_summary = {
                "edge_type_analysis": {
                    "total_edges": total_count,
                    "valid_edges": {"count": valid_count, "percent": round(valid_percent, 2), "unique_types": unique_valid_types},
                    "invalid_edges": {"count": invalid_count, "percent": round(invalid_percent, 2), "unique_types": unique_invalid_types},
                }
            }

            validation_reports.append(json.dumps(edge_type_summary, indent=2))

            # Add more detailed report about invalid edge types if there are any
            if invalid_count > 0:
                invalid_edge_types = edge_type_analysis.filter(~pl.col("valid")).sort("count", descending=True)
                logger.info(f"Found {unique_invalid_types} distinct invalid edge types")

                # Format invalid edge types for reporting (limit to top 20 for readability)
                invalid_types_report = {}
                for row in invalid_edge_types.head(20).iter_rows(named=True):
                    key = f"{row['subject_category']}-{row['predicate']}-{row['object_category']}"
                    value = row["count"]
                    invalid_types_report[key] = value

                # Build a dictionary for invalid edge types
                invalid_edge_types_dict = {
                    "warning": f"{invalid_count} edges ({invalid_percent:.2f}%) have invalid edge types according to the biolink model.",
                    "valid": {"count": valid_count, "percent": round(valid_percent, 2), "unique_types": unique_valid_types},
                    "invalid": {
                        "count": invalid_count,
                        "percent": round(invalid_percent, 2),
                        "unique_types": unique_invalid_types,
                        "top_invalid_edge_types": invalid_types_report,
                    },
                }
                validation_reports.append(json.dumps(invalid_edge_types_dict, indent=2))
                logger.info("Added invalid edge types warning to validation report")
            else:
                success_message = (
                    f"All {total_count} edges have valid edge types according to the biolink model.\n"
                    f"Number of unique valid edge types: {unique_valid_types}"
                )
                validation_reports.append(success_message)
                logger.info(success_message)

        except Exception as e:
            logger.error(f"Error analyzing edge types: {str(e)}")
            logger.exception("Full traceback:")
            # Don't add to validation reports as this is not a critical error

        return validation_reports
