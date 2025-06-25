"""Schema-based validator implementation."""

import json
import logging
import os

import polars as pl

from matrix_validator.datamodels import MatrixEdgeSchema, MatrixNodeSchema
from matrix_validator.validator import Validator

logger = logging.getLogger(__name__)


def format_schema_error(error: dict) -> str:
    """Format Pandera schema validation errors for better readability."""
    formatted_messages = []

    if "SCHEMA" in error:
        for issue_type, issues in error["SCHEMA"].items():
            print("-----")
            print(issue_type)
            print(issues)
            for issue in issues:
                formatted_messages.append(
                    f"  - ❌ **{issue_type.replace('_', ' ').title()} ({issue.get('check', 'Unknown check')})**\n"
                    f"    - Schema: `{issue.get('schema', 'Unknown')}`\n"
                    f"    - Column: `{issue.get('column', 'Unknown')}`\n"
                    f"    - Error: {issue.get('error', 'No details')}\n"
                )

    return "\n".join(formatted_messages) if formatted_messages else str(error)


class ValidatorPanderaImpl(Validator):
    """Pandera-based validator implementation."""

    def __init__(self, config=None):
        """Create a new instance of the pandera-based validator."""
        super().__init__(config)

    def validate(self, nodes_file_path, edges_file_path, limit: int | None = None) -> int:
        """Validate a knowledge graph as nodes and edges KGX TSV files."""
        validation_reports = []

        if nodes_file_path:
            try:
                logging.warning(f"🔍 Validating Nodes TSV: {nodes_file_path}")
                df_nodes = pl.read_csv(nodes_file_path, separator="\t", infer_schema_length=0)
                try:
                    MatrixNodeSchema.validate(df_nodes, lazy=True)
                    validation_reports.append("✅ **Nodes Validation Passed**")
                except Exception as e:
                    error_message = json.loads(str(e)) if "SCHEMA" in str(e) else str(e)
                    validation_reports.append(f"❌ **Nodes Validation Failed**:\n{format_schema_error(error_message)}")
            except Exception as e:
                error_message = str(e)
                validation_reports.append(f"❌ **Nodes Validation Failed**:\n No valid data frame could be loaded.\n{error_message}")

        if edges_file_path:
            try:
                logging.warning(f"🔍 Validating edges TSV: {edges_file_path}")
                df_edges = pl.read_csv(edges_file_path, separator="\t", infer_schema_length=0)
                try:
                    MatrixEdgeSchema.validate(df_edges, lazy=True)
                    validation_reports.append("✅ **Edges Validation Passed**")
                except Exception as e:
                    error_message = json.loads(str(e)) if "SCHEMA" in str(e) else str(e)
                    validation_reports.append(f"❌ **Edges Validation Failed**:\n{format_schema_error(error_message)}")
            except Exception as e:
                error_message = str(e)
                validation_reports.append(f"❌ **Edges Validation Failed**:\n No valid data frame could be loaded.\n{error_message}")

        # Write validation report
        self.write_output(validation_reports)

        if len(validation_reports) > 0:
            return 1
        return 0
