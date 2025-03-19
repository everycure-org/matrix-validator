"""Schema-based validator implementation."""

import json
import logging

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


def write_report(output_format, report_file, validation_reports):
    """Write the validation report to a file."""
    if report_file:
        with open(report_file, "w") as report:
            if output_format == "txt":
                report.write("\n".join(validation_reports))
            elif output_format == "md":
                report.write("\n\n".join([f"## {line}" for line in validation_reports]))


class ValidatorPanderaImpl(Validator):
    """Pandera-based validator implementation."""

    def __init__(self):
        """Create a new instance of the pandera-based validator."""
        super().__init__()

    def validate(self, nodes_file_path, edges_file_path, limit: int | None = None):
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
                validation_reports.append("❌ **Edges Validation Failed**:\n No valid data frame could be loaded.\n{error_message}")

        if self.is_set_report_dir():
            write_report(self.get_output_format(), self.get_report_file(), validation_reports)
