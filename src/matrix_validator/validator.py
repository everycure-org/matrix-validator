"""Main python file."""

import logging

from matrix_validator.datamodels import EdgeSchema, NodeSchema
from matrix_validator.util import read_tsv_as_strings

logger = logging.getLogger(__name__)


def validate_kg(nodes, edges, output_format, report_file):
    """Validate a knowledge graph using optional nodes and edges TSV files."""
    validation_reports = []

    # Validate nodes if provided
    if nodes:
        logger.info("Validating nodes TSV...")
        node_validation = NodeSchema.validate(read_tsv_as_strings(nodes), lazy=True).collect()
        # node_validation = read_tsv_as_strings(nodes).pipe(NodeSchema.validate).collect()
        validation_reports.append(f"Nodes Validation Passed: {node_validation}")

    # Validate edges if provided
    if edges:
        logger.info("Validating edges TSV...")
        edge_validation = EdgeSchema.validate(read_tsv_as_strings(edges), lazy=True).collect()
        # edge_validation = read_tsv_as_strings(edges).pipe(EdgeSchema.validate).collect()
        validation_reports.append(f"Edges Validation Passed: {edge_validation}")

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
