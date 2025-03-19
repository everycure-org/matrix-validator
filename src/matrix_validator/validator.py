"""Validator abstract class."""

import os
from abc import ABC, abstractmethod


class Validator(ABC):
    """Abstract class for a validator."""

    def __init__(self):
        """Create a new instance of the validator."""
        self.report_dir = None
        self.output_format = "txt"

    @abstractmethod
    def validate(self, nodes_file_path, edges_file_path, limit: int | None = None):
        """Validate a knowledge graph as nodes and edges KGX TSV files."""
        pass

    def is_set_report_dir(self):
        """Check if the report directory is set."""
        if self.get_report_dir():
            return True
        return False

    def set_report_dir(self, report_dir):
        """Set the report directory."""
        self.report_dir = report_dir

    def get_report_dir(self):
        """Get the report directory."""
        return self.report_dir

    def set_output_format(self, output_format):
        """Set the output format."""
        self.output_format = output_format

    def get_output_format(self):
        """Get the output format."""
        return self.output_format

    def get_report_file(self):
        """Get the path to the report file."""
        return os.path.join(self.report_dir, f"report.{self.output_format}")

    def write_report(self, validation_reports):
        """Write the validation report to a file."""
        report_file = self.get_report_file()
        with open(report_file, "w") as report:
            match self.output_format:
                case "txt":
                    report.write("\n".join(validation_reports))
                case "md":
                    report.write("\n\n".join([f"## {line}" for line in validation_reports]))
                case _:
                    report.write("\n".join(validation_reports))
