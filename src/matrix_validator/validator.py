"""Validator abstract class."""

import os
from abc import ABC, abstractmethod

NCNAME_PATTERN = r"[A-Za-z_][A-Za-z0-9\.\-_]*"
LOCAL_UNIQUE_IDENTIFIER_PATTERN = r"(/[^\s/][^\s]*|[^\s/][^\s]*|[^\s]?)"

CURIE_REGEX = rf"^({NCNAME_PATTERN}?:)?{LOCAL_UNIQUE_IDENTIFIER_PATTERN}$"
STARTS_WITH_BIOLINK_REGEX = rf"^biolink:{LOCAL_UNIQUE_IDENTIFIER_PATTERN}$"


class Validator(ABC):
    """Abstract class for a validator."""

    def __init__(self):
        """Create a new instance of the validator."""
        self.report_dir = None
        self.output_format = "txt"

    @abstractmethod
    def validate(self, nodes_file_path, edges_file_path):
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
