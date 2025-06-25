"""Validator abstract class."""

import json
import os
from abc import ABC, abstractmethod
from importlib import resources as il_resources

import tomllib
from biolink_model import prefixmaps


class Validator(ABC):
    """Abstract class for a validator."""

    def __init__(self, config=None):
        """Create a new instance of the validator."""
        self.report_dir = None
        self.output_format = "txt"

        tmp_prefixes = list(json.loads(il_resources.files(prefixmaps).joinpath("biolink-model-prefix-map.json").read_text()).keys())

        # Handle the case when config is None or not provided
        if config is not None:
            with open(config, "rb") as config_file:
                config_contents = tomllib.load(config_file)
                self.config_contents = config_contents

            if config_contents["biolink"]["supplemental_prefixes"]:
                supplemental_prefixes = list(config_contents["biolink"]["supplemental_prefixes"])
                tmp_prefixes.extend(supplemental_prefixes)

        self.prefixes = list(set(tmp_prefixes))

        preferred_prefixes_per_class = json.loads(il_resources.files(prefixmaps).joinpath("preferred_prefixes_per_class.json").read_text())
        self.class_prefix_map = {
            item["class_name"]: [prefix["prefix"] for prefix in item["prefix_map"]]
            for item in preferred_prefixes_per_class["biolink_class_prefixes"]
        }

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
