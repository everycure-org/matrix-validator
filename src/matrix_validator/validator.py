"""Validator abstract class."""

import os
import yaml
from yaml import SafeLoader
from abc import ABC, abstractmethod
from biolink_model.datamodel.pydanticmodel_v2 import KnowledgeLevelEnum, AgentTypeEnum
from importlib import resources as il_resources


class Validator(ABC):
    """Abstract class for a validator."""

    def __init__(self):
        """Create a new instance of the validator."""
        self.report_dir = None
        self.output_format = "txt"
        from biolink_model import schema

        self.bl_model_data = list(yaml.load_all(il_resources.read_text(schema, "biolink_model.yaml"), Loader=SafeLoader))

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

    def get_biolink_model_prefix_keys(self):
        """Get biolink model prefix keys."""
        return list(self.bl_model_data[0]["prefixes"].keys())

    def get_biolink_model_knowledge_level_keys(self):
        """Get biolink model knowledge_level keys."""
        return list(self.bl_model_data[0]["enums"]["KnowledgeLevelEnum"]["permissible_values"].keys())
        # return [k.value for k in KnowledgeLevelEnum]

    def get_biolink_model_agent_type_keys(self):
        """Get biolink model agent_type keys."""
        return list(self.bl_model_data[0]["enums"]["AgentTypeEnum"]["permissible_values"].keys())
        # return [k.value for k in AgentTypeEnum]

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
