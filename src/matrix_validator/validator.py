"""Validator abstract class."""

import json
import sys
from abc import ABC, abstractmethod
from importlib import resources as il_resources

import tomllib
from typing import Any

from biolink_model import prefixmaps


class Validator(ABC):
    """Abstract class for a validator."""

    def __init__(self, nodes: Any, edges: Any, config=None):
        """Create a new instance of the validator."""
        self.output_format = "txt"
        self.config_contents = None
        self._nodes = nodes
        self._edges = edges

        tmp_prefixes = list(json.loads(il_resources.files(prefixmaps).joinpath("biolink-model-prefix-map.json").read_text()).keys())

        # Handle the case when config is None or not provided
        if config is not None:
            with open(config, "rb") as config_file:
                self.config_contents = tomllib.load(config_file)

            if self.config_contents and "biolink" in self.config_contents:
                biolink_config = self.config_contents["biolink"]
                if "supplemental_prefixes" in biolink_config:
                    supplemental_prefixes = list(biolink_config["supplemental_prefixes"])
                    tmp_prefixes.extend(supplemental_prefixes)

        self.prefixes = list(set(tmp_prefixes))

        preferred_prefixes_per_class = json.loads(il_resources.files(prefixmaps).joinpath("preferred_prefixes_per_class.json").read_text())
        self.class_prefix_map = {
            item["class_name"]: [prefix["prefix"] for prefix in item["prefix_map"]]
            for item in preferred_prefixes_per_class["biolink_class_prefixes"]
        }

    @abstractmethod
    def validate(self, limit: int | None = None) -> int:
        """Validate a knowledge graph as nodes and edges KGX TSV files."""
        ...

    def set_output_format(self, output_format):
        """Set the output format."""
        self.output_format = output_format

    def get_output_format(self):
        """Get the output format."""
        return self.output_format

    def write_output(self, validation_reports):
        """Write the validation output"""
        match self.output_format:
            case "txt":
                sys.stdout.write("\n".join(validation_reports))
            case "md":
                sys.stdout.write("\n\n".join([f"## {line}" for line in validation_reports]))
            case _:
                sys.stdout.write("\n".join(validation_reports))
