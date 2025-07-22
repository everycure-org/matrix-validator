"""Test Validation."""

import json
import os.path
import polars as pl
import unittest
from importlib import resources as il_resources

from biolink_model import prefixmaps

from matrix_validator.validator_polars import ValidatorPolarsDataFrameImpl
from matrix_validator.validator_schema import ValidatorPanderaImpl


class TestValidate(unittest.TestCase):
    """Test validate."""

    def test_version_type(self):
        """Test validation method."""
        validator = ValidatorPanderaImpl(config="./config.toml")
        validator.validate(nodes_file_path=None, edges_file_path=None)

    def test_biolink_prefix_class_mapping(self):
        """Test extraction of biolink preferred prefix per category mapping."""
        preferred_prefixes_per_class = json.loads(il_resources.files(prefixmaps).joinpath("preferred_prefixes_per_class.json").read_text())
        class_prefix_map = {
            item["class_name"]: [prefix["prefix"] for prefix in item["prefix_map"]]
            for item in preferred_prefixes_per_class["biolink_class_prefixes"]
        }

        print(class_prefix_map)

        prefix_class_map = {}

        for key in class_prefix_map.keys():
            prefixes = class_prefix_map[key]

            for prefix in prefixes:
                if prefix not in prefix_class_map:
                    prefix_class_map[prefix] = set()
                prefix_class_map[prefix].add(key)

        print(prefix_class_map)

    def test_validate_dataframe_impl(self):
        """Test validation method from DataFrame implementation"""
        test_nodes = os.path.join("./data", "testdata_robokop-kg_nodes.tsv")
        nodes_df = pl.scan_csv(test_nodes, separator="\t", has_header=True, ignore_errors=True).limit(10).collect()
        test_edges = os.path.join("./data", "testdata_robokop-kg_edges.tsv")
        edges_df = pl.scan_csv(test_edges, separator="\t", has_header=True, ignore_errors=True).limit(10).collect()
        validator = ValidatorPolarsDataFrameImpl(nodes=nodes_df, edges=edges_df)

        assert validator.validate() == 1


