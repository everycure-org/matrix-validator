"""Utilities for the matrix validator."""

import polars as pl
from importlib import resources as il_resources
from biolink_model import schema
import requests
import yaml
from yaml import SafeLoader


def read_tsv_as_strings(file_path):
    """Read a TSV file with all columns interpreted as strings."""
    return pl.scan_csv(
        file_path,
        separator="\t",
        infer_schema_length=0,  # Avoid inferring any schema
    )


def get_biolink_model_prefix_keys():
    """Get biolink model prefix keys."""
    try:
        prefixes = list(requests.get("https://w3id.org/biolink/biolink-model-prefix-map.json", timeout=10).json().keys())
    except Exception:
        bl_model_data = list(yaml.load_all(il_resources.read_text(schema, "biolink_model.yaml"), Loader=SafeLoader))
        prefixes = list(bl_model_data[0]["prefixes"].keys())
    return prefixes


def get_biolink_model_knowledge_level_keys():
    """Get biolink model knowledge_level keys."""
    bl_model_data = list(yaml.load_all(il_resources.read_text(schema, "biolink_model.yaml"), Loader=SafeLoader))
    return list(bl_model_data[0]["enums"]["KnowledgeLevelEnum"]["permissible_values"].keys())


def get_biolink_model_agent_type_keys():
    """Get biolink model agent_type keys."""
    bl_model_data = list(yaml.load_all(il_resources.read_text(schema, "biolink_model.yaml"), Loader=SafeLoader))
    return list(bl_model_data[0]["enums"]["AgentTypeEnum"]["permissible_values"].keys())
