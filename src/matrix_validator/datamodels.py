"""KG Data Model."""

from typing import Optional

import pandera.polars as pa


class NodeSchema(pa.DataFrameModel):
    """Schema for nodes TSV file."""

    id: str
    category: str


class EdgeSchema(pa.DataFrameModel):
    """Schema for edges TSV file."""

    subject: str
    predicate: str
    object: str
    primary_knowledge_source: str
    aggregator_knowledge_source: Optional[str]
    knowledge_level: str
    agent_type: str
