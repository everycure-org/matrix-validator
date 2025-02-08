"""KG Data Model."""

from typing import Optional

import pandera.polars as pa
from pandera.typing import Series


class NodeSchema(pa.DataFrameModel):
    """Schema for nodes TSV file."""

    id: Series[str]
    category: Series[str]


class EdgeSchema(pa.DataFrameModel):
    """Schema for edges TSV file."""

    subject: Series[str]
    predicate: Series[str]
    object: Series[str]
    primary_knowledge_source: Series[str]
    aggregator_knowledge_source: Optional[Series[str]] = pa.Field(nullable=True)
    knowledge_level: Series[str]
    agent_type: Series[str]
