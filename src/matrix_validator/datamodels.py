"""Pandera schema classes for Matrix Project."""

from typing import Optional

import pandera.polars as pa
from pandera.typing import Series


class MatrixNodeSchema(pa.DataFrameModel):
    """Schema for matrixnode TSV file."""

    id: Series[str]

    name: Optional[Series[str]] = pa.Field(nullable=True)

    category: Series[str]

    description: Optional[Series[str]] = pa.Field(nullable=True)

    equivalent_identifiers: Optional[Series[str]] = pa.Field(nullable=True)

    all_categories: Optional[Series[str]] = pa.Field(nullable=True)

    publications: Optional[Series[str]] = pa.Field(nullable=True)

    labels: Optional[Series[str]] = pa.Field(nullable=True)

    international_resource_identifier: Optional[Series[str]] = pa.Field(nullable=True)

    upstream_data_source: Series[str]


class MatrixEdgeSchema(pa.DataFrameModel):
    """Schema for matrixedge TSV file."""

    subject: Series[str]

    predicate: Series[str]

    object: Series[str]

    knowledge_level: Optional[Series[str]] = pa.Field(nullable=True)

    primary_knowledge_source: Optional[Series[str]] = pa.Field(nullable=True)

    aggregator_knowledge_source: Optional[Series[str]] = pa.Field(nullable=True)

    publications: Optional[Series[str]] = pa.Field(nullable=True)

    subject_aspect_qualifier: Optional[Series[str]] = pa.Field(nullable=True)

    subject_direction_qualifier: Optional[Series[str]] = pa.Field(nullable=True)

    object_aspect_qualifier: Optional[Series[str]] = pa.Field(nullable=True)

    object_direction_qualifier: Optional[Series[str]] = pa.Field(nullable=True)

    upstream_data_source: Series[str]


class MatrixEdgeCollectionSchema(pa.DataFrameModel):
    """Schema for matrixedgecollection TSV file."""

    entries: Optional[Series[str]] = pa.Field(nullable=True)
