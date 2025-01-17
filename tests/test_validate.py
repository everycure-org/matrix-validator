"""Test Validation."""

import unittest

from matrix_validator.validator import validate_kg


class TestValidate(unittest.TestCase):
    """Test validate."""

    def test_version_type(self):
        """Test validation method."""
        validate_kg(nodes=None, edges=None, output_format="txt", report_file=None)
