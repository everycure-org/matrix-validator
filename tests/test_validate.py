"""Test Validation."""

import unittest

from matrix_validator.validator_schema import ValidatorPanderaImpl


class TestValidate(unittest.TestCase):
    """Test validate."""

    def test_version_type(self):
        """Test validation method."""

        validator = ValidatorPanderaImpl(config="./config.yaml")
        validator.validate(nodes_file_path=None, edges_file_path=None)
