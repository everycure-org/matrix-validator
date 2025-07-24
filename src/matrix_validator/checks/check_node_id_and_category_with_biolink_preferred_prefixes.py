"""Polars-based validator check."""
import json


def validate(class_prefix_map, df):
    """Validate node.id and category align with biolink preferred prefix mappings."""
    results = {}

    for row in df.rows(named=True):
        prefix = row["id"].split(":")[0]
        row_category = row["category"]
        if "|" in row_category:
            cat = row_category.split("|")[0]
        else:
            cat = row_category

        if cat not in class_prefix_map.keys():
            continue

        if prefix not in class_prefix_map[cat]:
            if cat not in results:
                results[cat] = set()
            results[cat].add(prefix)

    violations = set()

    for key, value in results.items():
        value_str = ",".join(value)
        violation_str = f"The prefixes '{value_str}' are not within the Biolink preferred category mapping of '{key}'"
        violations.add(violation_str)

    violation_summary = {
        "check": "node_id_and_category_with_biolink_preferred_prefixes",
        "violations": violations
    }

    return json.dumps(violation_summary, indent=2, default=serialize_sets)


def serialize_sets(obj):
    if isinstance(obj, set):
        return list(obj)

    return obj

