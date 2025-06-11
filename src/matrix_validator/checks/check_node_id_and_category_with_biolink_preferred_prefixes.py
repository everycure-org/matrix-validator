"""Polars-based validator check."""


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
        violations.add(f"The prefixes {value} are not within the Biolink preferred category mapping of '{key}'")

    return violations
