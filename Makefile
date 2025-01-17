install:
	poetry install

test:
	mkdir -p tmp
	poetry run matrix-validate-kg -vvv \
		--report tmp/report.txt \
		--edges tests/data/testdata_robokop-kg_edges.tsv \
		--nodes tests/data/testdata_robokop-kg_nodes.tsv
	cat tmp/report.txt