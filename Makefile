install:
	poetry install

test:
	mkdir -p tmp
	poetry run matrix-validate-kg -vvv \
		--report tmp/report.txt \
		--edges tests/data/testdata_robokop-kg_edges.tsv \
		--nodes tests/data/testdata_robokop-kg_nodes.tsv
	cat tmp/report.txt

test_nodes:
	mkdir -p tmp
	poetry run matrix-validate-kg-nodes -vvv -o tmp -i tests/data/testdata_robokop-kg_nodes.tsv

test_edges:
	mkdir -p tmp
	poetry run matrix-validate-kg-edges -vvv -o tmp -i tests/data/testdata_robokop-kg_edges.tsv
