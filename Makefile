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
	poetry run matrix-validate-kg-nodes -vvv \
		--report tmp/nodes_report.txt \
		--nodes tests/data/testdata_robokop-kg_nodes.tsv
	cat tmp/nodes_report.txt

test_edges:
	mkdir -p tmp
	poetry run matrix-validate-kg-edges -vvv \
		--report tmp/edges_report.txt \
		--edges tests/data/testdata_robokop-kg_edges.tsv
	cat tmp/edges_report.txt