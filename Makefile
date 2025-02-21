RUN=poetry run
TIMECMD= #/usr/bin/time -l
VERBOSE=-vvv

install:
	poetry install

prepare_tests:
	mkdir -p tmp

test_small_%: prepare_tests
	$(RUN) $(TIMECMD) matrix-validator $(VERBOSE) validate \
		--report-dir tmp/ \
		--validator $* \
		--edges tests/data/testdata_robokop-kg_edges.tsv \
		--nodes tests/data/testdata_robokop-kg_nodes.tsv

run_small_tests:
	$(MAKE) test_small_pandera
	$(MAKE) test_small_python
	$(MAKE) test_small_polars

test_large:
	mkdir -p tmp
	$(RUN) /usr/bin/time -l matrix-validate-kg -vvv \
		--report tmp/report.txt \
		--edges data/data_01_RAW_KGs_robokop-kg_6fce5de1f1332b19_edges.tsv \
		--nodes data/data_01_RAW_KGs_robokop-kg_6fce5de1f1332b19_nodes.tsv
	#cat tmp/report.txt
