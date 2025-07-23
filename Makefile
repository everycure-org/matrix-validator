RUN=poetry run
TIMECMD= #/usr/bin/time -l
VERBOSE=-vvv

install:
	poetry lock
	poetry install

prepare_tests:
	mkdir -p tmp

test_small_%: prepare_tests
	$(RUN) $(TIMECMD) matrix-validator $(VERBOSE) $*  \
		--report-dir tmp/ \
		--edges tests/data/testdata_robokop-kg_edges.tsv \
		--nodes tests/data/testdata_robokop-kg_nodes.tsv

test_large_%: prepare_tests
	$(RUN) $(TIMECMD) matrix-validator $(VERBOSE) $* \
		--report-dir tmp/ \
		--edges data/data_01_RAW_KGs_robokop-kg_23f46efa87c2bad7_robokop_23f46efa87c2bad7_edges.tsv \
		--nodes data/data_01_RAW_KGs_robokop-kg_23f46efa87c2bad7_robokop_23f46efa87c2bad7_nodes.tsv

run_small_tests:
	$(MAKE) test_small_pandera
	$(MAKE) test_small_python
	$(MAKE) test_small_polars

run_large_tests:
	$(MAKE) test_large_pandera
	$(MAKE) test_large_python
	$(MAKE) test_large_polars
