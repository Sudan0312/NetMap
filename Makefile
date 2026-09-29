# NetMap - no build step for the core; these targets cover the workflow.
PYTHON ?= python3
NETMAP = $(PYTHON) -m netmap
OUT ?= out

.PHONY: help lab scan analyze report serve ci test lint data snapshot-clean rules docs

help:
	@printf "%%s\\n" \
	  "make lab            run the synthetic network and write every report format" \
	  "make scan TARGETS=10.0.0.0/24 CONFIRM=1   live discovery (needs authorization)" \
	  "make analyze          re-run topology + risk on $(OUT)/lab-snapshot.json" \
	  "make report           re-render reports from the saved snapshot" \
	  "make serve            dashboard on http://127.0.0.1:8080 (lab snapshot)" \
	  "make ci               fail if new/at-risk findings (exit 1)" \
	  "make test / lint      pytest / ruff" \
	  "make data             regenerate netmap/refs/*.json catalogues"

lab:
	$(NETMAP) lab --size medium -o $(OUT) --formats md,html,csv,json,sarif,cef,dot --snapshot-out $(OUT)/lab-snapshot.json

scan:
	$(NETMAP) discover $(TARGETS) -o $(OUT) --formats md,html,csv,json,sarif --snapshot-out $(OUT)/live-snapshot.json $(if $(CONFIRM),--confirm-authorized,--dry-run)

analyze:
	$(NETMAP) analyze --from $(OUT)/lab-snapshot.json -o $(OUT) --formats md,html --save $(OUT)/lab-snapshot.json

report:
	$(NETMAP) report --from $(OUT)/lab-snapshot.json -o $(OUT) --formats md,html,csv,sarif,cef,dot

serve:
	$(NETMAP) serve --snapshot $(OUT)/lab-snapshot.json --port 8080

ci:
	$(NETMAP) ci --from $(OUT)/lab-snapshot.json -o $(OUT) --formats sarif,txt --fail-on high

rules:
	$(NETMAP) rules list
	$(NETMAP) rules validate

test:
	$(PYTHON) -m pytest -q

lint:
	$(PYTHON) -m ruff check netmap tests tools || true
	$(PYTHON) -c "import compileall,sys; sys.exit(0 if compileall.compile_dir('netmap', quiet=2) else 1)"

data:
	$(PYTHON) tools/sync_data.py

snapshot-clean:
	rm -rf $(OUT)
