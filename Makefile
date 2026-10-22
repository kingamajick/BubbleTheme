.PHONY: test lint secrets-check

test: lint secrets-check

secrets-check:
	@python3 scripts/check_secrets.py

lint:
	@echo "Checking YAML syntax..."
	@python3 -c "import yaml, glob; [yaml.safe_load(open(f)) for f in glob.glob('themes/*.yaml')]"
	@echo "YAML syntax valid."
