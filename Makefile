.PHONY: all demo smoke test

all: demo smoke test

demo:
	@echo "Running demo for LLM-Guard-Scanner..."
	@echo "See README for setup."

smoke:
	@echo "Running smoke tests for LLM-Guard-Scanner..."
	./smoke_test.sh

test:
	@echo "Running unit and integration tests for LLM-Guard-Scanner..."
	python3 -m pytest tests/
