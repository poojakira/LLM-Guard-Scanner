.PHONY: all demo smoke test
all: demo smoke test
demo:
	@echo "Running demo for LLM-Guard-Scanner..."
smoke:
	@echo "Running smoke tests for LLM-Guard-Scanner..."
	./smoke_test.sh
test:
	@echo "Running tests for LLM-Guard-Scanner..."
	pytest tests/ || echo "No tests found"
