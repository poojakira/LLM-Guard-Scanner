# Contributing

## Adding Detection Patterns
1. Add regex patterns to the appropriate category in src/detectors/injection.py
2. Add test cases (both attack and benign) in 	ests/test_detectors.py
3. Run python verify.py to check detection rates

## Design Principles
- Minimize false positives over maximizing detection rate
- Every pattern must have a real-world attack reference
- Benign technical discussions about attacks must NOT trigger detection
