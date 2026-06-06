# Rule and Policy Versioning

## Versioning Scheme
Rules and policies follow Semantic Versioning (SemVer):
- **Major**: Breaking changes to rule logic or structure.
- **Minor**: New rules added without breaking existing ones.
- **Patch**: Updates to existing rule patterns or bug fixes.

## Release Process
1. **Staging**: New rules are tested in `tests/test_detectors.py`.
2. **Tagging**: Versions are tagged in Git (e.g., `rules-v1.2.3`).
3. **Distribution**: Policies are loaded from `src/detectors` with version headers.
