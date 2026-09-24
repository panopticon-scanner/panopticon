## Testing scanner fixtures (optional)
Panopticon includes a local Docker-based fixture suite for validating scanner adapters against
intentionally vulnerable applications.

```bash
# Use existing fixtures image
python3 skill/scripts/run_fixture_tests.py

# Force rebuild (clones latest public fixtures)
python3 skill/scripts/run_fixture_tests.py --rebuild

# Run only one language/test target
python3 skill/scripts/run_fixture_tests.py --test rust
```

This is optional and not part of CI. Rebuild the image periodically to pull updated fixtures.
