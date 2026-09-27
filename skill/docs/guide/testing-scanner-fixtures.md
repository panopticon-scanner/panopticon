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

Both containers launch under the tool runner's envelope: `--cap-drop=ALL`, no-new-privileges, and
6g/4-CPU/1024-pid ceilings. `PANOPTICON_TOOL_MEMORY`, `_CPUS`, `_PIDS` retune one; empty drops it.

This is optional and not part of CI. Rebuild the image periodically to pull updated fixtures.
