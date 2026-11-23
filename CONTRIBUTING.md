# Contributing

## Setup

```console
python -m venv .venv
.venv\Scripts\activate
python -m pip install -e ".[dev]"
```

`.[svg]` additionally installs the Graphviz binding used by `--format svg`.

## Before you send a change

```console
ruff check src tests scripts
ruff format --check src tests scripts
mypy src
python -m pytest -q
```

All four must pass. They are the same checks CI runs on Linux and Windows.

If you touched a code path that compiles Solidity, also run a real scan:

```console
python -m contractmap scan tests/fixtures/foundry
python -m contractmap scan tests/fixtures/project --allow-build
```

and confirm the contract and function counts in the summary match what you expect.
`python scripts/verify_ci_steps.py` replays every command CI runs, including the
access-grading assertions, so a change to the CLI surface fails there first.

## Where CI lives

`.github/workflows/ci.yml` runs lint, types, tests and real CLI scans on Linux and
Windows with Python 3.12 and 3.13, compiles the source fixture with a pinned
`solc`, and builds the wheel.

## How the code is organised

The pipeline is one direction: input becomes facts, facts become models, models
become a graph, and the graph is exported.

- `sources/` produces `ContractFacts`. `analyze.py` and `functions.py` read the
  Solidity AST. There is no regex over source text; if you need new information,
  read it from the AST.
- `scanner/local.py` and `scanner/remote.py` turn facts into `ContractModel` and
  `FunctionModel`, and add edges through `graph/assemble.py`.
- `graph/identity.py` owns every identifier. Any new id must be a pure function of
  stable inputs (address, chain id, source name, name, signature), never of array
  position or iteration order, or `diff` starts reporting spurious changes.
- `exporters/` only reads models. An exporter must not compute analysis.

## Rules that are easy to break

**Never turn a missing fact into a claim.** If source is unavailable, the access
assessment is `unresolved`. Do not default to `none_identified`; those mean
different things and the second one is an assertion.

**Network failures degrade, they do not abort.** A scan that cannot reach Sourcify
still completes with a warning and bytecode-level entry points.

**Compilation stays behind `--allow-build`.** Anything that executes a binary is
gated. Do not add a convenience path that skips the flag.

**Every request is pinned.** RPC reads go through the resolved block from
`ScanContext.pinned()`.

**Respect the budgets.** `max_nodes`, `max_requests` and `concurrency` exist so a
scan of a large proxy system terminates. When a budget is hit, warn with
`partial=True` so the exit code is 4; do not silently truncate.

## Tests

Tests live in `tests/unit/` and run offline. Build a fake chain rather than
pointing at a network: `tests/unit/test_proxies.py` shows the pattern, and
`tests/fixtures/` has a prebuilt Foundry project and a source-only project.

When a test needs a real compiler, guard it:

```python
@pytest.mark.skipif(find_solc() is None, reason="needs a solc binary")
```

Add a fixture under `tests/fixtures/` for anything structural, and assert on the
model, not on exact console text. Formatting drifts; identifiers should not.

## Commits and pull requests

Keep a commit to one idea. In the description, say what was wrong and how you
verified the fix. If output changes, paste the before and after of `contractmap
diff` between the two runs.

## Reporting bugs

Include the version, the exact command, the target (a public address or a minimal
reproduction contract), and the output. Add `CONTRACTMAP_DEBUG=1` for a traceback.
Redact your RPC URL; ContractMap already masks it, but your shell history does not.
