# Examples

Checked-in output from the fixture project, so you can see the shape of a real
analysis without installing anything. Both files come from the same command.

`foundry-terminal.txt` is what `contractmap scan tests/fixtures/foundry` prints:
the summary panel, the contract table, privileged entry points, observations, and
the node counts.

`foundry-analysis.json` is the same analysis with `--format json`. It is the input
`diff` expects. Regenerate both, and re-verify the claims below, with:

```console
python scripts/regenerate_examples.py
```

The JSON carries a `generated_at` timestamp, so re-running changes the file hash
but not its content: `contractmap diff examples/foundry-analysis.json
examples/foundry-analysis.json` still reports `no architectural changes`, because
`diff` compares identities and excludes run metadata.

Two things to notice in the JSON:

- `id` values are derived from the source unit and contract name, not from array
  position. Re-scanning unchanged code produces identical ids, which is what makes
  `diff` report real changes only.
- `functions[].access.restriction` is `confirmed` for `Vault.setFee(uint256)` and
  `Vault.pause()` because `onlyOwner` is defined in `Ownable.sol` and its body was
  read. `Roles.pause()` is only `inferred`: `onlyRole` checks a mapping that cannot
  be resolved statically, so the guard's existence is certain but its role is not.

The terminal summary phrases the same verdicts for humans, so `confirmed` prints as
`restricted` and `inferred` as `likely restricted` in `foundry-terminal.txt`. The
JSON is the authoritative value.

`target.resolved_paths` is empty for artifact scans (the build output names its own
sources) and lists the compiled files for source scans. `scripts/verify_ci_steps.py`
checks the same gradings against a fresh scan, and CI runs it.
