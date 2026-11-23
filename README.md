# ContractMap

ContractMap shows you the attack surface of a Solidity project or a deployed
contract: every function anyone can call, what guards it, what it calls, and the
proxies and admins behind it.

It reads only. It never signs, sends, or changes anything on chain.

## Install

ContractMap is not on PyPI yet. Install it from a checkout (Python 3.12+):

```console
git clone https://github.com/swarmsec/contractmap.git
cd contractmap
python -m pip install -e .
```

## Quick start

Map the Foundry or Hardhat project in the current directory:

```console
contractmap scan --allow-build
```

Write an interactive map you can open in a browser:

```console
contractmap scan --allow-build -o map.html
```

Look at a deployed contract. `--rpc` takes any Ethereum JSON-RPC URL (Alchemy,
Infura, your own node):

```console
contractmap scan 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 --rpc $RPC_URL
```

`--allow-build` lets ContractMap run `forge` or `solc` to compile your code. It
asks because compiling runs a program from your PATH. Without it, ContractMap
only reads build output that already exists.

## What you get

For every contract you can deploy, ContractMap lists each function someone can
call, including the ones it inherits from OpenZeppelin, Solmate or your own
bases. For each one it says who may call it and which state it changes. This is
`contractmap scan -o report.md` on a small fixture in this repository:

| function | access | who can call | writes | declared in |
| --- | --- | --- | --- | --- |
| `Helper.claim(address)` | no guard found | anyone | owner | - |
| `Helper.sweep()` | restricted | owner | - | - |
| `Safe.upgradeTo(address)` | restricted | owner | implementation | Upgradeable |
| `Unsafe.upgradeTo(address)` | no guard found | anyone | implementation | Upgradeable |

`Safe` and `Unsafe` inherit the same `upgradeTo`. `Safe` overrides the
`_authorizeUpgrade` hook with `onlyOwner`; `Unsafe` overrides it with an empty
body. ContractMap follows the internal call into each contract's own hook, so it
gets both right. It does the same for helpers like `_onlyOwner()`.

It then points at what deserves a look first:

```text
Observations
 contract  finding                                                                resolution
 Helper    Entry point with no guard reaches call to an address the caller picks  inferred
           run(address,bytes)
 Unsafe    Anyone can change implementation                                       inferred
           upgradeTo(address)
 Helper    Anyone can change owner                                                inferred
           claim(address)
```

Findings say where to look, not that something is broken. The full list is in
[docs/USAGE.md](docs/USAGE.md#observations).

Each entry point gets one of four access grades:

| Terminal shows | In JSON | Meaning |
| --- | --- | --- |
| `restricted` | `confirmed` | A modifier or `require` in the source checks the caller. |
| `likely restricted` | `inferred` | A guard exists, but who passes it could not be worked out. |
| `no guard found` | `none_identified` | The source was read and nothing checks the caller. Look at these first. |
| `unresolved` | `unresolved` | There was no source to read. This does not mean unprotected. |

A `restricted` grade means a check exists, not that the check is correct.

## Common tasks

Pick the output format with the file name. `.html`, `.md`, `.json`, `.dot` and
`.svg` are recognised; `--format` overrides it.

```console
contractmap scan ./my-project --allow-build -o map.html     # register, map and evidence, offline
contractmap scan ./my-project --allow-build -o report.md    # tables for a PR, issue or audit note
contractmap scan ./my-project --allow-build -o before.json  # full data, for diff
```

Fail a CI job when the attack surface changes, and post what changed on the PR:

```console
contractmap scan --allow-build -o after.json -q
contractmap diff before.json after.json -o changes.md -q
gh pr comment --body-file changes.md
contractmap diff before.json after.json --exit-code -q
```

`diff --exit-code` exits 1 when a function, guard, role, proxy or call changed,
and 0 when nothing did. Keep `before.json` in the repository, or produce it by
scanning the base branch in the same job.

Scan a deployed proxy and also read its verified source, so guards can be graded:

```console
contractmap scan 0x... --rpc $RPC_URL --allow-build
```

To stop typing `--rpc`, copy `.env.example` to `.env` in the directory you run
from and fill in `CONTRACTMAP_RPC_URL=`.

Include library, test and script contracts, which are hidden by default:

```console
contractmap scan --allow-build --all
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Done. |
| 1 | `diff --exit-code` found changes. |
| 2 | Bad input: wrong path, bad address, missing `--allow-build`, not a JSON analysis. |
| 3 | Something failed: RPC, compiler, forge. |
| 4 | Partial result: a budget ran out. Raise `--max-nodes` or `--max-requests`. |

## When something looks wrong

- **Everything is `unresolved` on a local project.** Your build output has no
  AST (a plain `forge build` leaves it out). Add `--allow-build` and ContractMap
  rebuilds with `forge build --ast` in a temporary directory. Your `out/` and
  `cache/` are not touched.
- **Everything is `unresolved` on an address.** The contract is not verified, or
  you left out `--allow-build`. Without source, nobody can tell who may call a
  function.
- **`no Solidity compiler found`.** Install Foundry (`foundryup`) or solc, or
  pass `--solc /path/to/solc`.
- **Contracts you expected are missing.** Files under `lib/`, `node_modules/`,
  `test/` and `script/`, and `*.t.sol` / `*.s.sol`, are hidden. Add `--all`.

Run with `--verbose` to see every warning.

## More

- [docs/USAGE.md](docs/USAGE.md): every command, option, environment variable
  and output format.
- [examples/](examples/): a real analysis of the test fixture, terminal and JSON.
- [CONTRIBUTING.md](CONTRIBUTING.md): running the tests and checks.

## License

MIT. See [LICENSE](LICENSE).
