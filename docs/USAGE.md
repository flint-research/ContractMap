# ContractMap reference

Every command and option. For a first run, read the [README](../README.md).

All examples use the fixture projects in `tests/fixtures`, so they work right
after cloning. `contractmap ...` and `python -m contractmap ...` run the same code.

## Commands

| Command | What it does |
| --- | --- |
| `scan [target]` | Map a project, a file, or an address. Target defaults to `.`. |
| `inspect <address>` | Terminal view of one deployed contract (`scan` with `--depth 1`). |
| `diff <before.json> <after.json>` | List what changed between two JSON scans. |
| `schema` | Print the JSON Schema of the scan output (`--diff` for diff output). |
| `version` | Print the version. |

## Scanning a local project

`scan` accepts a project directory, a single `.sol` file, or one artifact file
(Foundry, Hardhat, `solc --combined-json` or `--standard-json` output).

For a directory, ContractMap picks the first route that works:

1. **Build output with ASTs** (`out/`, `artifacts/`, `artifacts/build-info/`).
   Read directly. Nothing is compiled.
2. **Foundry project, `--allow-build`, `forge` on PATH.** ContractMap runs
   `forge build --ast --skip test script` into a temporary directory and reads
   that. Your `out/` and `cache/` stay as they are. This is the route a normal
   Foundry project takes, because a plain `forge build` leaves ASTs out.
3. **Build output without ASTs.** Functions are listed from the ABI and every
   access grade is `unresolved`. A warning says how to fix it.
4. **Only `.sol` files, `--allow-build`.** ContractMap compiles them with `solc`.
   Files under `lib/`, `node_modules/` and build directories are skipped.

```console
contractmap scan tests/fixtures/foundry                  # route 1
contractmap scan tests/fixtures/project --allow-build    # route 4
contractmap scan tests/fixtures/project/src/Vault.sol --allow-build
```

Scanning one `.sol` file compiles its whole directory, so relative imports
resolve. If an import points outside that directory, scan the project root.

Without `--allow-build`, a project with no build output at all stops with exit 2
and says so.

### Which solc

`--solc /path/to/solc` wins. Otherwise ContractMap uses `solc_version` from
`foundry.toml`, then an exact `pragma solidity 0.8.24;`, then the newest solc it
finds on PATH or in Foundry's compiler store (`SVM_HOME` overrides where that is).

### Inherited functions

Each deployable contract lists every public and external function it answers,
including inherited ones. `Vault is AccessControl, UUPSUpgradeable` lists
`grantRole` and `upgradeToAndCall`, with `declared_in` naming the contract that
declares them. When two bases declare the same function, the most derived one
wins, as in Solidity.

Abstract contracts and interfaces stay in the contracts table, but their
functions are left out of the entry-point tables and admin findings, because the
contracts that inherit them already list those functions.

### Hidden contracts

Contracts from `lib/`, `node_modules/`, `test/`, `tests/`, `script/`, npm-style
paths (`@openzeppelin/...`, `hardhat/...`) and files ending in `.t.sol` or
`.s.sol` are left out of the result. A warning gives the count. Their functions
and guards still count: a `Vault` that inherits OpenZeppelin's `Ownable` lists
`transferOwnership` and is `confirmed` by its `onlyOwner`. `--all` keeps the
library contracts as rows of their own.

## Scanning a deployed address

Needs a JSON-RPC endpoint, from `--rpc`, `CONTRACTMAP_RPC_URL` or `ETH_RPC_URL`.

```console
contractmap scan 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 --rpc $RPC_URL
contractmap inspect 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 --rpc $RPC_URL
```

What happens:

- The chain id and head block are read first. Every later read uses that block,
  so the result is one consistent snapshot. `--block N` picks an older block.
  `--chain-id N` stops the scan if the endpoint serves a different chain.
- Proxies are followed up to `--depth` levels (default 2): EIP-1967
  implementation and admin, beacons, EIP-1167 clones, and diamond facets.
- `owner()`, `admin()` and `pendingOwner()` are called. Any address they return
  is shown as a privileged account.
- Verified source is fetched from Sourcify (on by default, no key). With
  `--allow-build` it is compiled, so guards can be graded, inherited functions
  get `declared_in`, and state writes are recorded. Without it, functions come
  from the verified ABI and stay `unresolved`.
- With no verified source, function selectors are read from the bytecode. They
  show up as `unknown_<selector>()` and stay `unresolved`.

Etherscan is off unless you set `ETHERSCAN_API_KEY` (or pass `--etherscan`).

## Options

| Option | Commands | Default | What it does |
| --- | --- | --- | --- |
| `-o, --output PATH` | scan, diff, schema | stdout | Write here. The terminal summary still prints unless `-q`. |
| `-f, --format` | scan, diff | from `-o` | `terminal`, `json`, `html`, `markdown`, `dot`, `svg` (diff: `terminal`, `json`, `markdown`). |
| `--allow-build` | scan, inspect | off | Allow running `forge` or `solc`. |
| `--all` | scan | off | Include library, test and script contracts. |
| `--solc PATH` | scan, inspect | auto | Use this compiler. |
| `--rpc URL` | scan, inspect | env | JSON-RPC endpoint. |
| `--chain-id N` | scan, inspect | none | Fail if the endpoint serves another chain. |
| `--block N` | scan, inspect | head | Read state at this block. |
| `--depth N` | scan, inspect | 2 (inspect: 1) | How many proxy levels to follow. |
| `--max-nodes N` | scan | 400 | Graph size limit. |
| `--max-requests N` | scan, inspect | 300 | RPC request limit. |
| `--concurrency N` | scan | 4 | RPC requests in flight. |
| `--timeout S` | scan, inspect | 20 | Seconds per request. |
| `--no-sourcify` | scan, inspect | off | Do not query Sourcify. |
| `--etherscan` | scan | off | Also query Etherscan (needs `ETHERSCAN_API_KEY`). |
| `--exit-code` | diff | off | Exit 1 when anything changed. |
| `-q, --quiet` | scan, inspect, diff | off | With `-o`, print nothing but errors. |
| `--verbose` | scan, inspect, diff | off | Print every warning, and every diff row. |

## Output formats

The format follows the `-o` file extension: `.json`, `.html`/`.htm`, `.md`,
`.dot`/`.gv`, `.svg`. Any other extension, or no `-o`, gives the terminal summary.

| Format | Use it for |
| --- | --- |
| terminal | Reading the result yourself. |
| json | Everything, with stable ids. The input for `diff` and for other tools. |
| html | One offline file to explore and to hand over. See [The HTML report](#the-html-report). |
| markdown | Contracts; every state-changing entry point with its grade, who can call it, what it writes and where it is declared; observations. |
| dot | Graphviz source for your own rendering. |
| svg | A rendered graph. Needs `pip install -e ".[svg]"` and Graphviz installed. |

```console
contractmap scan tests/fixtures/foundry -o map.html
contractmap scan tests/fixtures/foundry -o report.md
contractmap scan tests/fixtures/foundry -o analysis.json
```

### The HTML report

`-o map.html` writes one file that works offline and makes no network requests.
It is meant both for exploring during a review and for handing to someone who
did not run the scan.

- **Legend.** Every entry point carries one tick mark: Verified (`restricted`),
  Named, not traced (`likely restricted`), Open (`no guard found`) and No source
  (`unresolved`). A red pencil ring marks an exception, a function named in a
  takeover finding. The legend shows counts and filters by tick when clicked.
- **Register.** Exceptions first, then every entry point with who can call it,
  what it writes and where it is declared, then notes and warnings. Columns
  sort; search covers names, roles, state, selectors and modifiers.
- **Map.** Each contract is a parcel listing its functions with their ticks and
  who holds control. Lines show proxy wiring, calls out and control; inheritance
  appears for the selected contract. Scroll to pan, Ctrl + scroll to zoom, Save
  SVG to export it.
- **Evidence panel.** Selecting a row or a map plot shows the grade, the guard,
  the state written, the evidence with source positions, and every finding that
  names the function.
- **References.** Contracts are `C1`, `C2`; functions `C2.07`; exceptions `E1`;
  notes `N1`. Add one to the file's address to open it there: `map.html#C2.07`,
  or `map.html#map:C2.07` for the map. References are numbered per report.
- **Print report** turns the register into one linear document, for a PDF.

### Access grades

| Terminal | JSON `access.restriction` | Meaning |
| --- | --- | --- |
| restricted | `confirmed` | A modifier or inline check in the source tests the caller. |
| likely restricted | `inferred` | A guard exists, but which callers pass it is not known statically. |
| no guard found | `none_identified` | The source was read and nothing checks the caller. |
| unresolved | `unresolved` | No source was available. Not the same as unprotected. |

### What counts as a guard

A function is `confirmed` when its body, one of its modifiers (including modifiers
inherited from a base contract), or an internal function it calls (up to 4 calls
deep) contains one of these:

| Pattern | Example |
| --- | --- |
| A known access-control call | `onlyOwner`, `_checkOwner()`, `onlyRole(X)`, `hasRole(X, msg.sender)` |
| The caller compared with a privileged value | `require(msg.sender == owner)`, `if (msg.sender != admin) revert();` |
| The same, with a getter or a struct field | `msg.sender == owner()`, `msg.sender == ds.contractOwner` |
| The caller read through `_msgSender()`, `address(...)` or a local copy | `require(_msgSender() == governance)`, `address sender = _msgSender(); require(sender == pendingOwner);` |
| A caller-indexed allow list, inside a check | `require(wards[msg.sender] == 1)`, `if (!isAdmin[msg.sender]) revert();` |
| A check call handed the caller | `_checkCaller(msg.sender)`, `_onlyAllowed(msg.sender)` |
| A verdict call handed the caller, inside a check | `require(isAuthorized(msg.sender, msg.sig))` (Solmate `requiresAuth`) |

Internal calls are resolved in the contract being deployed. UUPS
`upgradeToAndCall` is guarded by whatever that contract's own
`_authorizeUpgrade` override checks, so an override with an empty body is
reported as `no guard found`.

`hasRole(role, account)` about some other account is a lookup, not a guard:
OpenZeppelin's `_grantRole` asks it before granting.

The role in `onlyRole(FEE_ROLE)` is read from the call site, so `who can call`
says `fee` rather than a generic `role`.

"Privileged value" means a name containing owner, admin, governor, governance,
timelock, operator, guardian, controller, keeper, manager, multisig, pauser or
minter. An allow list counts only inside `require`, `assert` or an `if`
condition, because `operators[msg.sender] = true` is bookkeeping, not a check.

A modifier whose body has none of these but whose name says it guards something
(`onlyGovernance`) gives `inferred`.

### Observations

| Category | Raised when |
| --- | --- |
| `unguarded_dangerous_operation` | A function with no guard calls `selfdestruct`, `delegatecall`, or `.call` on an address taken from its arguments, directly in its body. `fallback` and `receive` are skipped, because proxies delegate there by design. |
| `unguarded_privileged_write` | A function with no guard writes state whose name says it controls the contract: owner, admin, governance, implementation, authority, guardian, operator, pauser, minter, timelock, controller, keeper, paused. Functions with `initializer` or `reinitializer` are skipped. |
| `administrative_function` | A function named like an admin action (`set`, `withdraw`, `upgrade`, `pause`, `mint`...) has no guard. |
| `authorization_unresolved` | The same, but there was no source to check. |
| `payable_entry_point` | A function accepts ETH. |
| `external_call` | An entry point calls another contract. |
| `delegatecall_usage` | A contract that is not a proxy uses `delegatecall`. |
| `token_interaction`, `oracle_dependency` | An entry point calls token transfer functions or a price oracle. |
| `inheritance_structure` | Several bases share an ancestor, so override order matters. |
| `proxy_upgrade`, `diamond_architecture` | The contract is an upgradeable proxy or a diamond. |
| `unverified_dispatch` | Deployed bytecode has selectors the verified ABI does not explain. |

Terminal and Markdown list findings in the order of this table, so the first
rows are the ones to read first.

### State writes

Each function in the JSON has `writes`: the state variables it assigns,
increments or deletes, directly or through internal and `super` calls. A write
through a storage pointer (diamond storage, ERC-7201 namespaced storage) is
recorded by the field name, such as `_paused`. Writes made inside a library
function, such as OpenZeppelin's `ERC1967Utils`, are not followed.

## Comparing two scans

```console
contractmap scan tests/fixtures/foundry -o before.json -q
# ...change the code, rebuild...
contractmap scan tests/fixtures/foundry -o after.json -q
contractmap diff before.json after.json
contractmap diff before.json after.json --exit-code      # for CI
contractmap diff before.json after.json -o changes.json  # machine-readable
contractmap diff before.json after.json -o changes.md    # a table to post on a PR
```

`diff` reports added, removed and changed contracts, functions, access grades,
roles, proxy wiring, facets, calls and observations. Ids come from names and
signatures, not array positions, so an unchanged contract never shows as removed
and re-added. Two scans of the same code print `no architectural changes`.

`diff` only reads JSON scans. Any other file is exit 2.

Scans use schema version 1.1, which added `declared_in` and `writes` to each
function. A 1.0 scan from an older ContractMap can still be compared: `diff`
prints a note, and inherited functions show up as added.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Done. |
| 1 | `diff --exit-code` found changes. |
| 2 | Bad input: missing target, unsupported file, bad address, missing `--allow-build`, not a JSON scan. |
| 3 | Operational failure: RPC, compiler or `forge build` failed. |
| 4 | Partial result: `--max-nodes` or `--max-requests` ran out. Raise it and run again. |

Warnings that weaken a result without cutting it short, such as Sourcify being
unreachable, still exit 0. The first three print under the summary; `--verbose`
prints all of them.

## Environment variables

ContractMap reads `.env`, then `.env.local`, from the directory you run it in.
Variables already set in your shell win over both files. `KEY=` with no value is
ignored, so an unfilled copy of `.env.example` does no harm.

| Variable | Effect |
| --- | --- |
| `CONTRACTMAP_RPC_URL` | RPC endpoint. `ETH_RPC_URL` also works. |
| `ETHERSCAN_API_KEY` | Turns on Etherscan lookups. |
| `CONTRACTMAP_ETHERSCAN=1` | Turns on Etherscan without a key. |
| `CONTRACTMAP_NO_SOURCIFY=1` | Turns off Sourcify. |
| `SOURCIFY_URL` | A Sourcify mirror or your own instance. |
| `CONTRACTMAP_DEPTH` | Default for `--depth`. |
| `CONTRACTMAP_MAX_NODES` | Default for `--max-nodes`. |
| `CONTRACTMAP_MAX_REQUESTS` | Default for `--max-requests`. |
| `CONTRACTMAP_CONCURRENCY` | Default for `--concurrency`. |
| `CONTRACTMAP_ENV_FILE` | Read this file instead of `.env` and `.env.local`. |
| `CONTRACTMAP_DEBUG=1` | Show a full traceback on errors. |

RPC URLs often carry an API key in the path. ContractMap never prints the path.

## Troubleshooting

**`forge build failed: ...`**: the project does not build on its own. Run
`forge build` yourself and fix that first, usually with `forge install`.

**`Source "X.sol" not found`**: an import points outside the scanned directory,
or uses a remapping plain `solc` does not know. Scan the project root, and for
Foundry projects make sure `forge` is on PATH so route 2 is used.

**`sourcify returned HTTP 429`**: the public Sourcify is rate-limiting you. Set
`SOURCIFY_URL` to another instance, or `CONTRACTMAP_NO_SOURCIFY=1`.

**Boxes print as `?` on Windows**: run `chcp 65001` once in that console.

## Limits

ContractMap maps surface. It does not prove a bug is exploitable, and a
`confirmed` guard means a check exists, not that it is right. Hardhat projects
are read from their build output; ContractMap does not run `npx hardhat compile`
for you.
