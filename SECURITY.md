# Security policy

## Reporting a vulnerability

Email security@swarmsec.app. Include the affected version (`contractmap version`),
a minimal reproduction, and what an attacker gains. Do not open a public issue
first; we will agree on a disclosure date with you.

Expect an acknowledgement within three working days. Advisories are published as
GitHub security advisories once a fix ships.

## Scope

ContractMap is a static and read-only analysis tool. It issues `eth_*` reads
against an endpoint you configure, fetches verified source from Sourcify or
Etherscan, and writes files you ask for.

These are in scope:

- **Untrusted build artifacts.** A crafted Foundry or Hardhat artifact must not be
  able to read arbitrary files, escape the output path, or execute code.
- **Untrusted API responses.** Sourcify and Etherscan payloads are validated before
  they reach the model. A response that triggers a crash, unbounded memory use, or
  injected markup in HTML output is a bug.
- **Credential handling.** An RPC URL or API key that appears in terminal output,
  JSON, HTML, warnings, or error messages is a bug.
- **Compiler invocation.** `--allow-build` gates execution; that gate must not be
  bypassable by anything inside a scanned project.

These are out of scope:

- Findings about the contracts you scan. ContractMap reports surface; it does not
  audit your Solidity.
- A malicious JSON-RPC provider returning wrong data. The block is pinned and its
  hash recorded, but the provider is trusted for the values it returns.
- Denial of service from the size of the input you chose to scan, beyond the
  documented limits.

## Operating notes

Address scans are read-only: no `eth_sendTransaction`, no signing, no private keys.
Networking is limited to the RPC endpoint you pass and the verified-source providers
you enable.

`.env` is git-ignored and `.env.example` contains no real values. If you commit a
key by mistake, rotate it; the key is in your git history.

## Supported versions

The latest minor release receives fixes. Older releases are not patched.
