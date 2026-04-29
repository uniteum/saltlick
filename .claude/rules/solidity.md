---
paths:
  - "**/*.sol"
  - "foundry.toml"
  - "remappings.txt"
---

# Solidity Development Rules

## Code Style

- NatSpec: always use `/** */` multi-line block notation, never `///`
- Include `@notice` for public descriptions, `@param` and `@return` as needed
- Function visibility order: external → public → internal → private
- Imports: one per line, sorted alphabetically
- Max line length: 120 characters
- Indentation: 4 spaces
- Run `forge fmt` before committing
- Multi-line function declarations:
  ```solidity
  // CORRECT
  function longFunctionName(uint256 param1, uint256 param2)
      public
      returns (uint256 result1, uint256 result2)
  {
      // body
  }
  ```

## Compiler & EVM

- Solidity 0.8.30+ required (EIP-1153 transient storage support)
- EVM version: Cancun
- Compiler: optimizer enabled, 200 runs, via_ir = true
- CREATE2 factory: always_use_create_2_factory = true
- foundry.toml is authoritative for all configuration

## Security

- Reentrancy protection: EIP-1153 transient storage via OpenZeppelin ReentrancyGuardTransient
- Token interactions: always use SafeERC20
- Factory deployments: CREATE2 deterministic deployment
- Minimal proxies: EIP-1167 via OpenZeppelin Clones

## Code Quality

**All generated code MUST be lint-free.**

Pre-commit checklist:
1. Run `forge fmt` on all modified `.sol` files
2. Verify compilation: `forge build`
3. Run affected tests: `forge test`
4. Check for warnings in compiler output

When writing code, mentally verify it follows forge fmt rules. If unsure, write cleanly and expect forge fmt may auto-format.

## Testing

- Default to smoke tests: target specific tests with `--match-test` or `--match-contract` for fast feedback
- Only run full suite for core protocol changes or before commits
- Invariant test profiles: quick (64 runs), default (256 runs), ci (512 runs), deep (1024 runs)
- Do not write full test suites unprompted — write the specific test requested

## Workflow

- Build: `forge build`
- Test: `forge test`
- Format: `forge fmt`
- Gas report: `forge test --gas-report`

## Forge Command Safety

**Denied** (permanent, irreversible consequences):
- `forge script` — executes Solidity that can deploy contracts and send transactions on live networks; `--broadcast` sends to mainnet
- `forge create` — deploys contracts directly using the user's private key; costs real gas and is permanent
- `forge verify-contract` — publishes source code to Etherscan permanently; uses the user's `ETHERSCAN_API_KEY`

**Allowed** (no permanent side effects):
- `forge build` — compiles to local `out/`, overwritten on next build
- `forge test` — runs in a local EVM fork, no state changes
- `forge fmt` — reformats files locally, reversible via git
- `forge inspect` — reads compiled artifact metadata, no writes
- `forge coverage` — runs tests with coverage tracking, no writes beyond reports

## OpenZeppelin Ports — Do Not Review

These uniteum repos are minimal ports of OpenZeppelin contracts.
Do not flag style violations or suggest changes to their code.

- uniteum/clones — proxy/Clones.sol
- uniteum/erc20 — token/ERC20/ERC20.sol
- uniteum/ierc20 — token/ERC20/IERC20.sol, IERC20Metadata.sol
- uniteum/math — utils/math/Math.sol, SafeCast.sol, SignedMath.sol
- uniteum/panic — utils/Panic.sol
- uniteum/reentrancy — utils/ReentrancyGuardTransient.sol
- uniteum/strings — utils/Strings.sol

## Troubleshooting

- If format-on-save stops working, see
  `crucible/.claude/troubleshooting/forge-fmt-on-save.md`.

## Common Mistakes to Avoid

- Do not use `///` for NatSpec — always `/** */`
- Do not run the full test suite when a targeted smoke test suffices
- Do not add unnecessary error handling or validation beyond what the protocol requires
- Do not refactor or "improve" surrounding code when fixing a specific issue
- Do not delete or overwrite files without explicit confirmation
- Add blank line before function if missing
- Remove trailing whitespace
- Ensure consistent spacing around operators
