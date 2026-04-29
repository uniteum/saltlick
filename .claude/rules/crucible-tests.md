---
paths:
  - "test/**/*.sol"
---

# Test Architecture Rules

## Test Infrastructure Pattern

All crucible-derived projects share a layered test architecture:

### Layers

1. **Base test** (`Base.t.sol`) — extends `forge-std/Test.sol`, provides shared constants and `setUp()`
2. **User contract** (`User.sol`) — wraps token operations with logging; extends both `Test` and `Random`
3. **Domain user** (e.g. `LiquidUser.sol`) — extends `User` with protocol-specific wrappers
4. **Test contracts** (`*.t.sol`) — extend the base test, use domain user instances

### Key Conventions

- **Never use `vm.prank`** — all user actions go through User contract instances
  - User contracts are real contracts with addresses and balances
  - This mirrors production where EOAs call contracts, not `vm.prank` spoofing
  - Each user has its own state (tokens, name, balances)

- **User wrappers log automatically** — use modifiers like `logging()` or `waterlog()` for tracing
  - Wrappers call the view/quote function first, then the state-changing function
  - This validates that quotes match actual results

- **Helpers belong in helper contracts**, not in test files
  - `TestToken.sol`, `Random.sol`, `Namer.sol` — reusable test utilities
  - Helper contracts do NOT end in `.t.sol` and are NOT test contracts

### File Naming

- `*.t.sol` — test contracts (Foundry discovers and runs these)
- `*.sol` (no `.t.`) — helper contracts, user contracts, test utilities
- Both live in `test/` but serve different roles

### Test Style

- Use descriptive test names: `test_HeatCool`, `test_FixedHeatCool`
- Use project constants for amounts (e.g. `SUPPLY`, `GIFT`, `DOLLIP`)
- Assert with descriptive messages: `assertEq(u, s, "alex liquid != solid")`
- Prefer `assert` for invariant checks, `assertEq`/`assertGt` etc. for specific values
