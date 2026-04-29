---
paths:
  - "**/*.sol"
---

# Forge Lint Suppression

Suppress individual lint warnings inline with:

```solidity
// forge-lint: disable-next-line(rule-id)
```

Common rule IDs:

- `mixed-case-function` — function name doesn't use mixedCase
- `mixed-case-variable` — variable name doesn't use mixedCase
- `screaming-snake-case-const` — constant not SCREAMING_SNAKE_CASE
- `screaming-snake-case-immutable` — immutable not SCREAMING_SNAKE_CASE
- `erc20-unchecked-transfer` — unchecked ERC-20 transfer/transferFrom return value
- `unsafe-typecast` — potentially lossy type cast

**Suppression is a last resort.** Fix the warning first — rename the
variable, drop unused return names, restructure the code. Only suppress
when the name is dictated by an external interface or inherited signature
and cannot be changed. If you suppress, add a comment explaining why.
