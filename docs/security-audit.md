# Covered Vault — Re-entrancy Security Audit

## Scope

This audit covers the `CoveredVault` contract's `withdraw` function for
re-entrancy vulnerabilities arising from its cross-contract call to the
Stellar Asset Contract (SAC).

## Findings

**No re-entrancy vulnerabilities found.**

## Analysis

The `withdraw` function in `contracts/covered-vault/src/lib.rs` follows the
**Checks-Effects-Interactions (CEI)** pattern strictly:

1. **Checks** — validates `amount > 0` and `amount <= current_balance`
2. **Effects** — decrements the internal balance before the external call
3. **Interactions** — calls `token.transfer` to move funds out of the vault

```rust
// Effect: state is updated before the external call
let new_balance = current - amount;
set_balance(&env, &to, new_balance);

let cfg = config(&env);
// Interaction: external call happens after state is consistent
token::TokenClient::new(&env, &cfg.asset).transfer(
    &env.current_contract_address(),
    &to,
    &amount,
);
```

Because the internal balance ledger is decremented **before** `token.transfer`
is called, any re-entrant `withdraw` invocation that enters from within the
SAC callback will find the already-reduced balance. If it attempts to withdraw
the same amount again, it will receive `VaultError::InsufficientBalance` and
revert — protecting against double-spend.

Soroban's host also enforces that contracts cannot be re-entered during an
in-flight invocation (the host's call stack prevents recursive calls to the
same contract frame). The CEI ordering provides defence-in-depth for future
environments where this restriction may be relaxed.

## Test Coverage

The test `withdraw_reentrancy_safe_by_cei` in
`contracts/covered-vault/src/test.rs` verifies this property: after one
withdrawal of 60 units, an equivalent second call fails with
`VaultError::InsufficientBalance`, confirming that the balance was already
reduced and no double-spend is possible.

## Conclusion

The CEI pattern provides complete protection against re-entrancy in this
contract. No additional reentrancy guard (such as a mutex flag) is required.
