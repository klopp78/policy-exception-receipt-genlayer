# PolicyExceptionReceipt for GenLayer

`PolicyExceptionReceipt` is a reusable Intelligent Contract primitive for the exceptional case:
an AI agent needs to take a bounded action outside its ordinary policy.

## What it enforces

1. The contract builds one canonical action object from the policy identifier, action, maximum amount,
   and expiry, then derives the SHA-256 `action_hash` itself. Callers cannot submit a hash for another action.
2. The leader and validators independently render every source, hash every rendered snapshot,
   and independently adjudicate whether the exception is justified.
3. The accepted record contains a durable exception ID, request commitment, source manifest,
   snapshot hashes, consensus decision, and receipt hash.
4. Source independence is enforced at the registrable-domain level: apex, `www`, and sibling subdomains
   map to one identity and cannot satisfy the two-independent-source requirement together.
5. Only the original requester may consume an approved receipt. Consumption is one-time, expires,
   cannot exceed its cap, and re-derives the exact committed action hash before use.

## Contract methods

### `request_exception`

Arguments: `policy_id`, `action`, `max_amount`, Unix `expires_at`, and
`evidence_urls` (2-4 `https://` sources). Returns `exc_<id>`.

### `consume_exception`

Arguments: `exception_id`, exact `action`, and `amount`. Returns a stable consumption hash
only when the receipt was approved, has not expired, belongs to the caller, has not already been
used, and its cap is respected.

## Local check

```powershell
node tests/check-contract.mjs
```

## Why GenLayer is central

The approval is not a local or submitter-provided decision. Consensus validators re-fetch the
evidence, bind the source snapshots, and independently re-derive the decision before a one-use
receipt is accepted into contract state.
