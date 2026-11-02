# Pruned Ledger Write-up

## Flag

`hiCTF{pruned_storage_calldata_never_forgets}`

## Investigation

The challenge archive contains the Solidity contracts and a complete transaction chain. The target case identifier `0xca5ef11e` is a Relay `bytes4` case tag. Replaying the archived transactions and filtering `CaseActivity(bytes4,address,uint256)` logs for that tag shows the settlement moving through the relays and ending at Ledger `0x68fb8760b1353f7349c431442d6e97ab61685ee7` (transaction 268).

The Ledger's `caseReference()` getter returns the bytes32 value whose ASCII text is `pruned_storage`. Its current `record()` is zero and `pruned()` is true, so the working record was cleared.

## Recovering the record and archive entry

The Ledger contract exposes `configure(bytes32)` and `seal(bytes32)` calls in the transaction archive. The relevant sequence for the target Ledger is:

| Transaction | Call | Value |
|---|---|---|
| 123 | `configure(bytes32)` | `calldata` |
| 136 | `seal(bytes32)` | seals the current record |
| 325 | `prune()` | clears the record |

Thus the record in effect when `seal()` ran was `calldata`.

`seal()` stores the archive entry at:

```text
keccak256(abi.encodePacked("hictf.pruned-ledger.archive", record)) - 1
```

Using the full 32-byte, zero-padded `calldata` record as the input gives the derived storage slot. Reading that slot from the replayed chain yields the bytes32 value `never` (left-aligned ASCII, zero-padded).

## Recovering the note

The Ledger constructor stores a masked note. The contract's `_note(caller)` function unmasks it with:

```text
keccak256(abi.encodePacked(
  keccak256("hictf.pruned-ledger.note"),
  ledgerAddress,
  caller
))
```

Transaction 291 calls `unlock()` from `0x123332679fb9643cb4302de5dc8f7efba76d060f` with the guess `letmein`. The constructor's masked note, combined with that caller-bound mask, decodes to `forgets`.

## Reconstructed case file

| Field | Value |
|---|---|
| Case reference | `pruned_storage` |
| Working record at sealing | `calldata` |
| Archive entry | `never` |
| Note | `forgets` |

Joining the field values in order gives `pruned_storage_calldata_never_forgets`, which produces the flag above.
