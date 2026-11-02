# Apex Multi-Threaded Settlement Engine — Write-up

## Challenge

The service starts with 100 credits. VIP access costs 10,000 credits, and the Secure Vault Enclave blocks paths containing `flag`. The intended chain uses two concurrency bugs: a race in escrow settlement to inflate the balance, then a time-of-check/time-of-use (TOCTOU) race in document streaming to read `/flag`.

**Flag:** `hiCTF{t0ct0u_mult1thr34d_r4c3_c0nd1t10n_w1n_8d3f_11d6845032}`

## 1. Reverse engineering the balance race

The menu allows up to eight active escrow orders. Each order creates a worker thread. In the worker (`sub_1EF0`), the relevant order is:

1. Check that the shared cash balance is at least the requested amount.
2. Mark the order as processing.
3. Sleep for 100 ms (`usleep(0x61A8)`).
4. Subtract the amount from the shared balance and add it to escrow.

There is no lock around the balance check and later debit. Submit eight transfers of 100 credits quickly, before the workers wake. All eight workers see the original balance of 100 and pass their checks. Their later debits total 800, so the unsigned 64-bit balance wraps around. That wrapped balance exceeds the VIP threshold.

I confirmed this by viewing account status after the transfers: the escrow held 800 credits and the cash balance was near `2^64`. Selecting option 4 then upgraded the account to VIP.

## 2. Reverse engineering the enclave path race

The enclave's streaming worker (`start_routine`) checks whether the slot's target path contains `flag`, then sleeps for 25 ms (`usleep(0x61A8)`), then opens the target path. The worker uses the slot's path buffer directly; it does not copy the path before checking it.

The VIP flag is set in the low 32 bits of `qword_43F0`, while the worker checks its high 32 bits when allowing paths containing `flag`. Thus VIP by itself does not authorize `/flag`.

The delay creates a TOCTOU window:

1. Create a document slot. Its default path is `/tmp/preview.txt`, which passes the substring check.
2. Dispatch streaming for that slot. The worker checks the allowed path and sleeps.
3. Before the worker resumes, edit the same slot's path to `/flag`.
4. The worker opens the edited path and prints the flag.

## 3. Exploit sequence

Connect over TLS with SNI set to the challenge hostname. Then send eight `2` / `100` transfer pairs as quickly as possible:

```text
2
100
2
100
2
100
2
100
2
100
2
100
2
100
2
100
```

After the workers settle, use menu option `4` to upgrade. Enter the enclave with option `5`, create slot `0` with `1`, then stream it with `2` and slot `0`. Immediately choose `3`, slot `0`, and set its path to `/flag`.

The critical timing is that the path edit must land after the streaming worker checks the initial path but before its 25 ms delay ends. Retrying the stream/edit pair is effective if a scheduling race is missed; restore the slot path to `/tmp/preview.txt` before the next attempt.

## Result

The streaming worker printed:

```text
hiCTF{t0ct0u_mult1thr34d_r4c3_c0nd1t10n_w1n_8d3f_11d6845032}
```
