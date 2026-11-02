# Orphaned Context — investigation notes

## Result

The relay has a stale recovery-descriptor flaw: a descriptor remains usable after its work slot has been recycled to an untrusted note. The recovery preview executes the note's `relay-maint/1` commands against the virtual map. However, the seal returned by this instance is explicitly a development fixture, not a valid challenge flag:

```text
hiCTF{local_dev_fixture_not_a_real_flag_742eb3eea2}
```

I could not recover the real flag. The investigator handout mentioned in the challenge was not available in the workspace, and the audit API does not expose the original `cap-0002` recovery descriptor needed to replay the seeded incident. A newly issued descriptor reproduced the stale-slot behavior but returned only the fixture value.

## Audit findings

The read-only API is available at `/api/relay/status`, `/api/relay/events`, and `/api/incidents`. Its event sequence showed:

1. `cap-0001` opened and committed in slot 0 at epoch 1.
2. `cap-0002` opened in slot 0 at epoch 2, then was interrupted with its recovery descriptor retained.
3. Untrusted `note-0003` was recorded in slot 0 at epoch 3.

That sequence means the retained descriptor refers to an older generation of a slot later occupied by untrusted note data. The console derives the stale-handle warning from this audit trail. The live slot counters did not reconcile with the seeded events, which is why the original descriptor itself could not be obtained from the public event response.

## Reproducing the read with a fresh descriptor

The following operator endpoints accepted the documented operation shapes:

- `POST /api/capture/open` returns a `recovery_descriptor`.
- `POST /api/capture/interrupt` interrupts a capture but retains its descriptor.
- `POST /api/note/store` accepts a `text` field and stores the note as untrusted.
- `POST /api/note/discard` accepts `note_id` and `epoch`, freeing the note's slot.
- `POST /api/recover/preview` accepts `recovery_descriptor` and returns diagnostics.

Using a fresh capture `cap-0005` in slot 1, I interrupted it and stored successive notes in that same slot. After discarding each note, the next note occupied slot 1 at a higher epoch. A preview with the original `cap-0005` descriptor still ran the newer note's commands. For example, storing this note:

```text
#!relay-maint/1
help
ls /
```

and previewing with the old descriptor returned output from the virtual interpreter. Listing the discovered paths (rather than guessing names) led to `/incidents/IR-7731/seal`. Reading that path returned the fixture string above. The preview response reported `trusted: true` even though the stored note's trust was `untrusted`, demonstrating that the recovery path did not bind the descriptor to the current slot epoch before interpreting the note.

## Assessment

The stale descriptor exposes data chosen by a later untrusted note in a recycled slot. This confirms the recovery-path integrity flaw. It does not establish exposure of a real protected seal on this instance: the only seal content returned is explicitly marked as a non-real local fixture. The missing handout/reference transcript and original descriptor prevent validating the seeded `cap-0002` path or obtaining the instance's real `hiCTF{...}` flag.
