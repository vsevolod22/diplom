# Holder mount diagnostic result — 2026-10-15

## Status and evidence attribution

**Parent reports ONE approved exact-ID diagnostic completed PASS. That invocation's authority is SPENT. STOP/HOLD remains; no repeat or follow-up operation is authorized by this record.** This author did not execute the diagnostic or perform a fresh runtime query.

The approved source/literal boundary is recorded in [holder-mounts-diagnostic-review-20261015.md](holder-mounts-diagnostic-review-20261015.md):

| Source under `server/deploy/trust/` | Approved SHA-256 |
| --- | --- |
| `diagnose_holder_mounts.py` | `8166310172c1ff6c02b833d1cb135f38de7fb0e0b126d0a4c2233286553fbb71` |
| `test_diagnose_holder_mounts.py` | `09b32e69e1425be859802516bbf0375d263ea5b46b3cd00dd4120b5473f98aae` |

These are the public review bindings, not a new hash measurement or new execution approval. The operation was limited to one bounded projected inspect of these exact resources:

- Holder: `d9433f7ed0fc504a3521574668f15b7b3a0e8d283d61b9aa33d1e97187708a4f`.
- Original API: `5cbe0936a5f09d663a77960749e687fbd41fbef52c8990b063362b9363d3e9ec`.
- Required image for both: `sha256:487c3909d3eeee08d60840a81c1adeb61c292aee0a31df17b2a8cf92f6dbb58c`.

The parent reports that both passed the required identity/image/state predicates: API EXITED, holder CREATED, both non-running, not paused/restarting/OOM/dead. This is a bounded observation at that diagnostic, not continuous supervision, ownership proof or full qualification. No other container's state was refreshed by this operation.

## Reported closed receipt fields

**Receipt transcription limit:** the parent supplied the following result fields as a summary, not the complete literal stdout JSON. The JSON below is an exact-value projection of those supplied closed fields, **not a byte-for-byte or complete receipt**. Unreported option summaries and other nested fields are deliberately not reconstructed. This document must not be used as a full raw-receipt hash/serialization oracle.

```json
{
  "code": "MOUNTS_CLASSIFIED_NOT_QUALIFIED",
  "ok": true,
  "Env": "NOT_OBSERVED",
  "fullQualification": "NOT_CLAIMED",
  "volumeBaseline": "COMPLETE",
  "declared": {
    "shape": {
      "kind": "ARRAY",
      "cardinality": "THREE",
      "duplicateTargets": false,
      "unknownTargets": 0,
      "tmpfsTargets": 0
    },
    "slots": {
      "AUTH": {"source": "EXACT", "typeMatch": true, "readOnly": "OMITTED"},
      "DATA": {"source": "EXACT", "typeMatch": true, "readOnly": "OMITTED"},
      "HELPER": {"source": "HOST_MNT_PREFIX", "readOnly": "TRUE"}
    }
  },
  "materialized": {
    "shape": {
      "kind": "ARRAY",
      "cardinality": "THREE",
      "duplicateTargets": false,
      "unknownTargets": 0,
      "tmpfsTargets": 0
    },
    "slots": {
      "AUTH": {"source": "EXACT", "typeMatch": true, "nameMatch": true, "rw": "TRUE"},
      "DATA": {"source": "EXACT", "typeMatch": true, "nameMatch": true, "rw": "TRUE"},
      "HELPER": {"source": "HOST_MNT_PREFIX", "rw": "FALSE"}
    }
  },
  "helperSourceAcrossViews": "MATCH"
}
```

The parent also reports three mounts in each view with no duplicates or extras. Declared AUTH/DATA `ReadOnly` omission and actual AUTH/DATA `RW:true` are distinct observations; no boolean value is silently substituted in this evidence. The helper declaration was read-only and its actual mount was not writable. No actual source paths, label values, private configuration, stderr or container contents are recorded here.

## Narrow interpretation

1. **Observed helper source discrepancy, no longer merely a hypothesis.** For both declaration and actual helper mount, `HOST_MNT_PREFIX` means the returned source was exactly the string `/host_mnt` concatenated with the diagnostic's expected literal helper source. `helperSourceAcrossViews:MATCH` means those two returned sources matched one another. It does not establish host filesystem equivalence, a universal Docker Desktop alias contract, or permission to accept arbitrary path rewriting.
2. **The previously reported two false discovery flags are consistent with this measured discrepancy.** Frozen discovery requires the helper source to equal the unprefixed literal in both views. The observed prefixed source fails those exact literal comparisons even though the two views match each other and the helper is read-only. AUTH/DATA source/name/type/RW observations do not demonstrate a corresponding volume mismatch.
3. **Declaration classification is not the controller's mount qualifier.** Frozen `Controller.qualify_holder()` checks actual mount tuples against the volume mountpoint baseline and literal helper source; it does not use discovery's additional HostConfig-declaration allowlist. The observed helper source would fail that strict actual-source comparison if reached. This does **not** identify the original production exception's sole cause: the controller also has earlier checks, including Env equality, which this diagnostic deliberately did not observe.
4. **Network matching is independent.** The earlier discovery's network-group result neither proves nor substitutes for mount tuple equality. This mount diagnostic made no new network query.
5. **Classification PASS is not mount acceptance or recovery authority.** The diagnostic succeeds when it safely classifies discrepancies. `NOT_CLAIMED` and `NOT_OBSERVED` remain operative; this result does not adopt or fully qualify the holder, authorize its startup/removal, permit relaxing guards, or authorize use of its mounted state.

## Explicit non-claims and retained HOLD

- No private Env, keys, DB, history, logs, recovery files or private-directory contents were read by this result-document author. No execution was performed in this documentation step.
- No real store version, integrity, preservation comparison, durable PRE/export/plan, SQL migration outcome, history readiness, serving readiness, provider operation or OpenRouter activation is established by mount metadata.
- No original production failure is reclassified as a proven single-cause incident, and no assertion is made that an unobserved operation did or did not change a DB.
- Existing HOLD/lock/backups and retained resources remain untouched. No adoption, restart, cleanup, compensating mutation, restoration, original-worker schema probe or spent-command retry is authorized.

## Separate controller work

The coordinator assigns the controller agent ownership of `recreate_openrouter_key.py` and its paired test for a narrowly bound handling of the **exact observed helper-source spelling** and stopped reconciliation. This document changes neither file and does not approve that implementation or any recovery invocation. Source/literal/security review and any required fresh operation authorization remain separate gates; no generalized alias normalization is inferred.

This new result note supplements [hold-handoff-20261015.md](hold-handoff-20261015.md). It does not edit or retroactively change the prior diagnostic review or any spent authority.
