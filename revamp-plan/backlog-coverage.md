# Coverage of `consolidated_backlog.md` by `revamp-plan/`

## Method

The authoritative source is `../../wamble-archive/consolidated_backlog.md`,
which contains 79 checkbox items. IDs below are assigned sequentially in source
order. This crosswalk inspects all three files that
were present in `revamp-plan/` before this report was added:

- `roadmap.org`
- `phase-2-thread-local-persistence.org`
- `phase-3-global-actors.org`

“Explicit” means the plan retains a concrete obligation that addresses the
backlog defect, even if it generalizes the implementation. “Partial/general”
means the plan names related machinery or requires a broad inventory that
should encounter the issue, but does not retain the defect's full acceptance
criteria. “Not retained” means that completing the written plan would not
necessarily address the backlog item.

## Summary

| Coverage | Count | Backlog IDs |
|---|---:|---|
| Explicit | 14 | 23, 33, 35–40, 42–45, 62, 65 |
| Partial/general | 23 | 2, 3, 6, 11, 25, 26, 34, 41, 46, 48–52, 56, 57, 59–61, 63, 64, 66, 70 |
| Not retained | 42 | 1, 4, 5, 7–10, 12–22, 24, 27–32, 47, 53–55, 58, 67–69, 71–79 |
| **Total** | **79** | **Every source checkbox exactly once** |

The plan is therefore principally a persistence redesign plus network/runtime
ownership globalization. It is not a replacement for the consolidated product,
protocol-schema, server-correctness, lock-contention, tooling, or product-change
backlog.

## Explicitly captured (14)

| ID | Backlog item | What the plan retains |
|---:|---|---|
| 23 | Read-side policy/capability evaluation creates durable identity/treatment state | QueryService is categorically read-only and may not create, assign, materialize, or otherwise move durable data; every operation is inventoried for hidden writes and tested for read purity (`phase-2-thread-local-persistence.org:202-265`). |
| 33 | No authoritative migration ledger/atomic migration-set authority | Physical schema generations require an authoritative checksummed migration/schema manifest (`phase-2-thread-local-persistence.org:161-165`), and migration authority—not request paths—establishes schema (`phase-2-thread-local-persistence.org:363-367`). This captures the ledger/authority requirement, though exact transaction mechanics remain design work. |
| 35 | Async flush worker uses wrong TLS profile/config/DB context and leaks connection | Phase 2 replaces per-flush cold context with one profile-owned, long-lived writer and owner-thread connections (`phase-2-thread-local-persistence.org:463-471`); Phase 3 inventories ambient QueryService/TLS restoration hazards (`phase-3-global-actors.org:400-409`). |
| 36 | `board_scoring_worker` has no IntentBuffer and silently loses payouts | The worker and lost-payout mechanism are named directly; its registration and outgoing transport must become explicit (`phase-3-global-actors.org:389-398`). |
| 37 | Scratch allocation failure silently changes planner semantics | Plans are lifecycle-equivalent only, unavailable planning prerequisites leave messages pending, scratch is bounded, and allocation/apply failures remain observable (`phase-2-thread-local-persistence.org:285-340,452-461`). This rules out an undeclared capture-order fallback. |
| 38 | Async prefix reconciliation can duplicate committed effects | Prefix-replacement allocation failure is named and requires recovery/visibility, with an explicit regression preserving retry remnants ahead of later work (`phase-3-global-actors.org:411-413,470-474`). |
| 39 | Profile/global mutations falsely claim one-store transaction atomicity | The plan states that separate stores cannot claim one PostgreSQL transaction and require staged lifecycle outcomes (`phase-2-thread-local-persistence.org:388-390`). |
| 40 | Persistence apply reports success without durable witnesses | SQL success alone is explicitly insufficient; affected-row, returned-identity, and version witnesses establish per-message outcomes (`phase-2-thread-local-persistence.org:346-359,383-386`). |
| 42 | “Batching” still incurs one blocking round trip per operation | Prerequisite reads are batched, compatible writes are set-based, independent operations are pipelined, and round trips follow semantic barriers rather than individual messages (`phase-2-thread-local-persistence.org:369-386`). |
| 43 | Request/write paths repeatedly execute schema DDL | Runtime reads and writes are expressly forbidden from executing schema DDL; startup/reload validates the migration manifest (`phase-2-thread-local-persistence.org:363-367`). |
| 44 | Async flush allocates a thread, cold connection, clone, and reconciliation storage per flush | The target is a long-lived writer/connection and bounded buffer ownership swap with no payload copy (`phase-2-thread-local-persistence.org:452-471`). |
| 45 | Planner uses quadratic scans, repeated scratch allocations, and unnecessary sorting | The plan requires one semantic-key/dependency index pass, bounded reusable metadata, streaming execution, and pairwise scans/sorts only when semantics require them (`phase-2-thread-local-persistence.org:322-340`). |
| 62 | Treatment resolution performs writes during repeated read evaluation | Read programs cannot move durable data; `ASSIGN_SESSION_TREATMENT` is explicitly on the write migration surface (`phase-2-thread-local-persistence.org:202-265,402-427`). This captures removal of the write-on-read behavior, though not a caching policy. |
| 65 | Persistence flushing blocks the profile thread | Phase 2 moves apply to a reusable writer (`phase-2-thread-local-persistence.org:452-471`); Phase 3 moves semantic write intake/apply out of profile ownership and removes profile-owned apply as a completion condition (`phase-3-global-actors.org:425-446,479-492`). |

## Partially or generally captured (23)

These items are not safe to remove from the backlog: the plan touches them, but
its completion criteria do not preserve the whole original requirement.

| ID | Backlog item | Captured portion | Missing original requirement |
|---:|---|---|---|
| 2 | Reliable duplicate window/documentation mismatch | Network ownership includes reliable replay state, and selected regressions name endpoint rebinding, sequence rollover, old/terminal replay-adjacent behavior (`phase-3-global-actors.org:288-309,470-476`). | No 1024-window admission contract, old-packet watermark rule, or doc/code reconciliation. |
| 3 | WebSocket framing/local-ACK contract drift | Global network owns WebSocket ingress, ACK/retry/replay, routing, and tests UDP/WebSocket responses (`phase-3-global-actors.org:288-317,458-460`). | No one-packet-vs-coalesced frame decision or reliable-outbox clearing condition after frame write. |
| 6 | Fragmented profile/reservation directory responses are unusable by the client | Fragmentation state and fragmented reliable-delivery tests are in Phase 3 (`phase-3-global-actors.org:288-295,458-476`). | No directory response contract, client reassembly requirement, or authoritative-row advancement test. |
| 11 | Server-protocol TLS caches survive runtime restart | Protocol caches receive owners, invalidation rules, profile-isolation contracts, and a migration regression (`phase-3-global-actors.org:415-420,470-477`). | Rate-limit/login-challenge state and explicit profile-runtime init/reset/partial-cleanup boundaries are not named. |
| 25 | Config reload mixes new global policy with old per-profile config | Actor transport includes reload generations and profile-isolation tests (`phase-3-global-actors.org:425-442,458-477`). | No requirement that policy, treatment, and `rp->cfg` switch as one stable snapshot. |
| 26 | `GET_PROFILE_INFO` advertises an endpoint before its gateway adopts reload | Network reload and endpoint isolation are tested and WebSocket ownership moves globally (`phase-3-global-actors.org:288-317,458-477`). | No advertised-endpoint/live-gateway coherence invariant. |
| 34 | `UPDATE_BOARD_MOVE_META` SQL always fails | The exact intent kind is in the finite write migration surface, every write path is audited, and durable witnesses are mandatory (`phase-2-thread-local-persistence.org:346-359,392-427`). | The trailing comma bug and affected-row metadata regression are not retained explicitly. |
| 41 | Domain workers reconstruct/inherit runtime context ad hoc | Every thread becomes a runtime-registered actor; every emitter installs explicit transport; workers may communicate directly with global actors (`phase-3-global-actors.org:54-86,208-220,384-440`). | No complete constrained capability/context contract for config, queries, intents, runtime events, profile, and cancellation. |
| 46 | Prediction insert discards returned ID and reloads all predictions | `RECORD_PREDICTION` is inventoried and returned-identity witnesses must come directly from the establishing operation (`phase-2-thread-local-persistence.org:383-385,402-427`). | The `prediction_submit_with_parent` reload/scan path is not named or explicitly removed. |
| 48 | `compute_session_ui_caps` repeats many reads on every response | The exhaustive read inventory covers joins, aggregation, caches/wrappers, and mixed domain decisions (`phase-2-thread-local-persistence.org:240-255`). | No one-stable-capability-snapshot or per-response/query-count requirement. |
| 49 | `board_last_move_shown` writes/reloads unchanged state on every render | `RECORD_LAST_MOVE_SHOWN` is inventoried; idempotency, supersession, and lifecycle-equivalent transformations are required (`phase-2-thread-local-persistence.org:285-340,402-427`). | No explicit unchanged-tuple suppression or board-fetch subquery removal. |
| 50 | Player stats uses sequential query fan-out and a write-on-read handle lookup | Read purity captures removal of handle creation; the exhaustive inventory covers joins/aggregation and caches (`phase-2-thread-local-persistence.org:202-265`). | No concrete combined stats query/latency target for this handler. |
| 51 | Leaderboard reruns full ordering with no result cache | Query inventories must cover ordering and caches/wrappers (`phase-2-thread-local-persistence.org:240-255`), and caches have budgets/metrics (`phase-2-thread-local-persistence.org:146-155,473-485`). | No authoritative leaderboard result cache/invalidation requirement. |
| 52 | WebSocket route lookup is globally locked and linear | WebSocket routing and gateway/client ownership move under GlobalNetworkRuntime (`phase-3-global-actors.org:288-317,415-443`). | No route-index complexity or contention target. |
| 56 | Active-reservations polling performs 3–4 serial lookups | Every QueryService operation must be analyzed for joins, aggregation, and wrappers (`phase-2-thread-local-persistence.org:240-255`). | No named set-based reservation hydration operation or poll latency/query-count test. |
| 57 | Player hydration performs five sequential stat queries | Same exhaustive read-operation inventory can consolidate it (`phase-2-thread-local-persistence.org:240-255`). | No explicit replacement of the five-query hydration fan-out. |
| 59 | `LIST_PROFILES` performs per-profile policy/treatment fan-out | Read inventory covers operation shape, joins, caches, and mixed policy decisions; protocol cache ownership includes profile-list (`phase-2-thread-local-persistence.org:240-255`;  `phase-3-global-actors.org:415-420`). | No set-based/cached discovery evaluation or profile-count scaling criterion. |
| 60 | Every token packet refreshes treatment assignment from DB | Session-capability cache ownership and exhaustive query inventory apply (`phase-3-global-actors.org:415-420`; `phase-2-thread-local-persistence.org:240-255`). | No admission-path cache/version rule eliminating the per-packet lookup. |
| 61 | Every profile-info row reruns discovery/join/ToS probes | Profile-info cache ownership plus read inventory applies (`phase-3-global-actors.org:415-420`; `phase-2-thread-local-persistence.org:240-255`). | No single hydrated row operation or directory-load query/latency bound. |
| 63 | Every packet reruns trust-tier policy/treatment reads | Trust-cache ownership and exhaustive read inventory apply (`phase-3-global-actors.org:415-420`; `phase-2-thread-local-persistence.org:240-255`). | No stable per-request/session trust snapshot or elimination of the per-packet probes. |
| 64 | Every profile request rehashes/probes ToS acceptance | Terms-cache ownership and exhaustive read inventory apply (`phase-3-global-actors.org:415-420`; `phase-2-thread-local-persistence.org:240-255`). | No ToS version/cache invalidation contract that removes the per-request DB probe. |
| 66 | Prediction projection rereads complete move history | Query inventory covers ordering, joins, aggregation, and caches (`phase-2-thread-local-persistence.org:240-255`). | No incremental/materialized projection or game-length scaling requirement. |
| 70 | No general structured audit layer for runtime decisions | Persistence messages have explicit outcomes, witnesses, retry/drop semantics, metrics, and lifecycle observability (`phase-2-thread-local-persistence.org:285-359,473-485`); actor ordering/acceptance boundaries are explicit (`phase-3-global-actors.org:94-136`). | The requested codebase-wide decision-record layer for scheduling, admission, cleanup, WebSocket cadence, and all other runtime paths is absent. |

## Not retained (42)

Completing all written Phase 1–3 obligations would not necessarily address any
of the following. IDs and ordering match the source backlog.

### 01 conformance

1. Split raw transport-observation test receive helpers from protocol-admission helpers.
4. Decide fail-open/fail-closed semantics for missing board-pairing treatment assignments.

### 02 server weaknesses

5. Separate online-presence accounting from long-lived reservation ownership.
7. Bound per-transfer and aggregate client fragment-reassembly allocation.
8. Stop `max-contributors` capacity from silently changing scoring arithmetic.

### 03 simplification, server first

9. Define canonical typed protocol-facing state/transition objects.
10. Add typed server-handler domain outcomes and protocol/runtime effects.
12. Remove/restore the stale treatment-driven last-move rendering paths and align docs.
13. Define one structured profile status/ToS-state contract.
14. Add structured player-stats target kind/status/identity/rank.
15. Distinguish legal-move outcomes such as not-reserved, stale-board, and invalid-square.
16. Echo leaderboard request scope/page/cursor in responses.
17. Add canonical terminal result/status to board-facing payloads.
18. Add structured spectate-denial reasons.
19. Return authoritative profile directory rows instead of names plus fan-out.
20. Stop overloading notification `fen` with unrelated payload types.
21. Carry explicit identity-attachment state and canonical identity metadata.

### 04 quality philosophy, server first

22. Move process-global spectator state/caches into the correct per-profile ownership model.
24. Render each capability-shaped response from one stable treatment/session snapshot.
27. Make treatment assignment profile-dimensional rather than one mutable session value.
28. Prove/fix named-profile treatment materialization during normal multi-profile startup.
29. Replace partial handwritten runtime-config equality and test every reloadable field.
30. Deep-copy/free profile ToS text in rollback snapshots.
31. Add abort-handoff recovery after failed exec hot reload.
32. Include ports in normalized DB endpoint identity.

### 05 performance, server first

47. Remove dormant-board DB I/O and hydration from under `board_mutex`.
53. Move treatment/board/player reads out of `g_prediction_mutex` during submit.
54. Move spectator visible-FEN DB reads out of `spectators_mutex`.
55. Move player hydration DB misses out of `board_mutex` during tick.
58. Move spectator summary rebuild/export/hydration/sort out of `spectators_mutex`.
67. Move persistent-session/stat hydration out of `player_mutex`.
68. Resolve cold focus-spectate boards without holding `spectators_mutex`.
69. Avoid full prediction-table scans under the prediction mutex.

### 06 engineering tooling and tests

71. Run performance linters.
72. Parallelize test execution.
73. Remove the test runner minimum timing floor.
74. Flush parent stdout before test-process forks.
75. Run current tests against older code versions.

### 07 product changes

76. Configure scoring pot cap separately by game mode.
77. Replace account flow with username/password plus recovery-key reset.
78. Allow spectating by player rather than only board ID.
79. Expose selected-player historical moves and surrounding board/history context.

## Bottom line

The strongest retained subset is backlog IDs 33–45 around persistence
correctness/performance, plus read purity (23 and 62), profile-thread persistence
stall removal (65), and parts of network reliability/cache ownership. Broad
“inventory every query/write/cache/thread” clauses provide discovery coverage
for another 23 items, but they do not preserve those items' concrete acceptance
criteria. The other 42 source requirements are absent and must remain in a
separate backlog or be added explicitly to the roadmap if they are intended to
survive the revamp.
