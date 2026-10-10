# Immutable collection epoch contract (source implementation; installed gate open)

The epoch is explicitly selected before activation. It is not an activation-generated clock timestamp, a result receipt timestamp, or the original historical inventory observation time.

* `task11-assembly-seed/contract/contract.go` declares Input.CollectionEpoch (`collection_epoch`) and validates frozen UTC whole seconds.
* `task11-assembly-runtime/config.go:33` writes that exact value into the green candidate Config.Deployment.CollectionEpoch.
* `internal/adoption/binding.go:24` includes it in the signed ExpectedBinding contract.
* `internal/app/parallel.go:245` passes that exact configured value into PrepareCollectionEpoch during genuine protected prepare.
* `internal/storage/postgres/parallel_epoch.go` inserts the supplied epoch; it refuses any changed existing deployment/transition/manifest/epoch and refuses imported accounting/export history.
* `task11-acceptance/sql_linux.go` and `scenario_sql_linux.go` require actual stored SQL epoch equal the protected config value.

Root accepted the local-only declaration, implemented after meaningful behavioral RED: required time.Time `json:"collection_epoch"`, nonzero UTC whole seconds, independently selected from the pinned green candidate/input. Controller admission must compare plan epoch to the exact protected candidate/config. NAS expectation generation then uses the immutable plan epoch and rejects any mismatched caller value. Actual probe/ledger observations remain separate evidence and must equal that independently expected epoch; the plan alone does not establish installed SQL state.

Original CA issue/database verification runs before capture using the separately pinned original authorities. Its plan may already contain the selected green candidate epoch; it must never substitute the original legacy config's unset epoch or historical inventory timestamps. No NAS SQL query, wallclock fallback, inferred result timestamp, new outer Request selector or private stdin field is needed for expectation epoch. The required plan field, UTC whole-second validation and expectation mismatch refusal have actual source RED/GREEN/race/lint evidence in REPORT.md. No actual protected config/SQL/runtime observation has run; controller admission and reconciliation remain separate installed gates.
