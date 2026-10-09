# Task11 offline protocol fixture

This owned ARM development fixture installs the unchanged authenticated shipping62 closure into the cached Debian13 image and exercises actual FreeRADIUS/EAP, TLS PostgreSQL, native replay and fixed step-ca SCEP. The two containers share an internal network namespace, expose no host ports, and have aggregate limits of 2 CPU / 3 GiB. Only owner-labelled resources are cleaned.

The application is supplied explicitly; no frozen application is accepted by default:

```
python3 tests/runtime/task11-protocol/run.py \
  --application-dir /private/tmp/ROOT-PROVIDED/application \
  --source-sha EXACT40HEXCOMMIT \
  --application-sha256 EXACT64HEXARMAPPHASH \
  --go /path/to/cached/compatible/go \
  --output-dir /private/tmp/OWNED-EVIDENCE-DIRECTORY
```

The runner verifies the exact binary hash, its directory's mandatory SHA256SUMS binding, Linux/ARM64 build settings, source revision and clean VCS metadata before creating any container. The output directory must already contain the owned development native-fixture/SCEP executables, verified cached psql16 binary, and public synthetic SCEP configurations. Source and binary hashes are recorded; development fixture helpers are separate from the clean shipping application. No packages are acquired and no shipping artifact is rebuilt.

`--ca-only` runs the existing actual SCEP suite against Badger and verified TLS PostgreSQL. `--account-only` preserves the narrow direct/native account probe. `--sudo-regression` exercises the actual package-created locked/nologin/expired account using the rendered product command-scoped sudo policy, then genuine EAP. These modes are mutually exclusive.

The full packet path includes actual dedicated certificate expiry/issuer propagation, production Class-validating auth ingestion, persisted BYOD and attested ACME expiry observations, shared-subject `wifi` classification, retained missing-field/unavailable coverage, legacy/resumption unavailable coverage and raw TLS/Class privacy. Original packet, VLAN13/6, TLS, SQL, replay, permission and resumption assertions remain intact.

`runner_inputs_test.py` is a read-only check of actual cached application identity. Supply `TASK11_INPUT_APPLICATION_DIR`, `TASK11_INPUT_SOURCE_SHA`, `TASK11_INPUT_APPLICATION_SHA256`, and `TASK11_INPUT_GO`; it starts no native resources.

The protocol report records the preserved setup/account/wiring REDs and exact corrected81 full native/SCEP GREEN. Installed systemd/PID1, HA/operator flows and AMD native authentication are separate gates. Run only within root's authorized resource and Git windows; no staging, commit or push is implied by a fixture run. All synthetic keys/data/binaries stay outside Git under the explicit owned temporary directories.

Cleanup validates ownership before any capture/removal, attempts removal independently of log/probe/copy failures, continues every created owned resource, and makes capture/ownership/removal failures nonzero. The final PASS is printed only after cleanup succeeds. `cleanup_test.py` exercises the actual runner finally block with injected failures; `--actual-stopped` additionally uses one reserved cached container under network-none/1CPU/128MiB, records the outcome, and independently rescues only its exact owned label when testing the old bug. Root authorization is required for that real-container mode.
