# Matched minimal Agent and DDOT security build

The shipping pair is `datadog-agent` and `datadog-agent-ddot`
**1:7.84.2-1+campus1**, built from official release7.84.2 commit
`73e6b0351caa6028bfc21e2668aef5a1463bff05` with Go1.27.2. Its runtime version is
7.84.2+campus1; the bundled collector is0.159.0. The official7.84.2 binary used
Go1.26.7 and failed the current actual-binary security gate; it is an authenticated
source/ABI input only. Never install it as a fallback.

`scripts/build-debian.sh monitoring ARCH EMPTY_OUTPUT_DIRECTORY` runs the complete
build in a pinned Debian13/Go image, verifies exact signed immutable Debian build
repositories and retains build inventory/provenance. `scripts/build-monitoring.sh`
verifies the official package via Datadog's Release signature, index digest and
package digest/size/architecture. `provenance/` retains the exact public key,
signed Release and compressed original indexes; the decompressed bytes must match
hardcoded SHA256 and the signed Release. The expected signature is
`5F1E256061D813B125E156E8E6266D4AC0962C7D`. A moving live index cannot change the
accepted inputs. Source tar SHA256 and the full revision embedded in the signed
vendor package bind the source release independently of the tag name.

The only source changes are the explicit security dependency patch. Schema
compression runs the original upstream Python generator functions; the small
wrapper avoids importing unrelated invoke build tooling. Core build tags retain
Python, systemd and OTLP support; DDOT retains the matched official collector and
Datadog exporter/flare components. The package retains matching upstream Python,
rtloader and native shared libraries, licenses and seven ordinary host checks:
cpu, disk, io, load, memory, network and uptime. It contains no stale trace-agent,
process-agent, security-agent or other official Go executable. Every ELF in both
archives is inventoried; each package must contain exactly its intended rebuilt
Go executable. Both executables are scanned with govulncheck1.8.0. Symbols are
retained so the scanner resolves actual called functions; there are no ignores.

These are inert packages with no postinstall service action or vendor units.
Protected Go bootstrap owns the dd-agent identity, private IPC token/certificate,
fixed units, credentials, durable business queue and activation/rollback. Only
DDOT receives `DD_APM_ENABLED=true`: its embedded trace component requires it
for actual startup. The core host Agent keeps APM disabled. Core logging goes
to stdout/journal and remote configuration is disabled; its writable IPC state
is confined to `/opt/datadog-agent/run`. No root execution or capabilities are
needed by the retained host checks.

`tests/ddot_queue.py --architecture ARCH --packages VERIFIED_OUTPUT --evidence DIR
--full-config` installs the actual pair in a networkless disposable container,
runs both processes as dd-agent, checks all seven integrations and the actual
effective pipeline, then proves SIGKILL/restart persistence, protobuf projection,
nonduplicative delivery without daemon resend, and queue overflow503. Add
`--storage-full` for actual filesystem ENOSPC503. No live Datadog key or host port
is used. These are process/package proofs; whole systemd and two-node deployment
acceptance is separate. Ordinary telemetry and the durable neutral OTLP business
pipeline remain separate.
