# Task 11 passive observer preparation report

Current status after scoped I1/I2 correction: **regressions/race/build/lint GREEN;
independent re-review pending; every genuine installed gate remains OPEN**.
The correction receipt below supersedes the initial source/helper freeze. Initial
evidence and report remain retained in the separately frozen review baseline.

Status: **focused preparation GREEN; installed execution/reboot/SQL proof NOT EXECUTED**.
Scope is only new `tests/runtime/task11-passive-audit/`. No shipping, controller,
peer cloud, package, account, PAM or KMS-source edits; no staging/commit/push and no
container/VM/SQL launch. R108's five source paths remain untouched by this slice.
Local source HEAD at final build: `0745ebd10aee420a3f07bef8fbaf7ac498700192`. Shared tracked worktree/index diff was
empty when inspected. The helper is development source, not a clean shipping app.

The fixed executable/argv, typed JSON and exact 24 closed preserved slots are
frozen in README.md and contract/types.go and were coordinated with runtime owner.
Controller owns independent prepared-state derivation, protected manifest/enrollment,
namespace/cgroup transport, actual reboot orchestration and before/after comparison.
Cloud owner R130 owns historical passive peer journal audit. Neither API permission
nor this observer's read-only snapshot is product activation evidence.

## Test-first evidence

Initial contract stubs returned nil and the five rejection groups failed on actual
Go execution (unsafe enrollment, incomplete/foreign slots, live service/timer,
unsafe/unfenced SQL, admission/outbound peer sockets accepted). Exact original
three-file source is retained under `/private/tmp/cloud8021x-task11-passive-audit-91a6/red-source`. A final replay of those
saved stdlib-only files with GO111MODULE=off returned actual exit **1**, separately
retained as preserved-contract-red-replay.log. Original RED logs are preserved.
Additional narrow REDs cover hardlinked credentials; real proc-format decoding;
missing physical preparation receipt; native's two fixed drop-ins; timer properties;
and mistaking historical ConditionResult for current activation state. Later RED
logs are pure observer regression evidence, not installed product failures.

Saved initial RED source hashes:

```json
{
  "types.go": "5561264d21e96ccffcbf1da8a5872490164b7ad671a15a589f02a011a5580302",
  "validate.go": "81d20b7a6b1db96315cdc650660e31c6c6a46fa478d0f6ec36f60c84c28eda1f",
  "validate_test.go": "fd51e7d0760db2262c1090ead5cd611ad5c464172c8a33c70c4d95950a2ad424"
}
```

Final affected verification commands (cached Go1.27.2/tooling, no dependencies acquired):

```
goimports -w tests/runtime/task11-passive-audit
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOMAXPROCS=1 GOCACHE=/private/tmp/cloud8021x-go-cache go test -race -count=1 -p=1 ./tests/runtime/task11-passive-audit/...
GOOS=linux GOARCH=arm64 GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOMAXPROCS=1 GOCACHE=/private/tmp/cloud8021x-go-cache go build -p=1 -o /private/tmp/cloud8021x-task11-passive-audit-91a6/task11-passive-audit-arm64 ./tests/runtime/task11-passive-audit
GOOS=linux GOARCH=arm64 GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOMAXPROCS=1 GOCACHE=/private/tmp/cloud8021x-go-cache GOLANGCI_LINT_CACHE=/private/tmp/cloud8021x-golangci-cache golangci-lint run ./tests/runtime/task11-passive-audit/...
goimports -l tests/runtime/task11-passive-audit
```

`go` resolves to the cached toolchain
`/Users/robbiet480/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.27.2.darwin-arm64/bin/go`.
`golangci-lint` is `/private/tmp/cloud8021x-pr38-security-bin/golangci-lint`, actual
version2.14.0 built with Go1.27.2. Final race command exit0, both packages pass;
Linux ARM64 cross-build exit0; scoped Linux lint exit0 / **0 issues**; goimports
list empty. Build emitted a sandbox denial for an opportunistic main-module stat
cache write outside writable roots; compilation still exited0. Metadata confirms
linux/arm64, CGO_ENABLED=0, vcs.revision `0745ebd10aee420a3f07bef8fbaf7ac498700192`, vcs.modified=true. That dirty
helper boundary is explicit; it is never substituted for root's clean shipping
application/source pins. Initial lint findings were fixed only in owned files.

Final Linux ARM64 helper SHA256: `57a40ff99261fbce2f68ae30ec8d87f837a8c2da35a8806a38df6695354590fd`.
Exact source/README freeze (canonical sorted JSON, without final newline): `92c53b7e4b2d8d08c51447a161291d6cace124a883528729291aaefd2dcdb057`.
File list/digests retained at `/private/tmp/cloud8021x-task11-passive-audit-91a6/source-sha256.json`.
REPORT.md is excluded from that source digest to avoid a self-referential hash;
its own final SHA is supplied in handoff.

## Safety and remaining actual gates

The Linux code calls actual production strict config, generation, committed
credential, installed receipt, passive barrier/unit rendering, worker fence and
Postgres TLS APIs. There are no writer locks, restore/write/sign/create calls,
RuntimeServices injection, arbitrary commands/paths, endpoint overrides or network
acquisition. SQL is source-fixed SELECT within verified READ ONLY repeatable-read;
actual migration role/database/private peer are constrained. File reads are
protected descriptor walks, exact owner/group/mode, non-symlink regular single-link,
bounded unchanged identity; installed/preserved state is rechecked after collection.

Unknown/missing state refuses. Prepared loaded stopped services and exact guarded
waiting timers are separated; deactivated requires genuine protected five-unit
masks and verified original worker completion bound to SQL. ConditionResult is
reported as a known historical result; current false guard comes from exact barrier
bytes and actual activation-file absence. Timer-only properties never fabricate
service PID/cgroup observations. Actual PID1/boot/namespaces, process/listener/peer
snapshots, mount/backing image/UUID/capacity, key/cert/Class/cache identity and both
physical preparation/SQL original source bindings are collected by the Linux path.
They have **not executed** on an installed node in this turn. Snapshot predicates
cannot prove absence of historical cloud attempts; R130's journal audit is required.

Concrete outstanding gates: independent actual preparation-derived manifest and
original source/certificate-state provenance; reviewed source/binary pins; both-green
actual installed observer runs; real controller-owned reboot and stable preserved
state comparison with changed genuine BootID; independent whole-window cloud peer
audit; final genuine prepared readiness/passive recheck before first activate;
actual deactivated worker/mount/state observations; later CLI/DB/PID1 activation and
business intake proof under R123. No pure test, build, marker or permission grant
closes those gates. No owned running resource was created, so none requires cleanup.

## Evidence hashes

All evidence is under `/private/tmp/cloud8021x-task11-passive-audit-91a6`.

| Artifact | SHA256 |
| --- | --- |
| contract-red.log | 3c5fde05f7aa29f76014b84e884f6a18c78f866c6551fb1198dc475fc6f46389 |
| preserved-contract-red-replay.log | 20ee371fa765abc466f5d782f338af66644b759d63f2d4b21b31f101f2b5df94 |
| files-red.log | feee4df791f8d05f5eb3ac6c1c08811cdcae2dac618649968dc2d2b4d9b2350b |
| kernel-red.log | 38ce0745e2d7469b81a4ea2949dd1ad9a4acc5ea8f61cfe354caedcd4dcd6c5a |
| prepared-red.log | 3bbbe04f50d8ff7e899b2f61bd5002920cae9888220a9d2e2fefc75f07d9c1cd |
| native-dropins-red.log | 33b146a87f9a561c1870ea128cef2ee2b2c4bd3cdfcddb778a8e456849cbb3a5 |
| timer-properties-red.log | 6a9c6f6b0f4f974503ff4a7ef4003932c96487aedcf144af2fa117a4a19e5539 |
| condition-history-red.log | e76677e087175f1bab40f69b6238b08c4652a8dae25bc883733090f6336a888e |
| race-green.log | b115d65df29d2f445f757f4f72db6522734c5c4d0ea83b613cfac12328f54c35 |
| lint-linux.log | e92606b0bf483111dff0a120c315ea165821348f31365020e2468a0059095c47 |
| build-linux.log | b2b86dd32241adcf60f9d6d8207f9e70059de4d85d595c9bb14106ec0e741d01 |
| build-metadata.txt | 82d30fa62b1b07fb43bd1cc40ac72362ad06a7c9099be90fad58af0ee7c64954 |

## Exact owned source freeze

| Path | SHA256 |
| --- | --- |
| tests/runtime/task11-passive-audit/README.md | 68e406377f1eb84a0ace4d1741835e47eef27b35ff0d654e56b829afe4eb65a6 |
| tests/runtime/task11-passive-audit/contract/types.go | 786698897f2837067263c91454c402b9ecce0ec5c99cd1db93811e36cd254b25 |
| tests/runtime/task11-passive-audit/contract/validate.go | 65ffab16563e8d3bbffb36920e274c97292edd16fe54a557ab067bbf48cebab3 |
| tests/runtime/task11-passive-audit/contract/validate_test.go | 8f04e71bc3a2af75bea99638e72cf4a6646ff7bc7f4943da4c779eead2b42998 |
| tests/runtime/task11-passive-audit/files.go | c880bec89dbb369fbbe34e3d801f70aaa5a9365c17c81cc40d6227e4bb95d95f |
| tests/runtime/task11-passive-audit/files_test.go | 9d584ea14f78b364d5f9d9091ab891faf331b2cd72977d93b733279cfd6b64ec |
| tests/runtime/task11-passive-audit/kernel.go | d99308b6f0878ff21ea5da16844187fe43b1276d6f04090e9dc97052acd9ff85 |
| tests/runtime/task11-passive-audit/kernel_linux.go | c3fb21078629c40d2eb7fc7d3d4a46efc33aa1036231a953467162bf068bb92a |
| tests/runtime/task11-passive-audit/kernel_test.go | fd5619190f2ff80cd7dffa8f1ecc242f94f4ebd22d0444064c9f597113ae116c |
| tests/runtime/task11-passive-audit/main.go | 5c0ec5afab3a40121bd905bc00940a7d9cafdbe47f7ea3c070e33e23e984a8c4 |
| tests/runtime/task11-passive-audit/main_test.go | 48fc9f4676832a90cfdfd9330063833116d2b4da584141d091b200c53df039ae |
| tests/runtime/task11-passive-audit/observe_linux.go | 942850e9f3a6968c5f07e214c5c2b300034c7051cfbe1064fba6d868d2cb0755 |
| tests/runtime/task11-passive-audit/observe_other.go | 2f9d552a36fe3565f26cb68fc632ef59a3b1cb2d476f145fc0d6ceca139c0e48 |
| tests/runtime/task11-passive-audit/sql_linux.go | 2d425753fbd63c05440dc69b08bffeaa18d51d58aab48b5e9bbc475bc7099067 |


## Scoped review correction I1/I2 — one wave

Read the complete independent frozen review task-11-passive-observer-review.md
(0 Critical, 2 Important). Changed only owned observer paths. Both findings were
reproduced before correction, with actual Go test command exit **1**; no native
observer/container/VM/SQL/cloud operation ran. Bounded host test subprocesses did
run because the actual os/exec pipe route is the required I1 reproducer.

I1 RED: actual io.Copy from os.Pipe and actual os/exec shared stdout/stderr route
accepted **32,769 and 98,304** bytes, returned nil error and retained all bytes.
The permitted exact **32,768** boundary passed before and after correction. The
buffer was moved unchanged from Linux-only source into buffer.go solely to test
that exact implementation on the host before fixing it; it now stores bytes.Buffer
in a named private field, exposing only enforcing Write plus Len/String. There is
no promoted ReadFrom to bypass the writer. Both routes refuse overflow and retain
at most32KiB after the correction.

I2 RED: for both renew and sources timers, both enabled waiting and disabled
inactive states accepted a foreign drop-in, a /run foreign fragment, and a missing
fragment. Corrected normal timer validation requires exact shipping protected
`/etc/systemd/system/` + unit name and empty DropInPaths, while retaining its exact
service target and legitimate waiting/inactive states. Existing genuine deactivated
five-mask semantics and all other contracts/24-slot/schema fields remain unchanged.

Only changed paths from the reviewed baseline: buffer.go, buffer_test.go,
kernel_linux.go (move of unchanged buffer declaration), contract/validate.go,
contract/validate_test.go, README.md, REPORT.md. All other frozen original files,
including contract/types.go, are byte-identical. The original15-file reviewed
baseline is retained under `/private/tmp/cloud8021x-task11-passive-audit-review1-91a6/frozen-source`; meaningful pre-fix regression
source under `/private/tmp/cloud8021x-task11-passive-audit-review1-91a6/red-source`. Neither replaces earlier evidence.

Verification used the same cached Go1.27.2, goimports, golangci-lint2.14.0 and
GOCACHE/GOLANGCI_LINT_CACHE as the initial report, GOPROXY=off/GOSUMDB=off.

```
go test -count=1 -p=1 ./tests/runtime/task11-passive-audit/...
go test -race -count=1 -p=1 ./tests/runtime/task11-passive-audit/...
GOOS=linux GOARCH=arm64 go build -p=1 -o /private/tmp/cloud8021x-task11-passive-audit-review1-91a6/task11-passive-audit-arm64 ./tests/runtime/task11-passive-audit
GOOS=linux GOARCH=arm64 golangci-lint run ./tests/runtime/task11-passive-audit/...
goimports -l tests/runtime/task11-passive-audit
```

Final regular/race tests exit0 (both packages), Linux ARM build exit0, lint exit0
/**0 issues**, formatter list empty. Build's opportunistic main-module stat-cache
write was again sandbox-denied without failing compilation; no cache permission
or acquisition change was made. New development binary SHA256 `c64f1e65d2d8afbdad15c665217d485c9a1c66f3e2584a2de1dfe07f53eccb9d`;
actual metadata source HEAD `0745ebd10aee420a3f07bef8fbaf7ac498700192`, vcs.modified=true, linux/arm64, CGO_ENABLED=0.
This is still a pinned development helper, never a clean shipping application.

Fresh canonical16-file source/README map SHA256 `e9e831f2ed161bbe07392013da7b289c770633dbb16b176dd74867baea6e2f32` at
`/private/tmp/cloud8021x-task11-passive-audit-review1-91a6/source-sha256.json`; REPORT excluded to avoid self-reference. Its separate
final SHA and the full scoped baseline-to-fixed diff are supplied in handoff.
No staging/commit/push. No product/peer/controller edits. Every independently
seeded installation, transport/reboot, SQL, R130 journal and activation gate listed
above stays pending. Independent scoped re-review is the next source gate.

### Correction evidence hashes

| Artifact | SHA256 |
| --- | --- |
| regressions-red.log | d74b97016efb2e061fbcc5010e262ac83c0669a3eb5687cb6d08db044f8b10e8 |
| regressions-green.log | 09c43df962990f9191cc322cb2b5dd9e60f1869cbc78f76f4c2172bb7b797314 |
| race-green.log | 9fa192c250acb80032e2d7358dccd48119ad84eb12a7fbdb1349fb73e0561efa |
| lint-linux.log | e92606b0bf483111dff0a120c315ea165821348f31365020e2468a0059095c47 |
| build-linux.log | 4bcaf61c895a58bed0a1ac896e5481159cb8817be676884345ba340df299c188 |
| build-metadata.txt | 10f42ec67bab4305c4e8257f6d4a53557b54bffb45958188b7d04dda9913ccc0 |
| goimports.log | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |

### Corrected exact source freeze

| Path | SHA256 |
| --- | --- |
| tests/runtime/task11-passive-audit/README.md | 3cc489e0b9129ad77c4f16fdf9cff586f4b53fcfaeb7882109035cd8b60ba42a |
| tests/runtime/task11-passive-audit/buffer.go | 646014d89b011995800c476b97694a615a5e6133539eec504dfcd58416854853 |
| tests/runtime/task11-passive-audit/buffer_test.go | 6f092c8d2b7714e1e7a4201cbe137f9c2cc195a50320c4a1362e0cd583c2b67a |
| tests/runtime/task11-passive-audit/contract/types.go | 786698897f2837067263c91454c402b9ecce0ec5c99cd1db93811e36cd254b25 |
| tests/runtime/task11-passive-audit/contract/validate.go | a91064b34ffaf97738b9236892c892226a9cbb6599117b8db759244c6d4df87b |
| tests/runtime/task11-passive-audit/contract/validate_test.go | ef97306c61b1d9e2eae40f8f9debe2e7a7b2ce13b5834bc7029206b4d7120577 |
| tests/runtime/task11-passive-audit/files.go | c880bec89dbb369fbbe34e3d801f70aaa5a9365c17c81cc40d6227e4bb95d95f |
| tests/runtime/task11-passive-audit/files_test.go | 9d584ea14f78b364d5f9d9091ab891faf331b2cd72977d93b733279cfd6b64ec |
| tests/runtime/task11-passive-audit/kernel.go | d99308b6f0878ff21ea5da16844187fe43b1276d6f04090e9dc97052acd9ff85 |
| tests/runtime/task11-passive-audit/kernel_linux.go | d8f19f6c470fe914d676045ee0abefea9ab2aaae53ddfef1c97f7affe6cc3847 |
| tests/runtime/task11-passive-audit/kernel_test.go | fd5619190f2ff80cd7dffa8f1ecc242f94f4ebd22d0444064c9f597113ae116c |
| tests/runtime/task11-passive-audit/main.go | 5c0ec5afab3a40121bd905bc00940a7d9cafdbe47f7ea3c070e33e23e984a8c4 |
| tests/runtime/task11-passive-audit/main_test.go | 48fc9f4676832a90cfdfd9330063833116d2b4da584141d091b200c53df039ae |
| tests/runtime/task11-passive-audit/observe_linux.go | 942850e9f3a6968c5f07e214c5c2b300034c7051cfbe1064fba6d868d2cb0755 |
| tests/runtime/task11-passive-audit/observe_other.go | 2f9d552a36fe3565f26cb68fc632ef59a3b1cb2d476f145fc0d6ceca139c0e48 |
| tests/runtime/task11-passive-audit/sql_linux.go | 2d425753fbd63c05440dc69b08bffeaa18d51d58aab48b5e9bbc475bc7099067 |
