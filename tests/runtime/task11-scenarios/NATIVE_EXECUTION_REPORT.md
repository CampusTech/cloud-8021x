# Native executable source checkpoint

This checkpoint implements the genuine fixed native client route; no installed helper, socket, service, SQL or guest execution was performed. The outer driver and full installed scenario gates remain open.

The first behavioral regression failed against exact preserved stubs (`red-native-source/`, 0.219s), then passed (0.180s). The executable/action regression separately failed against `red-native-execute-source/` (0.148s), then the entire nested module passed (1.639s). Final race passed (3.783s); native and Linux ARM64 lint each reported zero issues. The first analyzer failure is retained separately; only the unused literal and tagged switch were corrected.

Live source retains and measures the fixed `/usr/bin/eapol_test` ARM ELF descriptor against `b6b68a52dc15c9797ca8bc32645f51e4e758149158cea6522b3417660d437036`, executes that FD only, requires the literal TLS name `radius.task11.test`, forwards unmodified authenticated EAP frames, verifies the genuine Class before deriving independent event/usage IDs, and sends exact accounting frames only afterward. Duplicate pairs retain identical bytes. Accounting replies are individually authenticated; absent ACKs remain absent. Debug and private Class output are suppressed.

`main.go` necessarily extends the previous admit-only CLI with fixed `nas ACTION`, emitting only the shared NAS or CA body. It does not fabricate controller retirement. Controller namespace/cgroup/proc assembly, physical seed DNS/SAN, helper/material identity and actual installed behavior remain separate required gates.

Evidence directory: `/private/tmp/cloud8021x-task11-scenarios-91a6`. Exact log hashes:

- `red-native.log`: `aff117211f68a2a1a1ec90be0db2881b5dc4a1dc3851ce734f8f7cb430ed98cc`
- `green-native.log`: `8cf28a3d72d0d9c016b526299fa4e02a36785e87436981e1badc630eb40bf782`
- `red-native-execute.log`: `305b29d43551b2dee10403bb1a689a91d4ac780a3a028a1c9afe154955b932e9`
- `green-native-execute.log`: `d43ae857e50df6b77049beff4ff8f60d08f78e7b483f8d50fd7191680801771b`
- `race-native-execute.log`: `5df2f3d5acf188256ae22c7f74c450d6899a6adc642442eb72de34fe70861e64`
- `lint-native-execute-first.log`: `8e2402709bc70c993023fb3b96396848362b5efe0f481355e0e0989b278c49fc`
- `lint-native-execute.log`: `e92606b0bf483111dff0a120c315ea165821348f31365020e2468a0059095c47`
- `lint-linux-native-execute.log`: `e92606b0bf483111dff0a120c315ea165821348f31365020e2468a0059095c47`
