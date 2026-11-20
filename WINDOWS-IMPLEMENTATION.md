# Windows implementation status — 2026-11-20

This change implements a Windows experimental backend behind the existing
Local Apps UI. It reuses the existing EasyConnect worker; it does not change
the worker protocol, authentication, or the running Linux helper.

## Implemented

- The launch barrier reserves an empty Job Object and registers it with the helper
  before creating any application process. After rule acknowledgement, ordinary-user
  `CreateProcess` uses `PROC_THREAD_ATTRIBUTE_JOB_LIST` to assign the job atomically.
  This avoids a suspended-process orphan if the GUI crashes during preparation.
  Capture detach never terminates a launched application. Membership, ordinary-user
  ownership and process creation time are checked; children can outlive the launcher.
- TCP ownership uses both endpoints from sing's existing `winiphlpapi` tables,
  pins a process handle and rechecks the table. Unknown or ambiguous ownership
  is rejected. UDP forwarding is limited to DNS and confirmed unselected processes.
- Session helper elevated through UAC; a local named pipe has an explicit DACL,
  rejects remote clients, checks peer PIDs and executable identity, and carries
  private proxy credentials without command-line/config-file disclosure.
- DNS/helper preparation and queued control requests can be cancelled without
  holding the shared pool mutex. A committed DNS lease outlives the first software
  launch, preserving alias identity for the whole VPN generation.
- Cancelling UAC preparation closes its pipe promptly; an outstanding OS consent
  dialog must still be dismissed by the user. Only one prompt may be outstanding;
  a late-approved helper cannot configure the already-closed session. Shared
  attachment/publication operations consume their bounded reply before rollback,
  so cancellation of one launch/query does not close other applications' transport.
- Wintun from sing-tun, with explicit adapter address and resource routes; no
  default route, global DNS reset, system proxy change or firewall allow rule.
- The GUI's existing per-project SOCKS listener supplies selected TCP connections
  to the current VPN generation. Unselected connections use the current original
  route and an interface-bound socket, including virtual interfaces when selected
  by that route. Equal-priority ambiguity and conflicting routes fail explicitly.
- NRPT for validated internal namespaces, the worker's domain alias mapping,
  publication before DNS answers, original target restoration for unselected apps,
  and bounded alias draining after normal disconnect.
- Resource routes and NRPT are enabled on first attachment and removed on last
  detachment, even while the DNS lease retains the idle helper/adapter/alias route
  until VPN disconnect. Installation rolls back in reverse order. Failed cleanup
  remains owned and is retried on heartbeat and helper shutdown.
- Watchdog cleanup plus an HKLM journal containing only helper PID/creation time
  and session ID. The next elevated helper recovers orphaned DNS rules after a
  reboot. It does not run automatically during system startup.
- Windows Start-menu desktop executable import, restart preflight, UI entry,
  reproducible ZIP packaging, licenses, checksums and native self-test executable.

## Windows feedback and `.3` correction

The user reported `.2` VPN login success and VPN TCP establishment through the
proxy-browser and database-forward projects. DBX capture failed with only
`The parameter is incorrect.` after approving UAC, before the DBX window opened.
Those successful connections do not validate DBX capture; the earlier login and
certificate errors are separate from this failure.

`configureIPv4Interface` now resets `SitePrefixLength` to zero before writing an
IPv4 interface row back through `SetIpInterfaceEntry`. The pinned sing-tun
`internal/winipcfg` already normalizes this field after Get; our manual setup had
bypassed it. Microsoft's SetIpInterfaceEntry IPv4 contract requires zero:
<https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setipinterfaceentry>.
This is a verified configuration defect and a candidate cause for the observed
error. The `.2` log cannot identify the exact failing API, so the DBX root cause
remains unconfirmed until the user retries `.3`.

Initialization, routing, pipe verification and process-launch failures now carry
operation/API context and numeric Win32 codes before IPC serialization. Capture
startup/runtime failures also reach the existing app log with the launch-time
project name. Native regression tests inject Get/Set responses (including the
`0xffffffff` sentinel), check preservation of other interface settings, and cover
read/write failure diagnostics without modifying the host network.

## Dependency decision

The pinned sing-tun system stack automatically adds a Windows firewall rule.
Its `with_gvisor` adapter also fails to compile against the repository's existing
metacubex/gvisor version (`PacketBufferPtr`, UDP callback and constructor changes).
`internal/wincapture/netstack.go` adapts the existing gVisor API through its
channel endpoint and gonet forwarders. No dependency version was changed and no
TCP/IP implementation was copied or rewritten. Wintun is still created by the
existing sing-tun dependency; its embedded amd64 DLL matches official 0.14.1.

## Validation evidence

- Linux `go test ./...` passed after wiring the shared UI/config changes.
- `go test -race ./internal/wincapture ./internal/localapps ./internal/proxy` passed.
- In-memory packet integration tests pass real TCP request/response and half-close,
  UDP payload return, and original endpoint metadata through the adapter.
- Policy tests cover exact address-range conversion, original Tailscale-style route
  selection, ownership ambiguity, alias collisions, DNS namespace limits and IPC frames.
- Regression tests cover cancelled DNS preparation, pool shutdown, retained shared
  DNS identity, consent cancellation, queued/in-flight shared request cancellation,
  invalid acknowledgements and partial-rule rollback with cleanup retries.
- Async failure reporting tests pass for both DNS preparation and capture startup,
  including name/error propagation and unlocked observer callbacks.
- Windows amd64 GUI, helper, independent sibling worker and native tests compile.
  Windows-targeted `go vet ./internal/wincapture ./cmd/app-helper` passes.
- The ZIP and all entries in SHA256SUMS were checked. Packaging checks both worker
  protocol files are identical before building.

The Windows native executable has **not run on Windows** in this workspace.
Cross-compilation and memory packet tests do not validate Win32 runtime behavior.
The `.3` bundle uses capture helper protocol 2 (empty-job attachment); replace the
whole ZIP together. The EasyConnect worker protocol remains unchanged at version 5.
The new native IPv4 parameter tests have been cross-compiled, not executed here.
An existing `go vet` lost-cancel finding in `internal/localapps/manager.go` remains;
the new Windows backend is not claimed to make repository-wide vet clean.

## Remaining before acceptance

1. Run `test-capture.ps1` on ordinary-user Windows 10/11 x64. It covers the launch
   barrier, root/child ownership, creation-time mismatch, stop without termination,
   cancelled launch creating no process, duplicate launch rejection, and
   root-exit/last-child-exit behavior using loopback sockets only.
2. GUI/UAC/named-pipe handshake and refusal/cancellation checks; Wintun creation,
   IP Helper adapter setup and effective NRPT verification on the actual machine.
3. Selected versus unselected software to the same permitted target, internal DNS,
   IDEA/database/browser work, local development endpoints and Tailscale coexistence.
4. Stop/disconnect, unexpected GUI/helper/watchdog exit, reconnect, network changes
   and reboot recovery. Check exact route/NRPT/adapter cleanup.
5. Extend verified support for overlapping resource routes and packaged/background
   applications as needed. Current conflicts reject capture instead of guessing.
6. Decide the release installer/service and signing workflow after runtime evidence.
   This deliverable is a portable experimental ZIP, not a signed installer or an
   installed persistent Windows service.

The overall Windows feature goal remains open until these runtime requirements
are verified and any resulting defects are fixed.
