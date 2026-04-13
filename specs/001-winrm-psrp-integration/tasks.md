# Tasks: WinRM/PSRP Protocol Integration

**Input**: Design documents from `/specs/001-winrm-psrp-integration/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

**Tests**: Included inline — this project has 6300+ existing tests and test discipline is constitutional.

**Organization**: Tasks grouped by user story. US1+US2 are both P1 and tightly coupled (US2 is verified by US1's adapter change), so they share Phase 3.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story (US1, US2, US3, US4)

---

## Phase 1: Setup (Dependencies & Feature Flags)

**Purpose**: Update Cargo.toml and module declarations for winrm-rs/psrp-rs integration

- [X] T001 Update `Cargo.toml`: replace `winrm = ["dep:reqwest", "dep:quick-xml"]` with `winrm = ["dep:winrm-rs"]`, add `psrp = ["dep:psrp-rs", "winrm"]` feature, add `winrm-rs = { version = "1.0", optional = true }` and `psrp-rs = { version = "1.0", optional = true, default-features = false }` deps, update `all-protocols` bundle to include `psrp`
- [X] T002 Update `src/lib.rs`: add `#[cfg(feature = "psrp")] pub mod psrp;` module declaration, verify existing `#[cfg(feature = "winrm")] pub mod winrm;` still compiles
- [X] T003 Verify feature-gated compilation: `cargo check` (no features), `cargo check --features winrm`, `cargo check --features psrp`, `cargo check --all-features` — all must pass (will fail until later phases complete, but structure must be valid)

---

## Phase 2: Foundational (Config Types & Error Mapping)

**Purpose**: Extend config types shared by both WinRM and PSRP adapters. MUST complete before adapter work.

**CRITICAL**: No adapter implementation can begin until these types exist.

- [X] T004 Extend `AuthConfig` enum in `src/config/types.rs`: add `#[cfg(feature = "winrm")] Ntlm { password: Zeroizing<String>, domain: Option<String> }`, `#[cfg(feature = "winrm")] Certificate { cert_path: String, key_path: String }`, `#[cfg(feature = "winrm")] Kerberos` variants per data-model.md
- [X] T005 Extend `HostConfig` struct in `src/config/types.rs`: add `#[cfg(feature = "winrm")] winrm_use_tls: Option<bool>`, `winrm_accept_invalid_certs: Option<bool>`, `winrm_operation_timeout_secs: Option<u64>`, `winrm_max_envelope_size: Option<u32>` fields with `#[serde(default)]`
- [X] T006 Add `Protocol::Psrp` variant in `src/config/types.rs`: `#[cfg(feature = "psrp")] #[serde(alias = "PSRP")] Psrp` in the `Protocol` enum
- [ ] T007 Add config validation rules in `src/config/validation.rs` (or wherever config validation lives): reject `auth.type: key` and `auth.type: agent` when `protocol: winrm` or `protocol: psrp`, reject `proxy_jump` with WinRM/PSRP, warn on `winrm_use_tls: false` + `auth.type: password`
- [ ] T008 Implement `From<winrm_rs::WinrmError> for BridgeError` in `src/error.rs`: map `Auth` -> `BridgeError::Auth`, `Timeout` -> `BridgeError::Timeout`, `Soap` -> `BridgeError::SshExec` per contracts/winrm-adapter.md
- [ ] T009 [P] Implement `From<psrp_rs::PsrpError> for BridgeError` in `src/error.rs`: map `Winrm(we)` -> delegate to WinRM mapping, `Cancelled` -> `BridgeError::Cancelled`, `Protocol(msg)` -> `BridgeError::SshExec` per contracts/psrp-adapter.md
- [ ] T010 Implement `build_winrm_config(host_config: &HostConfig) -> Result<(WinrmConfig, WinrmCredentials)>` helper function in `src/winrm/mod.rs`: map `AuthConfig` variants to `winrm_rs::AuthMethod` + `WinrmCredentials`, map `HostConfig.port/winrm_*` fields to `WinrmConfig` per contracts/winrm-adapter.md mapping rules
- [ ] T011 Write unit tests for config types in `src/config/types.rs` `#[cfg(test)]` module: test serde deserialization of `auth.type: ntlm`, `auth.type: certificate`, `auth.type: kerberos` YAML, test `Protocol::Psrp` deserialization, test `winrm_*` field defaults
- [ ] T012 [P] Write unit tests for `build_winrm_config()` in `src/winrm/mod.rs` `#[cfg(test)]` module: test all 4 auth mappings (Password->Basic, Ntlm->Ntlm, Certificate->Certificate, Kerberos->Kerberos), test TLS auto-detection from port, test default values for timeout/envelope size
- [ ] T013 [P] Write unit tests for config validation in `src/config/validation.rs` `#[cfg(test)]`: test rejection of `Key`+`WinRm`, `Agent`+`WinRm`, `proxy_jump`+`WinRm`

**Checkpoint**: Config layer complete — adapter implementations can now begin

---

## Phase 3: User Story 1+2 — WinRM with Real Auth & Windows Handlers (Priority: P1) MVP

**Goal**: Replace homegrown WinRM adapter with winrm-rs. All 44 Windows handlers automatically work because `run_powershell()` replaces `cmd.exe /c`.

**Independent Test**: `cargo test --features winrm` passes. Configure a `protocol: winrm` host, run `ssh_win_service_status`, verify PowerShell execution succeeds.

### WinRM Adapter Implementation

- [ ] T014 [US1] Rewrite `src/winrm/mod.rs`: replace `WinRmConnection` struct to wrap ``Arc<WinrmClient>`` instead of `reqwest::Client`, implement `from_parts(host_name, client)` constructor, implement `exec()` using `client.run_powershell_with_cancel()` with proper `CommandOutput` conversion (`Vec<u8>` -> String, u32 -> i32 exit code, add duration_ms), implement `exec_with_cancel()` propagating `CancellationToken`, implement `mark_failed()` and `host_name()` per contracts/winrm-adapter.md
- [ ] T015 [US1] Rewrite `src/winrm/pool.rs`: replace `WinRmPool` to cache ``Arc<WinrmClient>`` instead of `reqwest::Client`, keep same API surface (`new()`, `with_config()`, `get_connection()`, `evict()`, `cleanup()`, `close_all()`, `size()`), cold path calls `build_winrm_config()` from T010 then `WinrmClient::new(config, creds)`, keep 120s idle TTL and ``Arc<RwLock<HashMap>>`` pattern per research.md R3
- [X] T016 [US1] Update `ConnectionGuard` enum in `src/ports/executor_router.rs`: verify `WinRm(crate::winrm::WinRmConnection)` variant still compiles with the new `WinRmConnection` struct, update `exec()` match arm if method signature changed, update `mark_failed()` match arm
- [X] T017 [US1] Update `ExecutorRouter` in `src/ports/executor_router.rs`: verify `winrm_pool: crate::winrm::WinRmPool` field still compiles with new pool type, verify `get_connection_with_jump()` WinRM dispatch arm works, verify `cleanup()` and `close_all()` forwarding

### WinRM Tests

- [ ] T018 [US1] Write unit tests for `WinRmConnection::exec()` in `src/winrm/mod.rs` `#[cfg(test)]` module: test PowerShell command execution (mock or stub), test `CommandOutput` conversion (stdout bytes to string, exit code mapping), test cancellation token propagation, test `mark_failed()` flag
- [ ] T019 [US1] Write unit tests for `WinRmPool` in `src/winrm/pool.rs` `#[cfg(test)]` module: test pool caching (get_connection returns same client on second call), test idle TTL eviction via `cleanup()`, test `evict()` removes entry, test `close_all()` empties pool
- [ ] T020 [US2] Verify all 44 `ssh_win_*` handlers compile and pass existing tests with `--features winrm`: run `cargo test --features winrm --lib` and check that no handler tests fail due to adapter change (handlers should be protocol-agnostic since they go through `ConnectionGuard::exec()`)

### Bug Fix (discovered in research)

- [X] T021 [US1] Fix `ExecutorRouter` cleanup lifecycle in `src/mcp/server.rs`: add `executor_router.cleanup()` call to the periodic cleanup task (`spawn_cleanup_tasks`), add `executor_router.close_all()` call to the shutdown sequence — this is a pre-existing bug where pools leak connections

**Checkpoint**: WinRM adapter fully replaced. All 44 Windows handlers work via `run_powershell()`. NTLMv2, Basic, Kerberos, Certificate auth supported. Feature-gated compilation passes.

---

## Phase 4: User Story 3 — PSRP Native PowerShell Remoting (Priority: P2)

**Goal**: Add PSRP protocol adapter for native typed PowerShell output and RunspacePool session reuse.

**Independent Test**: `cargo test --features psrp` passes. Configure a `protocol: psrp` host, run `ssh_exec` with a PowerShell command, verify PSRP execution.

### PSRP Adapter Implementation

- [ ] T022 [P] [US3] Create `src/psrp/mod.rs`: implement `PsrpConnection` struct wrapping `RunspacePool<WinrmPsrpTransport<'static>>`, implement `from_parts()`, `exec()` using `pool.run_script_with_cancel()` + `psrp_to_command_output()` conversion, `exec_with_cancel()`, `mark_failed()`, `host_name()` per contracts/psrp-adapter.md. Include `psrp_to_command_output()` and `pipeline_result_to_command_output()` helper functions.
- [ ] T023 [P] [US3] Create `src/psrp/pool.rs`: implement `PsrpPool` with `Arc<RwLock<HashMap<String, PooledRunspace>>>`, 300s idle TTL, same API surface as `WinRmPool` (`new()`, `with_config()`, `get_connection()`, `evict()`, `cleanup()`, `close_all()`, `size()`). Cold path: `build_winrm_config()` -> `WinrmClient::new()` -> `WinrmPsrpTransport::open()` -> `RunspacePool::open_with_transport()` -> cache per research.md R3
- [X] T024 [US3] Add `ConnectionGuard::Psrp` variant in `src/ports/executor_router.rs`: add `#[cfg(feature = "psrp")] Psrp(crate::psrp::PsrpConnection)` to the enum, add `exec()` match arm routing to `PsrpConnection::exec()`, add `mark_failed()` match arm
- [X] T025 [US3] Add `psrp_pool` field to `ExecutorRouter` in `src/ports/executor_router.rs`: add `#[cfg(feature = "psrp")] psrp_pool: crate::psrp::PsrpPool`, initialize in `with_defaults()` and `new()`, add `Protocol::Psrp` dispatch arm in `get_connection_with_jump()`, forward `cleanup()` and `close_all()` to `psrp_pool`

### PSRP Tests

- [ ] T026 [P] [US3] Write unit tests for `PsrpConnection::exec()` in `src/psrp/mod.rs` `#[cfg(test)]`: test `psrp_to_command_output()` conversion (`Vec<PsValue>` to stdout string), test `pipeline_result_to_command_output()` with errors/warnings, test exit code mapping (Completed->0, Failed->1, Stopped->2)
- [ ] T027 [P] [US3] Write unit tests for `PsrpPool` in `src/psrp/pool.rs` `#[cfg(test)]`: test pool caching, test 300s TTL eviction, test `evict()`, test `close_all()`
- [ ] T028 [US3] Run full test suite with PSRP feature: `cargo test --features psrp` — verify no regressions in existing 6300+ tests, verify new PSRP tests pass

**Checkpoint**: PSRP adapter functional. Hosts with `protocol: psrp` execute via RunspacePool. Session reuse verified by pool caching tests.

---

## Phase 5: User Story 4 — PSRP over SSH Transport (Priority: P3) — DEFERRED

**Goal**: Enable PSRP over SSH for Windows hosts without WinRM endpoints.

**Prerequisite**: psrp-rs must bump russh to 0.58 (separate PR in psrp-rs repo, see research.md R1).

**Status**: DEFERRED until russh version alignment is complete. Tasks listed for planning only.

- [ ] T029 [US4] (BLOCKED) Bump psrp-rs dependency to use `features = ["ssh"]` in `Cargo.toml` once psrp-rs ships russh 0.58 support
- [ ] T030 [US4] (BLOCKED) Add `ShellType::Psrp` variant in `src/config/types.rs` for `shell: psrp` config option on SSH hosts
- [ ] T031 [US4] (BLOCKED) Implement PSRP-over-SSH dispatch in `ExecutorRouter`: when `protocol: ssh` + `shell: psrp`, create `SshPsrpTransport` using existing SSH pool connection, open `RunspacePool` over SSH
- [ ] T032 [US4] (BLOCKED) Write integration tests for PSRP-over-SSH in `tests/`

**Checkpoint**: PSRP-over-SSH working for `protocol: ssh, shell: psrp` hosts.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Config documentation, registry updates, final verification

- [X] T033 [P] Update `config/config.example.yaml`: add WinRM host examples (NTLMv2, Kerberos, Certificate, Basic) and PSRP host example per research.md R6
- [ ] T034 [P] Update registry test counts in `src/mcp/registry.rs`: if any tools were added/changed, update the assertion counts in all 37 registry tests (use `/sync-counts` skill if available)
- [ ] T035 [P] Update `.claude/rules/protocol-adapters.md`: add WinRM adapter section documenting winrm-rs wrapping pattern, add PSRP adapter section, update pool TTL table (WinRM: 120s, PSRP: 300s)
- [ ] T036 Run full CI pipeline: `make ci` (fmt-check, lint, test, audit) with `--all-features` to verify zero regressions across all 6300+ tests
- [ ] T037 Feature gate matrix verification: run `cargo check` with each combination: no features, `winrm` only, `psrp` only, `air-gapped`, `all-protocols`, `--all-features` — all must pass cleanly

---

## Dependencies & Execution Order

### Phase Dependencies

- **Phase 1 (Setup)**: No dependencies — start immediately
- **Phase 2 (Foundational)**: Depends on Phase 1 (Cargo.toml must have deps)
- **Phase 3 (US1+US2)**: Depends on Phase 2 (config types must exist)
- **Phase 4 (US3)**: Depends on Phase 2 (config types) — can run in parallel with Phase 3
- **Phase 5 (US4)**: BLOCKED on external PR (psrp-rs russh bump)
- **Phase 6 (Polish)**: Depends on Phase 3 + Phase 4 completion

### User Story Dependencies

- **US1+US2 (WinRM Auth + Handlers)**: Depends on Foundational only. MVP target.
- **US3 (PSRP)**: Depends on Foundational only. Can parallelize with US1+US2 (different files: `src/psrp/` vs `src/winrm/`).
- **US4 (PSRP-over-SSH)**: Blocked on external dependency. Separate PR.

### Within Phase 3 (US1+US2)

```
T014 (WinRmConnection) ─┐
                         ├── T016 (ConnectionGuard) ── T017 (ExecutorRouter) ── T020 (handler verify)
T015 (WinRmPool) ────────┘
T010 (build_winrm_config) is from Phase 2, already complete
T018, T019 (unit tests) after T014, T015 respectively
T021 (cleanup bug fix) independent
```

### Within Phase 4 (US3)

```
T022 (PsrpConnection) ──┐ [P] — different files
T023 (PsrpPool) ────────┘ [P] — different files
         │
         ├── T024 (ConnectionGuard::Psrp)
         └── T025 (ExecutorRouter psrp_pool)
              │
              └── T028 (full test suite)
T026, T027 (unit tests) after T022, T023 [P]
```

### Parallel Opportunities

```
Phase 3 and Phase 4 can run in parallel:
  Agent A: T014, T015, T016, T017 (WinRM adapter)
  Agent B: T022, T023 (PSRP adapter)

Within Phase 2:
  T008 and T009 (error mappings) [P]
  T011, T012, T013 (unit tests) [P]

Within Phase 6:
  T033, T034, T035 (docs/config updates) [P]
```

---

## Implementation Strategy

### MVP First (Phase 1 + 2 + 3 = US1+US2)

1. Complete Phase 1: Setup (Cargo.toml, lib.rs)
2. Complete Phase 2: Foundational (config types, error mapping, validation)
3. Complete Phase 3: WinRM adapter replacement + handler verification
4. **STOP and VALIDATE**: `cargo test --features winrm` passes, all 44 handlers work
5. This alone fixes the critical cmd.exe bug and adds NTLMv2/Kerberos auth

### Incremental Delivery

1. MVP (Phases 1-3) -> WinRM works properly for the first time
2. Add Phase 4 (US3) -> PSRP for power users who want typed output
3. Add Phase 5 (US4) -> PSRP-over-SSH when psrp-rs aligns russh (separate PR)
4. Polish (Phase 6) -> Docs, config examples, CI verification

### Task Summary

| Phase | Tasks | Parallel | Story |
|-------|-------|----------|-------|
| Setup | T001-T003 | 0 | — |
| Foundational | T004-T013 | 4 | — |
| US1+US2 (WinRM) | T014-T021 | 2 | P1 MVP |
| US3 (PSRP) | T022-T028 | 4 | P2 |
| US4 (SSH) | T029-T032 | 0 | P3 DEFERRED |
| Polish | T033-T037 | 3 | — |
| **Total** | **37** | **13** | |

---

## Notes

- [P] tasks = different files, no dependencies on incomplete tasks
- US1+US2 merged because replacing WinRM adapter with `run_powershell()` automatically fixes all 44 handlers
- US4 is DEFERRED — requires psrp-rs to bump russh from 0.49 to 0.58 first
- Registry test counts (T034) only needed if tool count changes — likely no change here since we're replacing adapters, not adding tools
- The `reqwest` and `quick-xml` direct dependencies can be removed from Cargo.toml once winrm-rs is in place (winrm-rs brings its own reqwest internally)
