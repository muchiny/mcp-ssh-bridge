# Contract: Configuration Schema

**Files**: `src/config/types.rs`, `config/config.example.yaml`

## YAML Schema for WinRM Hosts

```yaml
hosts:
  <host-name>:
    hostname: <string>          # Required: IP or FQDN
    port: <u16>                 # Default: 5986 (HTTPS) or 5985 (HTTP)
    user: <string>              # Required: Windows username
    os_type: windows            # Required for Windows tools
    protocol: winrm             # Required: selects WinRM adapter
    auth:
      type: ntlm               # ntlm | password | certificate | kerberos
      password: <string>        # Required for ntlm/password
      domain: <string>          # Optional: NTLM domain (e.g., "CORP")
      cert_path: <string>       # Required for certificate
      key_path: <string>        # Required for certificate
    # WinRM-specific options (all optional):
    winrm_use_tls: <bool>       # Default: auto (true if port=5986)
    winrm_accept_invalid_certs: <bool>  # Default: false
    winrm_operation_timeout_secs: <u64> # Default: 60
    winrm_max_envelope_size: <u32>      # Default: 153600
```

## YAML Schema for PSRP Hosts

```yaml
hosts:
  <host-name>:
    hostname: <string>
    port: <u16>                 # Same as WinRM (uses WinRM transport)
    user: <string>
    os_type: windows
    protocol: psrp              # Selects PSRP adapter
    auth:                       # Same auth options as WinRM
      type: ntlm
      password: <string>
      domain: <string>
    # Same winrm_* options apply (PSRP uses WinRM transport)
    winrm_use_tls: true
```

## YAML Schema for PSRP over SSH (Phase 4)

```yaml
hosts:
  <host-name>:
    hostname: <string>
    port: 22
    user: <string>
    os_type: windows
    protocol: ssh
    shell: psrp                 # NEW: triggers PSRP-over-SSH transport
    auth:
      type: key
      path: ~/.ssh/id_ed25519
```

## Validation Rules

| Rule | Error Message |
|------|---------------|
| `protocol: winrm` + `auth.type: key` | "WinRM does not support SSH key authentication" |
| `protocol: winrm` + `auth.type: agent` | "WinRM does not support SSH agent authentication" |
| `protocol: winrm` + `proxy_jump: some` | "WinRM does not support SSH proxy jump" |
| `protocol: psrp` + `auth.type: key` | "PSRP over WinRM does not support SSH key auth" |
| `winrm_use_tls: false` + `auth.type: password` | WARNING: "Basic auth over plain HTTP exposes credentials" |
| `protocol: psrp` feature not enabled | "PSRP protocol requires the 'psrp' feature" |

## Cargo.toml Feature Schema

```toml
[features]
winrm = ["dep:winrm-rs"]
psrp = ["dep:psrp-rs", "winrm"]

[dependencies]
winrm-rs = { version = "1.0", optional = true }
psrp-rs = { version = "1.0", optional = true, default-features = false }
```

Note: psrp-rs is imported **without** `ssh` feature by default. The PSRP-over-SSH
transport (Phase 4) would add `psrp-rs/ssh` but requires russh 0.58 alignment first.
