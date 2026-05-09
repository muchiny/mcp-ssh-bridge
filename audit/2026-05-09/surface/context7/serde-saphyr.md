# serde-saphyr — upstream guidance (context7)

- Query date: 2026-05-09
- libraryId: `/bourumir-wyngs/serde-saphyr`
- Topic: `deny unknown fields untagged enum yaml safety billion laughs anchors aliases recursion limit panic-free deserialize`
- context7 server: Upstash `@upstash/context7-mcp@latest`

## Notes on substitution

The plan's original target #10 was `serde_yaml`, but `mcp-ssh-bridge` has migrated its YAML loader to **`serde-saphyr`** (per `CLAUDE.md` § "Config YAML Adapter"). `serde_yaml` is unmaintained as of 2024-04 — switching was the right call. This file documents the migrated loader's surface.

## Key takeaways

1. **`from_str` / `from_slice` / `from_reader`** — three entry points. The byte-slice variant supports zero-copy borrowing. The reader variant only accepts `DeserializeOwned`.
2. **`Options` and `Budget` are the safety knobs.** `from_str_with_options(yaml, opts)` lets you pin:
   - `duplicate_keys: DuplicateKeyPolicy::{LastWins, Error, FirstWins}` — default behavior is implementation-defined; explicit policy is safer.
   - `strict_booleans: true` — rejects YAML 1.1 fuzzy booleans (`yes`/`no`/`on`/`off`).
   - `budget: { max_anchors, max_depth, max_nodes, max_reader_input_bytes }` — caps protect against billion-laughs / depth-recursion / oversize input.
3. **YAML anchors / aliases (the billion-laughs vector)** are bounded by `max_anchors` and `max_nodes`. Without an explicit `Budget`, the defaults apply — verify those defaults in the saphyr source.
4. **`include` / `include_fs`** features splice external files into the YAML tree. If we use them, untrusted YAML can pull in arbitrary readable files — confirm we only use them in trusted-config code paths.
5. **`properties`** feature provides env-var substitution (`${VAR}`). This is a side channel for secrets exfiltration if untrusted YAML is parsed with this feature on.
6. **Strong typing acts as schema** — `#[derive(Deserialize)]` rejects unknown keys by default in saphyr (unlike serde_yaml which is lenient). Combined with `#[serde(deny_unknown_fields)]` for belt-and-suspenders.

## Audit checklist for `mcp-ssh-bridge`

- [ ] `src/config/loader.rs`: confirm we call `from_str_with_options` (NOT `from_str`) with an explicit `Budget` containing `max_depth`, `max_anchors`, `max_nodes`, and `max_reader_input_bytes` for the config file size.
- [ ] Confirm `#[serde(deny_unknown_fields)]` on `Config` and every nested struct in `src/config/types.rs`.
- [ ] `#[serde(rename_all = "snake_case")]` and consistent field naming — strict-typed configs catch typos that lenient parsers swallow.
- [ ] If runbook YAML (`config/runbooks/*.yaml`) flows through the same loader: is the runbook source ever from a remote host? If yes, runbook schema also needs `deny_unknown_fields` + Budget.
- [ ] grep for `serde_yaml::` — must be zero matches; confirm the migration to saphyr is complete.

## Raw response excerpt

```rust
let options = serde_saphyr::options! {
    duplicate_keys: DuplicateKeyPolicy::LastWins,
    strict_booleans: true,
    budget: serde_saphyr::budget! {
        max_anchors: 100,
        max_depth: 50,
    },
};

let cfg: Config = serde_saphyr::from_str_with_options(yaml, options).unwrap();
```

```rust
let opts = serde_saphyr::options! {
    budget: serde_saphyr::budget! {
        max_reader_input_bytes: Some(1024 * 1024), // 1 MiB cap
    },
};
```
