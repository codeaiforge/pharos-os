# Release integrity: the device secret, the signed audit head, and Secure Boot

## Status

**Draft, awaiting the maintainer's approval** (#254, M5.5). It implements [D-047](../project/decision-log.md#d-047-release-integrity-the-device-secret-the-audit-anchor-secure-boot-and-signed-artifacts) (accepted 2026-11-18). Nothing here is implemented yet; each part is **planned** until its issue lands:

| Part | Issue |
| --- | --- |
| The device secret and the `Key` capability | #255 |
| The signed audit head | #256 |
| The slot record's MAC | #257 |
| Secure Boot | #258 |
| Signed release artifacts | #259 |
| Export and rotation of the audit trail | #217 |

## 1. What it protects, and from whom

**The attacker** holds the disk images (`disk.img`, `store.img`) or the boot medium, but not the host. They can read and rewrite every byte, then boot the images in a VM of their own.

**Goals:**
1. A rewritten audit trail is rejected by a verifier outside Pharos, even when the rewrite keeps the SHA-256 chain consistent. This is M5.5's acceptance criterion.
2. A rewritten slot record is refused by `init`.
3. A changed kernel, module, or Limine configuration does not boot.
4. A user can check that a release is the one the maintainer built and signed.

**Not goals:**
- A host that is not trusted. On the reference platform the host's VM configuration is in the trusted base (D-036, D-044).
- Rolling the trail back to an older genuine copy. Detecting that needs an anchor outside the system (M6.7) or a monotonic counter (a TPM, M8.1).

## 2. The device secret (#255)

- **Source:** 32 random bytes per VM, which the host passes as the `fw_cfg` file `opt/org.pharos/device-key` (`-fw_cfg name=opt/org.pharos/device-key,file=<path>`).
  - QEMU's interface: selector port 0x510, data port 0x511, the file directory at key 0x19, 64-byte big-endian entries (QEMU's `docs/specs/fw_cfg.rst`).
  - The kernel reads it with port I/O only, not `fw_cfg`'s DMA interface, so the IOMMU is not involved.
- **Read once:** the kernel reads the key at boot, before `init` starts. It keeps it in one static that only the `Key` code reads.
- **Who else can reach it:** user space cannot do port I/O (the `user_mode` probe faults), so after boot only the kernel can read the item. A guest kernel that is not Pharos's could read it too. Secure Boot (section 5) is what keeps other kernels from booting in the VM.
- **No key, or a key of the wrong size:** the boot fails with `PHAROS: boot failed: no device key (opt/org.pharos/device-key, D-047)`. This fails closed, as a missing IOMMU does (#242).
- **`xtask`:**
  - makes `target/xtask/keys/device.key` from `/dev/urandom` on first use, as for the update-signing test key;
  - passes the key to every QEMU it starts;
  - lets a test kernel ask to run without it, as `without_iommu` does, for the refusal check.
- **Key files:** the host keeps one file per VM. The user guide (#260) says how; losing the file means old trails can no longer be verified as signed.

### Derived keys and the `Key` capability

The secret itself never leaves the kernel. The kernel derives one 32-byte key per purpose with HMAC-SHA256, the extract-then-expand of RFC 5869 with a fixed label and no salt:

| Purpose | Label | Used by | For |
| --- | --- | --- | --- |
| `AuditAnchor` | `pharos audit anchor v1` | `audit` | the Ed25519 seed that signs the head |
| `SlotRecord` | `pharos slot record v1` | `init` | the HMAC key of the slot record |

**How a derived key reaches only `audit` and `init`:** the kernel does not know which process is `audit` (processes have no name). So the key is a capability, `Object::Key(Purpose)`, passed the same way every other authority is:
- the kernel gives `init` one `Key` capability per purpose at boot, with `init`'s other boot capabilities;
- `init` keeps `SlotRecord` for itself;
- `init` passes `AuditAnchor` to `audit` through a new manifest entry, `Give::Key(AuditAnchor)`;
- the capability audit (D-027) checks that `audit`'s holding matches its manifest, so no other service holds it;
- it cannot be derived further.

**One new system call, `key_read(handle) -> [u8; 32]`:** it returns the derived key, never the secret. A process that holds the key holds what it protects. A compromised `audit` could sign a false head; that is the same trust `audit` already has as the trail's only writer.

**New trusted code:**
- a SHA-256 and HMAC module in a small new crate, `pharos-crypto`, which `pharos-store` re-exports and the kernel, `init`, `audit`, and `xtask` share. Its `sha256.rs` moves from `pharos-store`; HMAC is about 20 lines;
- the `fw_cfg` reader in `arch/x86_64.rs`, with `outw` added beside `outb`. The `unsafe` stays in the existing module.

## 3. Measured boot: module hashes (D-047 item 2)

**What the kernel hashes:**
- each Limine module with SHA-256 when it records the module (`storage::record_modules`: `root`, `recovery`, the model, and so on);
- its own executable file, through Limine's executable-file request (a new request; today the kernel asks only for its address).

**What it records:** the list `[(name, sha256)]` in recording order, and a single digest `boot_measurement = SHA-256(name_0 ‖ hash_0 ‖ name_1 ‖ hash_1 ‖ …)`, each name length-prefixed.

**How it is read:** a second operation on any `Key` capability, `key_measurement(handle) -> [u8; 32]`, returns the digest; `trust` shows the digest at start (a new line; `trust` has no `boot` command today).

**Cost:** hashing the 676 MB model is estimated at a few seconds of S1's boot under KVM (to measure in #256). The model is the large module; if this matters, the model's hash is taken from the store's own CRC, or the model is measured lazily on first use. That is a choice to make once it is measured (#256).

**How a verifier uses it:** it compares `boot_measurement` with the digest the release publishes in `SHA256SUMS` (section 6). A head signed by a boot chain that is not the release's carries a different digest. With Secure Boot enforced, such a chain cannot run in the first place.

## 4. The signed audit head (#256) and the slot record (#257)

### Head

After each append it commits, `audit` writes `audit/head/<boot>` (one store `Write`, in the audit namespace and its reserve), 160 bytes:

| Bytes | Field |
| --- | --- |
| 0..8 | magic `PHAROSAH` |
| 8..12 | version 1 |
| 12..16 | boot (the stream `log/<boot>`) |
| 16..24 | records |
| 24..56 | chain head |
| 56..88 | `boot_measurement` |
| 88..96 | uptime in µs |
| 96..160 | Ed25519 signature over bytes 0..96, with the seed `key_read(AuditAnchor)` |

- **Signing:** `ed25519-compact` is already linked into user programs through `pharos-image` and signs without `std`.
- **Cost:** one signature and one extra store write per record. To measure (#256); if a write per record is too slow, the head is written every N records and on each `HEAD` request, and the records past the last signed head are reported as unsigned by the verifier.
- **`HEAD` answer and `trust`:** `HEAD` returns the signed head, and `trust`'s `audit` prints its signature status (`signed`).

### Public key

No enrollment boot is needed: the host holds the secret, so it can compute the public key. `cargo xtask key public <device.key>` prints it: derive `AuditAnchor`, take Ed25519's public key from that seed. `trust` prints the same key at start, for the user to compare.

### Verifier

`cargo xtask store audit <IMAGE> --key <public key or device.key>` additionally checks, for each `log/<n>`:
- `head/<n>` exists;
- its signature verifies;
- its `records` and chain head equal the stream's (a stream longer than its signed head is reported as unsigned past it);
- optionally, its `boot_measurement` equals the release's (`--release <SHA256SUMS>`).

Without `--key`, it checks the chain alone and says it did not check signatures.

### Slot record

Version 2 of `system/state` appends a 32-byte HMAC-SHA256 over bytes 0..112, keyed with `key_read(SlotRecord)`, replacing the CRC-32 (148 bytes in all).
- **A version 1 record:** treated as corrupt (rewritten empty). Accepting it would let an attacker downgrade to an unauthenticated record. The version floor then falls to the factory image's, as for any corrupt record today. This happens once, on the first boot of v0.5.
- **What stays open:** someone holding the disk can still erase the record, or put back an older genuine one: a rollback to an older slot version. Fixing that needs a monotonic counter (a TPM, M8.1). The threat model's row is narrowed to this.

## 5. Secure Boot (#258)

The chain the M4.3 evaluation showed holds ([boot-evaluation.md](boot-evaluation.md#secure-boot-evaluation-166-d-028)): a Limine signed with `sbsign`, the BLAKE2b hash of `limine.conf` enrolled into the Limine binary, and a BLAKE2b hash on every `path:` and `module_path:`. In that order, since enrolling changes the binary.

- **Keys:** Pharos's PK, KEK, and db, X.509 certificates with RSA-2048 keys made with `openssl`. The db key signs Limine.
  - **Release:** the maintainer holds the PK and db keys offline (D-047 item 3).
  - **CI and tests:** a test key in `target/xtask/keys/secureboot/`, made on first use. It is never used for a release; `xtask release` refuses it.
- **Variable store:** each release ships `OVMF_VARS_4M.pharos.fd`, with Pharos's PK, KEK, and db enrolled and Secure Boot on. The user boots with it and `OVMF_CODE_4M.secboot.fd` (`-M q35,smm=on`, `cfi.pflash01` secure).
- **Enrolling keys into a variable store needs a tool.** The host has none (`virt-fw-vars` is not installed; `efitools` is not either). **Open question 1** below.
- **`xtask`:** `cargo xtask image --secure-boot` (and CI) adds the hashes, enrolls the config hash, and signs `BOOTX64.EFI` in both places (`EFI/BOOT/` and the El Torito image). The unsigned ISO stays the default for development.
- **CI boot checks:** a signed image boots; a changed kernel byte, a changed module byte, and a changed `limine.conf` are each refused. Limine reports these on the framebuffer only, so the check is that no `PHAROS` line appears on serial before a timeout, plus a QMP `screendump` kept with the logs. A throwaway branch that skips the path hashes must fail this check.
- **Reproducibility:** Limine signing is deterministic, and `sbattach --remove` gives back the unsigned binary, so anyone can compare a release's Limine with their own build.

## 6. Signed release artifacts (#259)

- **`cargo xtask release <version>`** builds `pharos-<version>.iso` (Secure Boot hashes in, Limine not yet signed), `OVMF_VARS_4M.pharos.fd`, and `SHA256SUMS`. `SHA256SUMS` lists each file and adds a `boot-measurement <hex>` line (section 3).
- **`cargo xtask release sign --db-key <file> --release-key <file>`**, on the maintainer's machine:
  1. signs Limine;
  2. rebuilds the ISO;
  3. rewrites `SHA256SUMS`;
  4. signs it with the release key (Ed25519, through `pharos-image`'s signing), giving `SHA256SUMS.sig`.
- **Verifying:** `cargo xtask release verify <dir> --key <release public key>`. The release public key is published in the repository (`RELEASE-KEY`) and in the user guide.
- **Two independent builds:** CI builds the unsigned release; the maintainer builds it locally; both `SHA256SUMS` (before signing) must be equal, and both are recorded at the gate. CI's reproducibility check today compares the ISO only; it is extended to `disk.img`, `store.img`, and the variable store.

## 7. Tests

| Test | What it shows | Throwaway branch that must fail CI |
| --- | --- | --- |
| `device_key` (new test kernel) | the key is read and derived as the host derives it (`xtask` passes a known key; the test kernel checks `key_read` against values computed on the host); a fifth boot check without the key is refused | the kernel ignores the key and uses zeros |
| `anchor` (new test kernel) | `audit` writes signed heads; the image is then checked on the host by `cargo xtask store audit --key`; a trail rewritten consistently (records changed, the chain recomputed) is rejected; a trail with a correct signed head passes | the verifier skips the signature check |
| `recovery` or `update` | a slot record rewritten with a correct CRC but a wrong MAC is refused and rewritten empty; the version floor holds for a genuine one | `init` skips the MAC check |
| Secure Boot boot checks (section 5) | the signed image boots; a changed kernel, module, or config does not | the path hashes left out |
| `pharos-crypto` host tests | SHA-256 against FIPS 180-4 vectors (moved), HMAC-SHA256 against RFC 4231, HKDF against RFC 5869 | — |
| `xtask` host tests | release signing and verification round trip; a changed file fails | — |

## 8. Open questions for the maintainer

1. **Enrolling Secure Boot keys into OVMF's variable store:** (a) `virt-fw-vars` from the `virt-firmware` Python package, installed by the maintainer and in CI (a build-time host tool, not part of Pharos); or (b) a small variable-store writer in `xtask` (edk2's authenticated-variable format, written directly into the file as `virt-fw-vars` does; more code, no new tool). **Recommendation: (a)**, with its licence and maintenance status recorded before use (AGENTS.md section 6).
2. **A missing device key:** fail closed (recommended, as above), or boot with signing off and say so on the trusted console.
3. **Signing the head on every append,** if it proves too slow under TCG: every N records plus on request, with unsigned records past the last signed head reported by the verifier.

## 9. Virtual TPM (evaluated, kept for M8.1)

Sealing the secret to PCRs needs a TPM 2.0 driver (CRB, commands, sessions) in the kernel, and measurements from the firmware and Limine. A kernel's measurement of itself proves nothing to a tampered kernel. It also needs `swtpm` on every host and in CI. It would remove the trust in the host's key file, but not in the host itself, which the reference platform trusts anyway. On bare metal (M8.1), with a real TPM and no trusted host, it becomes the way.
