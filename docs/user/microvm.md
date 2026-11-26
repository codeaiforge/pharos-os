# Running Pharos as a microVM

## Status

This guide is for v0.5, the microVM release (M5.5). It covers verifying a release, setting up a VM for it, booting it, using the trusted console, and exporting and checking the audit trail. Every command in it was run on the development host on 2026-11-20, as two boots of one VM with an export between them and a rotation in the second: under KVM on a release built at `0c7b5d3`, before Secure Boot; and with the Secure Boot firmware and variable store on a release built with `--secure-boot` and test keys (#258), under TCG, because another hypervisor held the CPU's virtualization then. At the v0.5 gate (#261) sections 2 to 6 were run again under KVM on the signed v0.5.0 release, with the Secure Boot firmware and the maintainer's keys.

| Part | State |
| --- | --- |
| Verifying a release's files and signature (`cargo xtask release verify`) | **implemented** (#259); v0.5.0 is the first signed release, and its public key is `RELEASE-KEY` in the repository (#261) |
| Booting a release in QEMU with KVM, a device key per VM, and the trusted console | **implemented** (D-047, D-049) |
| The audit trail: checking it, warnings as it fills, export, and rotation | **implemented** (D-047, D-048) |
| Secure Boot: Limine signed with Pharos's `db` key, and the variable store `OVMF_VARS_4M.pharos.fd` with Pharos's keys | **implemented** (#258) |
| A model for local inference in the release image | **planned**. The release image has no model; S1 runs it in a test kernel ([testing.md](../development/testing.md#s1-end-to-end)) |
| Other VMMs (Cloud Hypervisor, Firecracker) and bare metal | **untested** |

## 1. What you need

- A host that meets the [reference platform](../development/reference-platform.md): Linux with KVM, QEMU 8.2, OVMF, and a CPU the kernel accepts. Its section "Checking a host" says how to check one.
- A checkout of this repository at the release's tag, for `cargo xtask` (the verifier and the export run on the host; see [setup.md](../development/setup.md)).
- `mkfifo` (coreutils), for the trusted console.

## 2. Get and verify the release

A release is a directory with `pharos-<version>.iso`, `disk.img`, `store.img`, `OVMF_VARS_4M.pharos.fd`, `BUILDINFO`, `SHA256SUMS`, and `SHA256SUMS.sig` ([release-integrity.md](../architecture/release-integrity.md#6-signed-release-artifacts-259)).

```sh
cargo xtask release verify <RELEASE_DIR> --key RELEASE-KEY
```

It checks the signature against the maintainer's public key in `RELEASE-KEY`, then every file, and prints the boot measurement. Keep that measurement: every audit head the VM signs carries the one its boot measured (section 5).

Or build the release yourself from the same commit and compare. Two builds give the same `SHA256SUMS`:

```sh
cargo xtask release          # target/xtask/release/<version>/
diff target/xtask/release/<version>/SHA256SUMS <RELEASE_DIR>/SHA256SUMS
```

`BUILDINFO` names the commit and the compiler; `rust-toolchain.toml` pins the compiler, so a checkout of the tag uses the same one. Your build has no Secure Boot signature, so its ISO differs from the release's in Limine's signature only, and it has no variable store: compare the rest of `SHA256SUMS`, and Limine with its signature removed ([release-integrity.md](../architecture/release-integrity.md#5-secure-boot-258)).

## 3. Set up a VM

Each VM gets its own directory with four files. The release's files stay read-only and shared.

```sh
mkdir vm1 && cd vm1
(umask 077; head -c 32 /dev/urandom > device.key)
cp <RELEASE_DIR>/store.img store.img
cp <RELEASE_DIR>/OVMF_VARS_4M.pharos.fd vars.fd
mkfifo trust.in trust.out
```

| File | What it is |
| --- | --- |
| `device.key` | The VM's device secret: 32 random bytes, which the kernel reads once at boot (D-047). Without it the kernel refuses to boot. |
| `store.img` | The VM's writable store: the audit trail, the knowledge service, agent tasks, the slot record. A copy per VM. |
| `vars.fd` | OVMF's variable store with Pharos's Secure Boot keys enrolled and Secure Boot on, written by the firmware as it runs. A copy per VM. |
| `trust.in`, `trust.out` | The trusted console's input and output (D-018). |

**The device key.** Keep it for as long as you keep the VM's trails, readable by you only:
- every audit head is signed with a key derived from it, so the verifier needs it (`--key device.key`), and a lost key means old trails can no longer be checked as signed;
- anyone holding it can sign a false trail for this VM, so it is as sensitive as the trail;
- never share one between VMs, and never put it in the release directory (`cargo xtask release` never copies the build host's key).

## 4. Boot

From the VM's directory, with `R` the release directory:

```sh
R=<RELEASE_DIR>
qemu-system-x86_64 -M q35,smm=on -enable-kvm -cpu host -m 256M \
  -global driver=cfi.pflash01,property=secure,value=on \
  -device intel-iommu,intremap=off \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd \
  -drive if=pflash,format=raw,file=vars.fd \
  -cdrom $R/pharos-*.iso \
  -fw_cfg name=opt/org.pharos/device-key,file=device.key \
  -drive if=none,id=disk0,format=raw,readonly=on,file=$R/disk.img \
  -device virtio-blk-pci,drive=disk0,disable-legacy=on,iommu_platform=on \
  -drive if=none,id=disk1,format=raw,file=store.img \
  -device virtio-blk-pci,drive=disk1,disable-legacy=on,iommu_platform=on \
  -nic none -netdev user,id=net0 \
  -device virtio-net-pci,netdev=net0,disable-legacy=on,iommu_platform=on \
  -chardev pipe,id=trust,path=trust \
  -device virtio-serial-pci,disable-legacy=on,iommu_platform=on \
  -device virtconsole,chardev=trust \
  -object rng-random,id=rng0,filename=/dev/urandom \
  -device virtio-rng-pci,rng=rng0,disable-legacy=on,iommu_platform=on \
  -display none -serial file:serial.log
```

What each part is for:
- **`smm=on`, the secure flash, `OVMF_CODE_4M.secboot.fd`, and `vars.fd`:** OVMF with Secure Boot on and only Pharos's keys enrolled. The firmware boots Limine only with Pharos's signature, and Limine boots the kernel and the factory image only if their hashes match its configuration, whose own hash is in the signed Limine (#258). A changed file stops the boot on the screen, before the kernel, and nothing reaches `serial.log`.
- **`-enable-kvm -cpu host`:** the kernel checks the host CPU's real `IA32_ARCH_CAPABILITIES` and refuses a CPU affected by Meltdown or MDS (D-044).
- **`intel-iommu`, before the devices, and `iommu_platform=on` on each:** every device's DMA goes through the IOMMU; without one the kernel refuses to boot (#242).
- **The first disk, `disk.img`, read-only; the second, `store.img`:** the storage service takes the second virtio-blk device, so keep this order.
- **`-netdev user`:** user-mode networking, which needs no host privileges. The guest is 10.0.2.15; agents get no network unless granted (D-012).
- **`-chardev pipe ... path=trust`:** the trusted console, on `trust.in` and `trust.out`.
- **`virtio-rng-pci`, last:** the host's randomness for the TLS service's seed (tls.md, #271); the boot table does not start that service in M6.1, so a VM without it still boots. Keep it after the other devices so their PCI order stays the same.
- **No `opt/org.pharos/boot-check`:** without it the system keeps running after its boot (D-049). `cargo xtask test` passes it so that a boot check ends.

The kernel's log goes to `serial.log`. A boot that worked ends with:

```text
  services:   8 ready, 0 failed, from the factory image
PHAROS: boot ok
  running:    until the VM is stopped
```

A boot that did not work ends with `PHAROS: boot failed: <reason>`, and QEMU stops.

**Stopping the VM:** stop QEMU, with Ctrl+C in its terminal or `kill <pid>`. Pharos has no shutdown command yet. The store is crash-consistent: what was committed stays, and a record being written when QEMU stopped is lost.

## 5. The trusted console

*Unreleased (#310, M6.5; not in v0.5):* the console answers only `login <name>`, the stops (`stop all`, `stop <agent>`, `stop group <group>`, `stop service <service>`), and `help` until someone logs in. Before the first boot, seed the store with its first administrator: `cargo xtask identity first <name> --store store.img` asks for the passphrase twice; then type `login <name>` and the passphrase on the console. See [identity.md](../architecture/identity.md).

The trusted console is the only place where you approve or stop what agents do; no agent can read or write it (D-018). In a second terminal:

```sh
cat trust.out
```

In a third, type a command:

```sh
echo list > trust.in
```

With no agents yet, `trust` answers `runtime running` and `no agents`.

Under UEFI, OVMF's own boot messages appear on the console first. Then `trust` says:

```text
trust: ready; commands: list, stop <agent>, ...
audit: boot 1, 9 records, head 687df7bb...
audit: 9 of 9 records signed, key 8f6e105e..., measured 8b903094...
```

**On the first boot, check two things:**
1. `measured` is the boot measurement `release verify` printed. A different value means the VM did not boot the release's files.
2. `key` is the VM's audit public key. Record it; the host computes the same key from the device key (section 6).

A line `trust` does not know prints the list of commands. Agents, permissions, and approvals are in [agents.md](../architecture/agents.md) and [capabilities.md](../architecture/capabilities.md).

## 6. The audit trail

Every grant, approval, and consequential action is a record in the audit trail, one stream per boot, each record chained to the one before by SHA-256 and the chain's head signed after each record ([capabilities.md](../architecture/capabilities.md), [release-integrity.md](../architecture/release-integrity.md#4-the-signed-audit-head-256-and-the-slot-record-257)).

**Checking it**, with the VM stopped:

```sh
cargo xtask store audit store.img --key device.key
```

It checks every stream's records, chain, and signed head, prints the records, then `audit key <hex>`, which must be the key `trust` showed, and each stream's boot measurement. A trail rewritten on the disk, even with its chain recomputed, fails, because its head's signature no longer matches.

*Unreleased (#312, M6.5):* add `--resolve` to print after each record who did it, from the trail alone: `person alice`, `agent fetcher (owner alice)`, `service tls`, `init`, `the console, no one logged in`, or `the console, before identities` (records from before M6.5, actor `user`). It fails if a record does not resolve.

**As it fills:** at 80% and 95% of the space the trail may use, `trust` says `audit: the trail is <n>% full; export it on the host (cargo xtask store export), then audit rotate <code>`. When it is full, actions that need a record are refused; records are never dropped to make room (D-048).

**Exporting and rotating:**
1. Stop the VM, then export every stream into a new directory:
   ```sh
   cargo xtask store export store.img export-1 --key device.key
   ```
   It checks each stream against its signed head first, writes `export-1/audit.img` and `export-1/EXPORT`, and prints `audit rotate <code>`.
2. Boot the VM again and type that line on the trusted console. The service frees the streams of the earlier boots if the code matches, and records the rotation in the current stream:
   ```text
   audit: rotated; 1 earlier streams freed, and the new stream names the export
   ```
   A code that matches no export is refused, and the current boot's stream is never freed.
3. Later, check the export and its link to the VM's trail, with the VM stopped:
   ```sh
   cargo xtask store audit store.img --key device.key --archive export-1
   ```

Keep `export-1/` with the device key: the export's heads are signed by it.

## 7. What this guide does not cover

- Updates of the system image (`update propose` and `apply`, [boot.md](../architecture/boot.md)), safe mode and recovery.
- Several VMs from one release: give each its own directory as in section 3.
- A model in the image, planned.
- Booting with Secure Boot off (the distribution's `OVMF_CODE_4M.fd` and `OVMF_VARS_4M.fd`) works too, but then nothing checks Limine, and a changed Limine could skip the checks of the kernel and the factory image.
