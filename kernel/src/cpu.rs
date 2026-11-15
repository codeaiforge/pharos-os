//! Whether this CPU may run Pharos (D-044 item 1).
//!
//! Every address space maps the kernel half, and with it the direct map of
//! all memory, so on a CPU affected by Meltdown (or MDS) a process could
//! read other processes' memory by speculation. Pharos has no KPTI (D-044:
//! it broke D-004's IPC budget), so it refuses to boot on such a CPU and
//! says why. KPTI is carried to M8.1 for older bare metal.

/// What the CPU reports, read by [`crate::arch::x86_64::cpu_identity`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    /// CPUID leaf 0's vendor string.
    pub vendor: [u8; 12],
    /// The hypervisor's signature (CPUID leaf 0x4000_0000), if CPUID.1:ECX
    /// bit 31 says there is one.
    pub hypervisor: Option<[u8; 12]>,
    /// `IA32_ARCH_CAPABILITIES` (MSR 0x10A), if CPUID.7.EDX bit 29 says it
    /// exists.
    pub arch_capabilities: Option<u64>,
}

/// `IA32_ARCH_CAPABILITIES` bit 0: not affected by Meltdown (rogue data
/// cache load) or L1TF.
pub const RDCL_NO: u64 = 1 << 0;
/// `IA32_ARCH_CAPABILITIES` bit 5: not affected by MDS.
pub const MDS_NO: u64 = 1 << 5;

/// Why the CPU may run Pharos.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Allowed {
    /// QEMU's TCG: guest code never runs natively, so nothing leaks by
    /// speculation.
    Tcg,
    /// AMD and Hygon are not affected by Meltdown or MDS.
    Amd,
    /// Intel, reporting `RDCL_NO` and `MDS_NO`.
    IntelNotAffected,
}

/// Why it may not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// Neither AMD, Hygon, nor Intel.
    UnknownVendor,
    /// Intel without `IA32_ARCH_CAPABILITIES`: it cannot say it is not
    /// affected.
    NoArchCapabilities,
    /// Intel affected by Meltdown or L1TF.
    NoRdclNo,
    /// Intel affected by MDS.
    NoMdsNo,
}

impl Refused {
    /// What is missing, for the boot message.
    pub fn reason(self) -> &'static str {
        match self {
            Self::UnknownVendor => "the vendor is not AMD, Hygon, or Intel",
            Self::NoArchCapabilities => {
                "it has no IA32_ARCH_CAPABILITIES to report RDCL_NO and MDS_NO"
            }
            Self::NoRdclNo => "IA32_ARCH_CAPABILITIES lacks RDCL_NO (Meltdown, L1TF)",
            Self::NoMdsNo => "IA32_ARCH_CAPABILITIES lacks MDS_NO (MDS)",
        }
    }
}

/// The D-044 rule: TCG, AMD or Hygon, or Intel with `RDCL_NO` and
/// `MDS_NO`; anything else is refused (fail closed).
pub fn check(id: &Identity) -> Result<Allowed, Refused> {
    if id.hypervisor == Some(*b"TCGTCGTCGTCG") {
        return Ok(Allowed::Tcg);
    }
    match &id.vendor {
        b"AuthenticAMD" | b"HygonGenuine" => Ok(Allowed::Amd),
        b"GenuineIntel" => {
            let caps = id.arch_capabilities.ok_or(Refused::NoArchCapabilities)?;
            if caps & RDCL_NO == 0 {
                Err(Refused::NoRdclNo)
            } else if caps & MDS_NO == 0 {
                Err(Refused::NoMdsNo)
            } else {
                Ok(Allowed::IntelNotAffected)
            }
        }
        _ => Err(Refused::UnknownVendor),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(vendor: &[u8; 12], hypervisor: Option<&[u8; 12]>, caps: Option<u64>) -> Identity {
        Identity {
            vendor: *vendor,
            hypervisor: hypervisor.copied(),
            arch_capabilities: caps,
        }
    }

    #[test]
    fn tcg_runs_whatever_model_it_shows() {
        let tcg = Some(b"TCGTCGTCGTCG");
        assert_eq!(check(&id(b"GenuineIntel", tcg, None)), Ok(Allowed::Tcg));
        assert_eq!(check(&id(b"AuthenticAMD", tcg, None)), Ok(Allowed::Tcg));
    }

    #[test]
    fn amd_and_hygon_run() {
        assert_eq!(check(&id(b"AuthenticAMD", None, None)), Ok(Allowed::Amd));
        assert_eq!(check(&id(b"HygonGenuine", None, None)), Ok(Allowed::Amd));
        assert_eq!(
            check(&id(b"AuthenticAMD", Some(b"KVMKVMKVM\0\0\0"), None)),
            Ok(Allowed::Amd)
        );
    }

    #[test]
    fn intel_needs_both_bits() {
        let kvm = Some(b"KVMKVMKVM\0\0\0");
        let intel = |caps| check(&id(b"GenuineIntel", kvm, caps));
        assert_eq!(intel(Some(RDCL_NO | MDS_NO)), Ok(Allowed::IntelNotAffected));
        assert_eq!(
            intel(Some(RDCL_NO | MDS_NO | 1 << 8)),
            Ok(Allowed::IntelNotAffected)
        );
        assert_eq!(intel(None), Err(Refused::NoArchCapabilities));
        assert_eq!(intel(Some(0)), Err(Refused::NoRdclNo));
        assert_eq!(intel(Some(MDS_NO)), Err(Refused::NoRdclNo));
        assert_eq!(intel(Some(RDCL_NO)), Err(Refused::NoMdsNo));
    }

    #[test]
    fn a_hypervisor_signature_other_than_tcg_proves_nothing() {
        let kvm = Some(b"KVMKVMKVM\0\0\0");
        assert_eq!(
            check(&id(b"GenuineIntel", kvm, None)),
            Err(Refused::NoArchCapabilities)
        );
        assert_eq!(
            check(&id(b"GenuineIntel", Some(b"TCGTCGTCGTC\0"), Some(0))),
            Err(Refused::NoRdclNo)
        );
    }

    #[test]
    fn other_vendors_are_refused() {
        for vendor in [b"CentaurHauls", b"  Shanghai  ", b"GenuineIotel", &[0; 12]] {
            assert_eq!(
                check(&id(vendor, None, Some(RDCL_NO | MDS_NO))),
                Err(Refused::UnknownVendor)
            );
        }
    }
}
