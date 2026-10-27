//! Limine boot protocol structures (decision D-001), base revision 6.
//!
//! Written by hand from the Limine protocol specification (0BSD,
//! <https://github.com/limine-bootloader/limine-protocol/blob/trunk/PROTOCOL.md>)
//! instead of depending on the `limine` crate. Section names below refer to
//! that specification. Only the features the kernel uses are defined.
//!
//! The bootloader writes request responses and the base-revision tag before
//! the kernel runs. Those fields are wrapped in [`BootWritten`] and read with
//! volatile loads, because the compiler cannot see those writes.

#![allow(unsafe_code)]

use core::cell::UnsafeCell;
use core::ffi::{CStr, c_char};
use core::sync::atomic::{AtomicBool, Ordering};

/// Base revision this kernel is written against ("Base Revisions").
pub const BASE_REVISION: u64 = 6;

/// First two words of every request ID ("Features", `LIMINE_COMMON_MAGIC`).
const COMMON_MAGIC: [u64; 2] = [0xc7b1dd30df4c8b88, 0x0a82e883a194f07b];

/// "Requests Delimiters": start marker.
pub const REQUESTS_START_MARKER: [u64; 4] = [
    0xf6b8f4b39de7d1ae,
    0xfab91a6940fcb9cf,
    0x785c6ed015d3e316,
    0x181e920a7852b9d9,
];

/// "Requests Delimiters": end marker.
pub const REQUESTS_END_MARKER: [u64; 2] = [0xadc0e0531bb10d03, 0x9572709f31764c62];

/// A value the bootloader may overwrite before the kernel starts.
#[repr(transparent)]
pub struct BootWritten<T>(UnsafeCell<T>);

// SAFETY: only the bootloader writes these values, before the kernel starts
// and before any second CPU runs. Afterwards the kernel only reads them.
unsafe impl<T> Sync for BootWritten<T> {}

impl<T: Copy> BootWritten<T> {
    const fn new(value: T) -> Self {
        Self(UnsafeCell::new(value))
    }

    fn read(&self) -> T {
        // SAFETY: the pointer comes from our own `UnsafeCell`, so it is valid
        // and aligned. Volatile, because the write happened outside the
        // compiler's view (by the bootloader).
        unsafe { self.0.get().read_volatile() }
    }
}

/// Base revision tag ("Base Revisions"): `[magic, magic, revision]`.
#[repr(C)]
pub struct BaseRevisionTag(BootWritten<[u64; 3]>);

impl BaseRevisionTag {
    /// A tag requesting [`BASE_REVISION`].
    pub const fn new() -> Self {
        Self(BootWritten::new([
            0xf9562b2d5c95a6c8,
            0x6a7b384944536bdc,
            BASE_REVISION,
        ]))
    }

    /// True if the bootloader accepted the requested revision.
    pub fn is_supported(&self) -> bool {
        revision_accepted(self.0.read())
    }
}

impl Default for BaseRevisionTag {
    fn default() -> Self {
        Self::new()
    }
}

/// A bootloader that supports the requested revision sets the third value to 0.
pub fn revision_accepted(tag: [u64; 3]) -> bool {
    tag[2] == 0
}

/// A feature request ("Features": `id`, `revision`, `response`).
#[repr(C)]
pub struct Request<R: 'static> {
    id: [u64; 4],
    revision: u64,
    response: BootWritten<*const R>,
}

// SAFETY: `id` and `revision` are immutable; `response` follows the rules of
// `BootWritten`. The response data it points to is never written after boot.
unsafe impl<R> Sync for Request<R> {}

impl<R: 'static> Request<R> {
    const fn new(id: [u64; 2]) -> Self {
        Self {
            id: [COMMON_MAGIC[0], COMMON_MAGIC[1], id[0], id[1]],
            revision: 0,
            response: BootWritten::new(core::ptr::null()),
        }
    }

    /// The bootloader's response, if it answered this request.
    /// The bootloader's response, if it gave one and responses have not
    /// been retired (see [`retire_responses`]).
    pub fn response(&self) -> Option<&'static R> {
        if RESPONSES_RETIRED.load(Ordering::Acquire) {
            return None;
        }
        // SAFETY: the pointer is null or was set by the bootloader to a
        // response in bootloader-reclaimable memory, which stays untouched
        // until `retire_responses` (checked above).
        unsafe { self.response.read().as_ref() }
    }
}

static RESPONSES_RETIRED: AtomicBool = AtomicBool::new(false);

/// Marks all responses invalid: from now on every `response()` returns
/// `None`. Called before bootloader-reclaimable memory, where the responses
/// live, is reused. References obtained earlier must not be used after this.
// ponytail: earlier `&'static` references stay usable by safe code; the rule
// above is documented, not enforced. Revisit if responses spread further.
pub fn retire_responses() {
    RESPONSES_RETIRED.store(true, Ordering::Release);
}

/// Reads a 0-terminated string provided by the bootloader.
fn boot_str(ptr: *const c_char) -> Option<&'static str> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: the protocol guarantees 0-terminated ASCII strings that stay
    // valid while the kernel runs.
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

/// "Bootloader Info Feature".
#[repr(C)]
pub struct BootloaderInfoResponse {
    revision: u64,
    name: *const c_char,
    version: *const c_char,
}

impl BootloaderInfoResponse {
    pub fn name(&self) -> Option<&'static str> {
        boot_str(self.name)
    }

    pub fn version(&self) -> Option<&'static str> {
        boot_str(self.version)
    }
}

/// A request for [`BootloaderInfoResponse`].
pub const fn bootloader_info_request() -> Request<BootloaderInfoResponse> {
    Request::new([0xf55038d8e2a1202f, 0x279426fcf5f59740])
}

/// "Firmware Type Feature".
#[repr(C)]
pub struct FirmwareTypeResponse {
    revision: u64,
    pub firmware_type: u64,
}

/// A request for [`FirmwareTypeResponse`].
pub const fn firmware_type_request() -> Request<FirmwareTypeResponse> {
    Request::new([0x8c2f75d90bef28a8, 0x7045a4688eac00c3])
}

/// "HHDM (Higher Half Direct Map) Feature".
#[repr(C)]
pub struct HhdmResponse {
    revision: u64,
    /// Virtual address where the direct map of physical memory begins.
    pub offset: u64,
}

/// A request for [`HhdmResponse`].
pub const fn hhdm_request() -> Request<HhdmResponse> {
    Request::new([0x48dcf1cb8ad2b852, 0x63984e959a98244b])
}

/// "Memory Map Feature": one entry.
#[repr(C)]
pub struct MemmapEntry {
    pub base: u64,
    pub length: u64,
    /// One of the `MEMMAP_*` constants.
    pub kind: u64,
}

/// Memory map entry types ("Memory Map Feature").
pub const MEMMAP_USABLE: u64 = 0;
pub const MEMMAP_RESERVED: u64 = 1;
pub const MEMMAP_ACPI_RECLAIMABLE: u64 = 2;
pub const MEMMAP_ACPI_NVS: u64 = 3;
pub const MEMMAP_BAD_MEMORY: u64 = 4;
pub const MEMMAP_BOOTLOADER_RECLAIMABLE: u64 = 5;
pub const MEMMAP_EXECUTABLE_AND_MODULES: u64 = 6;
pub const MEMMAP_FRAMEBUFFER: u64 = 7;
/// Reserved, but mapped by the bootloader (base revision 4 and later).
pub const MEMMAP_RESERVED_MAPPED: u64 = 8;

/// "Memory Map Feature".
#[repr(C)]
pub struct MemmapResponse {
    revision: u64,
    entry_count: u64,
    entries: *const *const MemmapEntry,
}

impl MemmapResponse {
    /// The memory map entries, in the order the bootloader reported them.
    pub fn entries(&self) -> impl Iterator<Item = &'static MemmapEntry> + '_ {
        (0..self.entry_count as usize).map(move |i| {
            // SAFETY: the protocol guarantees `entries` points to
            // `entry_count` valid entry pointers, and the entries stay valid
            // and unmodified while the kernel runs.
            unsafe { &**self.entries.add(i) }
        })
    }
}

/// A request for [`MemmapResponse`].
pub const fn memmap_request() -> Request<MemmapResponse> {
    Request::new([0x67cf3d9d378a806f, 0xe304acdfc50c3c62])
}

/// "Executable Address Feature": where the kernel image was loaded.
#[repr(C)]
pub struct ExecutableAddressResponse {
    revision: u64,
    pub physical_base: u64,
    pub virtual_base: u64,
}

/// A request for [`ExecutableAddressResponse`].
pub const fn executable_address_request() -> Request<ExecutableAddressResponse> {
    Request::new([0x71ba76863cc55f63, 0xb2644a48c516a487])
}

/// "File Structure": a file the bootloader loaded, such as a module.
#[repr(C)]
pub struct File {
    revision: u64,
    address: *const u8,
    /// Size in bytes.
    pub size: u64,
    path: *const c_char,
    string: *const c_char,
    media_type: u32,
    unused: u32,
    tftp_ipv4: [u8; 4],
    tftp_port: u32,
    partition_index: u32,
    mbr_disk_id: u32,
    gpt_disk_uuid: [u8; 16],
    gpt_part_uuid: [u8; 16],
    part_uuid: [u8; 16],
}

impl File {
    /// Where the file is, as a direct-map (HHDM) address, at least 4 KiB
    /// aligned. The file has every 4 KiB page it covers to itself.
    pub fn address(&self) -> u64 {
        self.address as u64
    }

    /// The path within the boot volume, with a leading slash.
    pub fn path(&self) -> Option<&'static str> {
        boot_str(self.path)
    }

    /// The string from the configuration (`module_string`).
    pub fn string(&self) -> Option<&'static str> {
        boot_str(self.string)
    }
}

/// "Module Feature" response. Absent when no modules were loaded.
#[repr(C)]
pub struct ModuleResponse {
    revision: u64,
    module_count: u64,
    modules: *const *const File,
}

impl ModuleResponse {
    /// The modules, in configuration order.
    pub fn modules(&self) -> impl Iterator<Item = &'static File> + '_ {
        (0..self.module_count as usize).map(move |i| {
            // SAFETY: the protocol guarantees `modules` points to
            // `module_count` valid file pointers, valid and unmodified
            // until bootloader-reclaimable memory is reused (responses are
            // retired before that).
            unsafe { &**self.modules.add(i) }
        })
    }
}

/// A request for [`ModuleResponse`] (request revision 0: modules from the
/// configuration only, no internal modules).
pub const fn module_request() -> Request<ModuleResponse> {
    Request::new([0x3e7e279702be32af, 0xca1c4f3bd1280cee])
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn layouts_match_the_specification() {
        // id[4] + revision + response pointer, all 64-bit.
        assert_eq!(size_of::<Request<HhdmResponse>>(), 48);
        assert_eq!(size_of::<BaseRevisionTag>(), 24);
        assert_eq!(size_of::<MemmapEntry>(), 24);
        assert_eq!(size_of::<MemmapResponse>(), 24);
        assert_eq!(size_of::<HhdmResponse>(), 16);
        assert_eq!(size_of::<FirmwareTypeResponse>(), 16);
        assert_eq!(size_of::<BootloaderInfoResponse>(), 24);
        assert_eq!(size_of::<ExecutableAddressResponse>(), 24);
        // 5 x u64 + 6 x u32 + 3 UUIDs of 16 bytes.
        assert_eq!(size_of::<File>(), 112);
        assert_eq!(core::mem::offset_of!(File, string), 32);
        assert_eq!(core::mem::offset_of!(File, gpt_disk_uuid), 64);
        assert_eq!(size_of::<ModuleResponse>(), 24);
    }

    #[test]
    fn module_request_id() {
        let request = module_request();
        assert_eq!(&request.id[2..], &[0x3e7e279702be32af, 0xca1c4f3bd1280cee]);
        assert_eq!(request.revision, 0);
    }

    #[test]
    fn requests_carry_common_magic_and_their_id() {
        let request = memmap_request();
        assert_eq!(&request.id[..2], &COMMON_MAGIC);
        assert_eq!(&request.id[2..], &[0x67cf3d9d378a806f, 0xe304acdfc50c3c62]);
        assert!(request.response().is_none(), "no bootloader on the host");
    }

    #[test]
    fn base_revision_check() {
        assert!(
            !BaseRevisionTag::new().is_supported(),
            "unchanged tag means not accepted"
        );
        assert!(revision_accepted([
            0xf9562b2d5c95a6c8,
            0x6a7b384944536bdc,
            0
        ]));
        assert!(!revision_accepted([
            0xf9562b2d5c95a6c8,
            0x6a7b384944536bdc,
            6
        ]));
    }
}
