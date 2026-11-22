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
use core::sync::atomic::{AtomicU8, Ordering};

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

    /// The bootloader's response, if it gave one, borrowed from `boot`.
    /// The borrow ends before `boot` can be handed to the reclaim
    /// (`mm::reclaim_bootloader_memory`), so the response cannot be used
    /// after its memory is reused.
    pub fn get<'a>(&self, _boot: &'a BootMemory) -> Option<&'a R> {
        // SAFETY: the pointer is null or was set by the bootloader to a
        // response in bootloader-reclaimable memory. That memory is reused
        // only by the reclaim, which consumes the one `BootMemory`; `boot`
        // is borrowed for `'a`, so it is not consumed during `'a`.
        unsafe { self.response.read().as_ref() }
    }

    /// The bootloader's response for code that never reclaims bootloader
    /// memory (test kernels). The first call keeps that memory for good:
    /// [`BootMemory::take`] returns `None` from then on, so the reclaim can
    /// never run. Returns `None` once the [`BootMemory`] has been taken.
    pub fn response(&self) -> Option<&'static R> {
        if !BOOT_MEMORY.keep() {
            return None;
        }
        // SAFETY: as in `get`; `keep` succeeded, so the one `BootMemory`
        // can no longer be taken, the reclaim cannot run, and the memory
        // stays untouched for the rest of the kernel's life.
        unsafe { self.response.read().as_ref() }
    }
}

/// Who may read Limine's responses ([`BootMemoryState`]).
const UNCLAIMED: u8 = 0;
/// The [`BootMemory`] token was taken; only [`Request::get`] reads.
const TAKEN: u8 = 1;
/// [`Request::response`] was used; bootloader memory is never reclaimed.
const KEPT: u8 = 2;

/// Whether the [`BootMemory`] token is still available, taken, or given up
/// for `'static` responses. Its own type so host tests can use fresh copies.
struct BootMemoryState(AtomicU8);

impl BootMemoryState {
    const fn new() -> Self {
        Self(AtomicU8::new(UNCLAIMED))
    }

    /// True if the token was free and is now taken.
    fn take(&self) -> bool {
        self.0
            .compare_exchange(UNCLAIMED, TAKEN, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// True if responses may be `'static`: the token was never taken, and
    /// now never will be.
    fn keep(&self) -> bool {
        match self
            .0
            .compare_exchange(UNCLAIMED, KEPT, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => true,
            Err(state) => state == KEPT,
        }
    }
}

static BOOT_MEMORY: BootMemoryState = BootMemoryState::new();

/// The right to read Limine's responses ([`Request::get`]) while
/// bootloader-reclaimable memory, where they live, is untouched. There is
/// at most one, and `mm::reclaim_bootloader_memory` consumes it, so no
/// response borrowed from it survives the reclaim (issue #223). Not `Copy`
/// or `Clone`.
pub struct BootMemory {
    _private: (),
}

impl BootMemory {
    /// The one token: `None` if it was taken before, or if
    /// [`Request::response`] already kept bootloader memory for good.
    pub fn take() -> Option<BootMemory> {
        BOOT_MEMORY.take().then_some(BootMemory { _private: () })
    }
}

/// Reads a 0-terminated string provided by the bootloader, borrowed for as
/// long as the response that points to it.
fn boot_str<T: ?Sized>(_response: &T, ptr: *const c_char) -> Option<&str> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: the protocol guarantees a 0-terminated string. It lives in
    // bootloader-reclaimable memory next to the response, so it is valid
    // exactly as long as the response is: the returned lifetime is that of
    // `_response`, which `Request::get` or `Request::response` bounds by the
    // reclaim.
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
    pub fn name(&self) -> Option<&str> {
        boot_str(self, self.name)
    }

    pub fn version(&self) -> Option<&str> {
        boot_str(self, self.version)
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

/// "Date at Boot Feature": the firmware clock's date when Limine booted,
/// in Unix seconds (tls.md, time; #271). Under QEMU the RTC follows the
/// host's clock.
#[repr(C)]
pub struct DateAtBootResponse {
    revision: u64,
    pub timestamp: i64,
}

/// A request for [`DateAtBootResponse`].
pub const fn date_at_boot_request() -> Request<DateAtBootResponse> {
    Request::new([0x502746e184c088aa, 0xfbc5ec83e6327893])
}

/// "RSDP Feature": where the ACPI tables start (#241, iommu.md). Since base
/// revision 4 `address` is a direct-map (HHDM) address, not a physical one.
#[repr(C)]
pub struct RsdpResponse {
    revision: u64,
    /// The RSDP's address in the direct map.
    pub address: u64,
}

/// A request for [`RsdpResponse`].
pub const fn rsdp_request() -> Request<RsdpResponse> {
    Request::new([0xc5e77b6b397e7b43, 0x27637845accdcf3c])
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
    pub fn entries(&self) -> impl Iterator<Item = &MemmapEntry> {
        (0..self.entry_count as usize).map(move |i| {
            // SAFETY: the protocol guarantees `entries` points to
            // `entry_count` valid entry pointers. Array and entries live in
            // bootloader-reclaimable memory like the response, so they are
            // valid and unmodified for as long as `self` is borrowed (see
            // `Request::get`).
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

/// "Executable Command Line Feature": the entry's `cmdline` (#164).
#[repr(C)]
pub struct ExecutableCmdlineResponse {
    revision: u64,
    cmdline: *const c_char,
}

impl ExecutableCmdlineResponse {
    /// The command line; empty when the entry sets none.
    pub fn cmdline(&self) -> Option<&str> {
        boot_str(self, self.cmdline)
    }
}

/// A request for [`ExecutableCmdlineResponse`].
pub const fn executable_cmdline_request() -> Request<ExecutableCmdlineResponse> {
    Request::new([0x4b161536e598651e, 0xb390ad4a2f1f303a])
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
    pub fn path(&self) -> Option<&str> {
        boot_str(self, self.path)
    }

    /// The string from the configuration (`module_string`).
    pub fn string(&self) -> Option<&str> {
        boot_str(self, self.string)
    }

    /// The file's contents, for measuring it (D-047).
    pub fn bytes(&self) -> &[u8] {
        // SAFETY: the protocol guarantees `address` points to `size` bytes
        // of the loaded file, in memory the bootloader reserved for it
        // (executable and modules, or bootloader-reclaimable). It is not
        // reused while `self`, a borrow of a response, lives (see
        // `Request::get`), and nothing writes it.
        unsafe { core::slice::from_raw_parts(self.address, self.size as usize) }
    }
}

/// "Executable File Feature": the kernel's own file (D-047, measured at
/// boot).
#[repr(C)]
pub struct ExecutableFileResponse {
    revision: u64,
    executable_file: *const File,
}

impl ExecutableFileResponse {
    /// The kernel's file.
    pub fn file(&self) -> &File {
        // SAFETY: the protocol guarantees a valid file pointer, in
        // bootloader-reclaimable memory like the response, valid for as
        // long as `self` is borrowed (see `Request::get`).
        unsafe { &*self.executable_file }
    }
}

/// A request for [`ExecutableFileResponse`] (`limine.h`,
/// `LIMINE_EXECUTABLE_FILE_REQUEST_ID`).
pub const fn executable_file_request() -> Request<ExecutableFileResponse> {
    Request::new([0xad97e90e83f1ed67, 0x31eb5d1c5ff23b69])
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
    pub fn modules(&self) -> impl Iterator<Item = &File> {
        (0..self.module_count as usize).map(move |i| {
            // SAFETY: the protocol guarantees `modules` points to
            // `module_count` valid file pointers. List and files live in
            // bootloader-reclaimable memory like the response, so they are
            // valid and unmodified for as long as `self` is borrowed (see
            // `Request::get`).
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
        assert_eq!(size_of::<RsdpResponse>(), 16);
        assert_eq!(size_of::<BootloaderInfoResponse>(), 24);
        assert_eq!(size_of::<ExecutableAddressResponse>(), 24);
        assert_eq!(size_of::<ExecutableCmdlineResponse>(), 16);
        // 5 x u64 + 6 x u32 + 3 UUIDs of 16 bytes.
        assert_eq!(size_of::<File>(), 112);
        assert_eq!(core::mem::offset_of!(File, string), 32);
        assert_eq!(core::mem::offset_of!(File, gpt_disk_uuid), 64);
        assert_eq!(size_of::<ModuleResponse>(), 24);
    }

    #[test]
    fn cmdline_request_id() {
        let request = executable_cmdline_request();
        assert_eq!(&request.id[2..], &[0x4b161536e598651e, 0xb390ad4a2f1f303a]);
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
    fn one_boot_memory_token_and_no_static_responses_beside_it() {
        let state = BootMemoryState::new();
        assert!(state.take(), "the first take gets the token");
        assert!(!state.take(), "there is only one token");
        assert!(!state.keep(), "no 'static responses while it is out");
    }

    #[test]
    fn static_responses_rule_out_the_token() {
        let state = BootMemoryState::new();
        assert!(state.keep(), "'static responses before any token");
        assert!(state.keep(), "and again");
        assert!(!state.take(), "then the reclaim can never be allowed");
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
