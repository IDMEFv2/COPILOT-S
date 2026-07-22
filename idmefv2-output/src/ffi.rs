// FFI helpers for output plugin (simplified)
// The real Suricata headers define structures and function prototypes; here we
// provide a minimal Rust representation sufficient for registration and for
// implementing the prototype filetype. The goal is to mirror the expected C
// layout so the plugin can be built as a cdylib and loaded by Suricata.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::str::Utf8Error;
use std::sync::mpsc::SyncSender;
use std::ptr;

// Type aliases for the callback prototypes Suricata expects for a filetype.
pub type InitFn = unsafe extern "C" fn(conf: *const c_void, threaded: bool, init_data: *mut *mut c_void) -> c_int;
pub type DeinitFn = unsafe extern "C" fn(init_data: *const c_void);
pub type WriteFn = unsafe extern "C" fn(buffer: *const c_char, buffer_len: c_int, init_data: *const c_void, thread_data: *const c_void) -> c_int;
pub type ThreadInitFn = unsafe extern "C" fn(init_data: *const c_void, thread_id: std::os::raw::c_int, thread_data: *mut *mut c_void) -> c_int;
pub type ThreadDeinitFn = unsafe extern "C" fn(init_data: *const c_void, thread_data: *mut c_void);

// Minimal representation of the Suricata SCEveFileType structure. The fields
// are pointers to C strings and function pointers matching the prototypes above.
#[repr(C)]
pub struct SCEveFileType {
    pub name: *const c_char,
    pub open: InitFn,
    pub close: DeinitFn,
    pub write: WriteFn,
    pub thread_init: ThreadInitFn,
    pub thread_deinit: ThreadDeinitFn,
    pad: [usize; 2],
}

impl SCEveFileType {
    // Create a heap-allocated SCEveFileType and return a raw pointer suitable
    // for passing to SCRegisterEveFileType.
    pub fn new(name: &str, open: InitFn, close: DeinitFn, write: WriteFn, thread_init: ThreadInitFn, thread_deinit: ThreadDeinitFn) -> *const Self {
        let name = CString::new(name).unwrap().into_raw();
        let ft = SCEveFileType { name, open, close, write, thread_init, thread_deinit, pad: [0,0] };
        Box::into_raw(Box::new(ft))
    }
}

extern "C" {
    // Suricata exposes SCRegisterEveFileType in its C API; we declare it here
    // so the plugin can call it during initialization.
    pub fn SCRegisterEveFileType(filetype: *const SCEveFileType) -> bool;
}

// Minimal SCPlugin structure representation returned by SCPluginRegister. The
// fields chosen here are the ones needed for Suricata's loader to query
// plugin metadata. In the real Suricata API other fields and layout details
// may be present.
#[repr(C)]
pub struct SCPlugin {
    pub version: *const c_char,
    pub suricata_version: *const c_char,
    pub name: *const c_char,
    pub plugin_version: *const c_char,
    pub license: *const c_char,
    pub author: *const c_char,
    pub Init: Option<unsafe extern "C" fn()> ,
}

impl SCPlugin {
    // Build a minimal SCPlugin structure. The returned Box must be leaked to
    // return a stable pointer to Suricata (the loader expects a static pointer).
    pub fn new(name: *const c_char, init: unsafe extern "C" fn()) -> Box<Self> {
        let v = CString::new("0").unwrap().into_raw();
        let sur = CString::new("suricata").unwrap().into_raw();
        let plugv = CString::new("0.1").unwrap().into_raw();
        let lic = CString::new("MIT").unwrap().into_raw();
        let author = CString::new("copilot").unwrap().into_raw();
        Box::new(SCPlugin{ version: v, suricata_version: sur, name, plugin_version: plugv, license: lic, author, Init: Some(init) })
    }
}

// ThreadContext is the small structure given to each Suricata worker thread
// that calls the plugin write callback. It bundles a cloned transmitter and
// provides counters for diagnostics.
pub struct ThreadContext {
    pub thread_id: usize,
    pub tx: SyncSender<String>,
    pub count: usize,
    pub dropped: usize,
}

impl ThreadContext {
    pub fn new(thread_id: usize, tx: SyncSender<String>) -> Self {
        Self { thread_id, tx, count: 0, dropped: 0 }
    }
    // In a real implementation we would log these stats to Suricata's logging.
    pub fn log_exit_stats(&self) {}
}

// Utility to convert a C buffer (NUL-terminated) and explicit length into a
// Rust &str reference. Suricata provides the buffer length; we handle the
// trailing NUL by constructing a slice of length buffer_len+1.
pub fn str_from_c_parts<'a>(buffer: *const c_char, buffer_len: c_int) -> Result<&'a str, Utf8Error> {
    unsafe {
        let slice = std::slice::from_raw_parts(buffer as *const u8, (buffer_len as usize) + 1);
        CStr::from_bytes_with_nul_unchecked(slice).to_str()
    }
}
