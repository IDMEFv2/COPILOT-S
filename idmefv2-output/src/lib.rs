// Simple Suricata filetype plugin: idmefv2-output
// This file contains a prototype implementation of a Suricata EVE filetype
// plugin that converts Suricata EVE JSON to IDMEFv2 JSON and writes NDJSON
// lines into a file. The important safety properties are:
//  - callbacks from Suricata are non-blocking: they only enqueue the raw EVE
//    line into a bounded channel
//  - the conversion and file I/O are performed in a dedicated worker thread
//    so Suricata's detection threads are not blocked by disk operations

mod ffi;

use std::ffi::CString;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};
use std::sync::mpsc::{sync_channel, SyncSender, Receiver};
use std::thread;
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;

use idmefv2_core::convert_eve_to_idmef;

// Filetype name registered with Suricata. Keep stable to avoid surprises.
const FILETYPE_NAME: &str = "idmefv2";
// Default output path for NDJSON. Can be overridden by config parsing (not yet in prototype).
const DEFAULT_PATH: &str = "/var/log/suricata/idmefv2.json";
// Size of the in-memory bounded buffer to protect Suricata threads.
const DEFAULT_BUFFER: usize = 10000;

// Context stored in Suricata's init_data pointer: holds a transmitter and the worker handle.
struct Context {
    tx: SyncSender<String>,
    th: thread::JoinHandle<()>,
}

// Initialization callback called by Suricata when the filetype is opened.
// For the prototype we keep configuration simple and use defaults; a full
// implementation should parse the ConfNode to take values from suricata.yaml.
unsafe extern "C" fn output_init(conf: *const c_void, _threaded: bool, init_data: *mut *mut c_void) -> c_int {
    // TODO: parse ConfNode `conf` to read file path and buffer size
    let path = DEFAULT_PATH.to_string();
    let buffer = DEFAULT_BUFFER;

    // Create a bounded channel so Suricata's write callback never blocks.
    let (tx, rx) = sync_channel::<String>(buffer);

    // Spawn a worker thread that will read from the channel, convert events and
    // write NDJSON lines to disk.
    let th = thread::spawn(move || worker_loop(rx, path));

    // Store the context pointer for later callbacks.
    let ctx = Context { tx, th };
    *init_data = Box::into_raw(Box::new(ctx)) as *mut _;
    0
}

// Close callback: called when Suricata closes the filetype. Drop transmitter to
// signal the worker to exit and join the thread.
unsafe extern "C" fn output_close(init_data: *const c_void) {
    if init_data.is_null() { return; }
    let ctx = Box::from_raw(init_data as *mut Context);
    // Dropping the transmitter will close the channel and the worker loop ends.
    drop(ctx.tx);
    let _ = ctx.th.join();
}

// Write callback: Suricata passes a pointer to a NUL-terminated buffer plus
// buffer length. We convert to &str and try to enqueue into the bounded channel.
// The callback must be fast and not block; if the channel is full we drop the
// event (and could increment a counter for diagnostics).
unsafe extern "C" fn output_write(buffer: *const c_char, buffer_len: c_int, _init_data: *const c_void, thread_data: *const c_void) -> c_int {
    if thread_data.is_null() { return -1; }
    // thread_data contains a per-thread ThreadContext created in thread_init.
    let thread_ctx = &mut *(thread_data as *mut ffi::ThreadContext);
    let s = match ffi::str_from_c_parts(buffer, buffer_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    // We attempt to send without blocking. On full channel, the message is dropped
    // to avoid impacting Suricata. The ThreadContext may record stats.
    if let Err(_) = thread_ctx.tx.try_send(s.to_string()) {
        // In production we would increment a dropped counter and log occasionally.
    }
    0
}

// Per-thread initialization: create a small ThreadContext wrapper that gives
// threads a cloned transmitter and tracks per-thread stats.
unsafe extern "C" fn output_thread_init(init_data: *const c_void, thread_id: c_int, thread_data: *mut *mut c_void) -> c_int {
    let ctx = &*(init_data as *const Context);
    let tc = ffi::ThreadContext::new(thread_id as usize, ctx.tx.clone());
    *thread_data = Box::into_raw(Box::new(tc)) as *mut _;
    0
}

// Per-thread deinit: log basic stats and free resources; called when Suricata
// shuts down the thread or plugin.
unsafe extern "C" fn output_thread_deinit(_init_data: *const c_void, thread_data: *mut c_void) {
    if thread_data.is_null() { return; }
    let tc = Box::from_raw(thread_data as *mut ffi::ThreadContext);
    tc.log_exit_stats();
}

// This function registers the filetype with Suricata using the FFI helper.
// It will be called by Suricata when loading the plugin.
unsafe extern "C" fn init_plugin() {
    let ft = ffi::SCEveFileType::new(
        FILETYPE_NAME,
        output_init,
        output_close,
        output_write,
        output_thread_init,
        output_thread_deinit,
    );
    if !ffi::SCRegisterEveFileType(ft) {
        // In a real plugin we would log to Suricata logging facility.
    }
}

// SCPluginRegister is the exported symbol Suricata expects to find in the
// plugin shared object. It returns a pointer to an SCPlugin structure.
#[no_mangle]
pub extern "C" fn SCPluginRegister() -> *const ffi::SCPlugin {
    // Build a minimal SCPlugin instance with our init function.
    let name = CString::new("idmefv2-output").unwrap().into_raw();
    let plugin = ffi::SCPlugin::new(name, init_plugin);
    Box::into_raw(plugin)
}

// Worker loop run in a dedicated thread: receives raw EVE lines from the
// channel, converts each to IDMEFv2 JSON using the core library, and writes
// a NDJSON line into the configured file. Errors are logged or ignored to
// keep the worker resilient.
fn worker_loop(rx: Receiver<String>, path: String) {
    // Ensure parent directory exists to avoid write failures.
    if let Some(parent) = std::path::Path::new(&path).parent() {
        let _ = create_dir_all(parent);
    }
    // Open file in append mode. In production we would implement rotation.
    let mut file = OpenOptions::new().create(true).append(true).open(&path).expect("open file");

    // Blocking receive loop: the worker ends when the transmitter is dropped
    // and the channel is closed by Suricata's shutdown.
    while let Ok(line) = rx.recv() {
        if let Some(json_line) = convert_eve_to_idmef(&line, "suricata", "127.0.0.1") {
            // Write the JSON line followed by a newline and flush to ensure
            // the data reaches disk promptly (useful for testing).
            if let Err(e) = writeln!(file, "{}", json_line) {
                // TODO: robust logging to Suricata log
            }
            let _ = file.flush();
        }
    }
}
