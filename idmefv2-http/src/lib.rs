// idmefv2-http plugin (prototype)
// This plugin is optional and intended for quick testing: it sends IDMEFv2
// JSON messages over HTTPS to a configured endpoint. For safety, it is
// implemented as a non-blocking Suricata filetype plugin where the callbacks
// only enqueue EVE events; the network I/O is performed in a dedicated
// dispatcher thread.

mod ffi;

use std::ffi::CString;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};
use std::sync::mpsc::{sync_channel, SyncSender, Receiver};
use std::thread;
use std::time::Duration;

use idmefv2_core::convert_eve_to_idmef;
use reqwest::blocking::Client;

// Plugin filetype registered with Suricata. Named differently to avoid
// colliding with the file output plugin; operators can enable either or both.
const FILETYPE_NAME: &str = "idmefv2-http";
// Default in-memory buffer size for enqueued EVE events.
const DEFAULT_BUFFER: usize = 10000;

// Simple runtime context stored in Suricata's init_data pointer.
struct Context {
    tx: SyncSender<String>,
    th: thread::JoinHandle<()>,
}

// Init callback called by Suricata. For the prototype the plugin reads the
// HTTP endpoint from an environment variable IDMEFV2_HTTP_ENDPOINT. A
// production implementation should parse suricata.yaml.
unsafe extern "C" fn output_init(_conf: *const c_void, _threaded: bool, init_data: *mut *mut c_void) -> c_int {
    // Create a bounded channel to protect the detection threads.
    let (tx, rx) = sync_channel::<String>(DEFAULT_BUFFER);
    // For prototype convenience, the endpoint is read from env var.
    let endpoint = std::env::var("IDMEFV2_HTTP_ENDPOINT").ok();
    // Spawn dispatcher thread which will convert events and perform HTTP sends.
    let th = thread::spawn(move || dispatcher_loop(rx, endpoint));
    let ctx = Context { tx, th };
    *init_data = Box::into_raw(Box::new(ctx)) as *mut _;
    0
}

// Close: drop transmitter and join dispatcher thread to ensure graceful shutdown.
unsafe extern "C" fn output_close(init_data: *const c_void) {
    if init_data.is_null() { return; }
    let ctx = Box::from_raw(init_data as *mut Context);
    drop(ctx.tx);
    let _ = ctx.th.join();
}

// Write callback: convert the C buffer to &str and try to enqueue; if the
// channel is full the message is dropped to avoid blocking Suricata.
unsafe extern "C" fn output_write(buffer: *const c_char, buffer_len: c_int, _init_data: *const c_void, thread_data: *const c_void) -> c_int {
    if thread_data.is_null() { return -1; }
    let thread_ctx = &mut *(thread_data as *mut ffi::ThreadContext);
    let s = match ffi::str_from_c_parts(buffer, buffer_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    if let Err(_) = thread_ctx.tx.try_send(s.to_string()) {
        // On full queue: drop
    }
    0
}

// Per-thread init: provide a ThreadContext wrapper containing a cloned
// transmitter and counters.
unsafe extern "C" fn output_thread_init(init_data: *const c_void, thread_id: c_int, thread_data: *mut *mut c_void) -> c_int {
    let ctx = &*(init_data as *const Context);
    let tc = ffi::ThreadContext::new(thread_id as usize, ctx.tx.clone());
    *thread_data = Box::into_raw(Box::new(tc)) as *mut _;
    0
}

// Per-thread deinit: log stats and free.
unsafe extern "C" fn output_thread_deinit(_init_data: *const c_void, thread_data: *mut c_void) {
    if thread_data.is_null() { return; }
    let tc = Box::from_raw(thread_data as *mut ffi::ThreadContext);
    tc.log_exit_stats();
}

// Register filetype with Suricata.
unsafe extern "C" fn init_plugin() {
    let ft = ffi::SCEveFileType::new(
        FILETYPE_NAME,
        output_init,
        output_close,
        output_write,
        output_thread_init,
        output_thread_deinit,
    );
    unsafe { ffi::SCRegisterEveFileType(ft); }
}

// Export SCPluginRegister symbol expected by Suricata loader.
#[no_mangle]
pub extern "C" fn SCPluginRegister() -> *const ffi::SCPlugin {
    let name = CString::new("idmefv2-http").unwrap().into_raw();
    let plugin = ffi::SCPlugin::new(name, init_plugin);
    Box::into_raw(plugin)
}

// Dispatcher thread: receives raw EVE lines, converts them to IDMEF JSON
// using the core library and performs HTTP POST to the configured endpoint.
// For the prototype we implement a simple retry policy (3 attempts with
// exponential backoff) to tolerate transient failures.
fn dispatcher_loop(rx: Receiver<String>, endpoint: Option<String>) {
    // Build a blocking HTTP client with a reasonable timeout.
    let client = Client::builder().timeout(Duration::from_secs(10)).build().expect("client");

    while let Ok(eve_line) = rx.recv() {
        // Convert to IDMEF JSON line; skip if conversion fails.
        if let Some(idmef) = convert_eve_to_idmef(&eve_line, "suricata", "127.0.0.1") {
            if let Some(ref url) = endpoint {
                // Try to send with a small retry loop.
                let mut attempt = 0;
                loop {
                    attempt += 1;
                    let res = client.post(url).header("Content-Type", "application/idmef+json").body(idmef.clone()).send();
                    match res {
                        Ok(r) if r.status().is_success() => break, // sent ok
                        _ => {
                            // On failure, retry up to 3 attempts with exponential backoff.
                            if attempt >= 3 { break; }
                            thread::sleep(Duration::from_secs(1 << attempt));
                        }
                    }
                }
            }
        }
    }
}
