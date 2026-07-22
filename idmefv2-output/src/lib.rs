// Simple Suricata filetype plugin: idmefv2-output
// Non-blocking: callback enqueues EVE lines; a worker thread converts and writes NDJSON to a file.

mod ffi;

use std::ffi::CString;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};
use std::sync::mpsc::{sync_channel, SyncSender, Receiver};
use std::thread;
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;

use idmefv2_core::convert_eve_to_idmef;

const FILETYPE_NAME: &str = "idmefv2";
const DEFAULT_PATH: &str = "/var/log/suricata/idmefv2.json";
const DEFAULT_BUFFER: usize = 10000;

struct Context {
    tx: SyncSender<String>,
    th: thread::JoinHandle<()>,
}

unsafe extern "C" fn output_init(conf: *const c_void, _threaded: bool, init_data: *mut *mut c_void) -> c_int {
    // For prototype, we use defaults. Real implementation would parse ConfNode.
    let path = DEFAULT_PATH.to_string();
    let buffer = DEFAULT_BUFFER;

    let (tx, rx) = sync_channel::<String>(buffer);
    let th = thread::spawn(move || worker_loop(rx, path));

    let ctx = Context { tx, th };
    *init_data = Box::into_raw(Box::new(ctx)) as *mut _;
    0
}

unsafe extern "C" fn output_close(init_data: *const c_void) {
    if init_data.is_null() { return; }
    let ctx = Box::from_raw(init_data as *mut Context);
    drop(ctx.tx);
    let _ = ctx.th.join();
}

unsafe extern "C" fn output_write(buffer: *const c_char, buffer_len: c_int, _init_data: *const c_void, thread_data: *const c_void) -> c_int {
    if thread_data.is_null() { return -1; }
    let thread_ctx = &mut *(thread_data as *mut ffi::ThreadContext);
    let s = match ffi::str_from_c_parts(buffer, buffer_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    // enqueue
    if let Err(_) = thread_ctx.tx.try_send(s.to_string()) {
        // drop on full
    }
    0
}

unsafe extern "C" fn output_thread_init(init_data: *const c_void, thread_id: c_int, thread_data: *mut *mut c_void) -> c_int {
    let ctx = &*(init_data as *const Context);
    let tc = ffi::ThreadContext::new(thread_id as usize, ctx.tx.clone());
    *thread_data = Box::into_raw(Box::new(tc)) as *mut _;
    0
}

unsafe extern "C" fn output_thread_deinit(_init_data: *const c_void, thread_data: *mut c_void) {
    if thread_data.is_null() { return; }
    let tc = Box::from_raw(thread_data as *mut ffi::ThreadContext);
    tc.log_exit_stats();
}

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
        // log error (can't use Suricata logger here easily)
    }
}

#[no_mangle]
pub extern "C" fn SCPluginRegister() -> *const ffi::SCPlugin {
    // Minimal SCPlugin struct
    let name = CString::new("idmefv2-output").unwrap().into_raw();
    let plugin = ffi::SCPlugin::new(name, init_plugin);
    Box::into_raw(plugin)
}

fn worker_loop(rx: Receiver<String>, path: String) {
    if let Some(parent) = std::path::Path::new(&path).parent() {
        let _ = create_dir_all(parent);
    }
    let mut file = OpenOptions::new().create(true).append(true).open(&path).expect("open file");
    while let Ok(line) = rx.recv() {
        if let Some(json_line) = convert_eve_to_idmef(&line, "suricata", "127.0.0.1") {
            if let Err(e) = writeln!(file, "{}", json_line) {
                // log
            }
            let _ = file.flush();
        }
    }
}
