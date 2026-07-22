// idmefv2-http plugin (prototype)
// Non-blocking callback enqueues EVE lines; dispatcher converts and enqueues messages for sender.

mod ffi;

use std::ffi::CString;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};
use std::sync::mpsc::{sync_channel, SyncSender, Receiver};
use std::thread;
use std::time::Duration;

use idmefv2_core::convert_eve_to_idmef;
use reqwest::blocking::Client;

const FILETYPE_NAME: &str = "idmefv2-http";
const DEFAULT_BUFFER: usize = 10000;

struct Context {
    tx: SyncSender<String>,
    th: thread::JoinHandle<()>,
}

unsafe extern "C" fn output_init(_conf: *const c_void, _threaded: bool, init_data: *mut *mut c_void) -> c_int {
    let (tx, rx) = sync_channel::<String>(DEFAULT_BUFFER);
    let endpoint = std::env::var("IDMEFV2_HTTP_ENDPOINT").ok();
    let th = thread::spawn(move || dispatcher_loop(rx, endpoint));
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
    if let Err(_) = thread_ctx.tx.try_send(s.to_string()) {
        // drop
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
    unsafe { ffi::SCRegisterEveFileType(ft); }
}

#[no_mangle]
pub extern "C" fn SCPluginRegister() -> *const ffi::SCPlugin {
    let name = CString::new("idmefv2-http").unwrap().into_raw();
    let plugin = ffi::SCPlugin::new(name, init_plugin);
    Box::into_raw(plugin)
}

fn dispatcher_loop(rx: Receiver<String>, endpoint: Option<String>) {
    let client = Client::builder().timeout(Duration::from_secs(10)).build().expect("client");
    while let Ok(eve_line) = rx.recv() {
        if let Some(idmef) = convert_eve_to_idmef(&eve_line, "suricata", "127.0.0.1") {
            if let Some(ref url) = endpoint {
                // simple send with one retry
                let mut attempt = 0;
                loop {
                    attempt += 1;
                    let res = client.post(url).header("Content-Type", "application/idmef+json").body(idmef.clone()).send();
                    match res {
                        Ok(r) if r.status().is_success() => break,
                        _ => {
                            if attempt >= 3 { break; }
                            thread::sleep(Duration::from_secs(1 << attempt));
                        }
                    }
                }
            }
        }
    }
}
