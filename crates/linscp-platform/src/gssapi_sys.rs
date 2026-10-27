//! Zero-build-dependency runtime Kerberos V5 GSSAPI loader (`dlopen` of
//! `libgssapi_krb5.so.2` on Linux; safe `None` stub on platforms without MIT/Heimdal
//! runtime libraries). Keeps default Cargo builds 100% pure-Rust with zero C
//! compiler or link-time dependencies while allowing `gssapi-with-mic` (`AuthGSSAPI`,
//! `LogicalHostName`, `GSSAPIFwdTGT`) to authenticate against Kerberos realms when
//! `libgssapi_krb5.so.2` is present at runtime.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformGssStep {
    Continue(Vec<u8>),
    Complete {
        token: Option<Vec<u8>>,
        mic: Vec<u8>,
    },
}

pub trait SystemGssapiContext: Send + Sync {
    fn step(
        &mut self,
        input_token: Option<&[u8]>,
        mic_data: &[u8],
    ) -> Result<PlatformGssStep, String>;
}

/// Returns `true` if a system Kerberos V5 GSSAPI runtime library can be loaded.
pub fn is_system_gssapi_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        linux_impl::load_gss_api().is_some()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Attempts to open a Kerberos V5 `host@<service_host>` initiator context.
pub fn try_create_system_gssapi_context(
    service_host: &str,
    delegate_creds: bool,
) -> Option<Box<dyn SystemGssapiContext>> {
    #[cfg(target_os = "linux")]
    {
        linux_impl::DlopenKrb5Context::new(service_host, delegate_creds)
            .map(|ctx| Box::new(ctx) as Box<dyn SystemGssapiContext>)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (service_host, delegate_creds);
        None
    }
}

#[cfg(target_os = "linux")]
mod linux_impl {
    use std::ffi::{c_void, CStr, CString};
    use std::sync::OnceLock;

    use super::{PlatformGssStep, SystemGssapiContext};

    type OmUint32 = u32;
    type GssNameT = *mut c_void;
    type GssCtxIdT = *mut c_void;
    type GssCredIdT = *mut c_void;

    #[repr(C)]
    struct GssOidDesc {
        length: u32,
        elements: *mut c_void,
    }

    #[repr(C)]
    struct GssBufferDesc {
        length: usize,
        value: *mut c_void,
    }

    const GSS_S_COMPLETE: OmUint32 = 0;
    const GSS_S_CONTINUE_NEEDED: OmUint32 = 1;

    const GSS_C_DELEG_FLAG: OmUint32 = 1;
    const GSS_C_MUTUAL_FLAG: OmUint32 = 2;
    const GSS_C_REPLAY_FLAG: OmUint32 = 4;
    const GSS_C_INTEG_FLAG: OmUint32 = 32;
    const GSS_C_INDEFINITE: OmUint32 = 0xffff_ffff;

    const GSS_C_GSS_CODE: libc::c_int = 1;
    const GSS_C_MECH_CODE: libc::c_int = 2;

    // Raw OID value bytes (without outer 0x06 + length tag):
    // GSS_C_NT_HOSTBASED_SERVICE = 1.2.840.113554.1.2.1.4
    const HOSTBASED_SERVICE_OID_BYTES: &[u8] =
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x04];
    // KRB5 mechanism = 1.2.840.113554.1.2.2
    const KRB5_MECH_OID_BYTES: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];

    type FnImportName = unsafe extern "C" fn(
        minor_status: *mut OmUint32,
        input_name_buffer: *mut GssBufferDesc,
        input_name_type: *mut GssOidDesc,
        output_name: *mut GssNameT,
    ) -> OmUint32;

    type FnInitSecContext = unsafe extern "C" fn(
        minor_status: *mut OmUint32,
        claimant_cred_handle: GssCredIdT,
        context_handle: *mut GssCtxIdT,
        target_name: GssNameT,
        mech_type: *mut GssOidDesc,
        req_flags: OmUint32,
        time_req: OmUint32,
        input_chan_bindings: *mut c_void,
        input_token: *mut GssBufferDesc,
        actual_mech_type: *mut *mut GssOidDesc,
        output_token: *mut GssBufferDesc,
        ret_flags: *mut OmUint32,
        time_rec: *mut OmUint32,
    ) -> OmUint32;

    type FnGetMic = unsafe extern "C" fn(
        minor_status: *mut OmUint32,
        context_handle: GssCtxIdT,
        qop_req: OmUint32,
        message_buffer: *mut GssBufferDesc,
        message_token: *mut GssBufferDesc,
    ) -> OmUint32;

    type FnReleaseBuffer =
        unsafe extern "C" fn(minor_status: *mut OmUint32, buffer: *mut GssBufferDesc) -> OmUint32;

    type FnReleaseName =
        unsafe extern "C" fn(minor_status: *mut OmUint32, input_name: *mut GssNameT) -> OmUint32;

    type FnDeleteSecContext = unsafe extern "C" fn(
        minor_status: *mut OmUint32,
        context_handle: *mut GssCtxIdT,
        output_token: *mut GssBufferDesc,
    ) -> OmUint32;

    type FnDisplayStatus = unsafe extern "C" fn(
        minor_status: *mut OmUint32,
        status_value: OmUint32,
        status_type: libc::c_int,
        mech_type: *mut GssOidDesc,
        message_context: *mut OmUint32,
        status_string: *mut GssBufferDesc,
    ) -> OmUint32;

    struct GssSymbols {
        import_name: FnImportName,
        init_sec_context: FnInitSecContext,
        get_mic: FnGetMic,
        release_buffer: FnReleaseBuffer,
        release_name: FnReleaseName,
        delete_sec_context: FnDeleteSecContext,
        display_status: FnDisplayStatus,
    }

    // SAFETY: Loaded symbol pointers reside in a permanently resident shared
    // object (`dlopen` without `dlclose`) and are thread-safe C entrypoints.
    unsafe impl Send for GssSymbols {}
    // SAFETY: See above.
    unsafe impl Sync for GssSymbols {}

    static GSS_API: OnceLock<Option<GssSymbols>> = OnceLock::new();

    unsafe fn sym<T: Copy>(handle: *mut c_void, name: &CStr) -> Option<T> {
        // SAFETY: `handle` is a valid `dlopen` handle and `name` is NUL-terminated.
        let ptr = unsafe { libc::dlsym(handle, name.as_ptr()) };
        if ptr.is_null() {
            return None;
        }
        // SAFETY: Caller specifies exact C function pointer signature `T`.
        Some(unsafe { std::mem::transmute_copy(&ptr) })
    }

    pub(super) fn load_gss_api() -> Option<&'static GssSymbols> {
        GSS_API
            .get_or_init(|| {
                for soname in [c"libgssapi_krb5.so.2", c"libgssapi_krb5.so"] {
                    // SAFETY: `soname` is a static C string; `RTLD_NOW | RTLD_LOCAL` is safe.
                    let handle =
                        unsafe { libc::dlopen(soname.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
                    if handle.is_null() {
                        continue;
                    }
                    // SAFETY: Resolving standard RFC 2744 C symbols from `libgssapi_krb5`.
                    unsafe {
                        return Some(GssSymbols {
                            import_name: sym(handle, c"gss_import_name")?,
                            init_sec_context: sym(handle, c"gss_init_sec_context")?,
                            get_mic: sym(handle, c"gss_get_mic")?,
                            release_buffer: sym(handle, c"gss_release_buffer")?,
                            release_name: sym(handle, c"gss_release_name")?,
                            delete_sec_context: sym(handle, c"gss_delete_sec_context")?,
                            display_status: sym(handle, c"gss_display_status")?,
                        });
                    }
                }
                None
            })
            .as_ref()
    }

    pub(super) struct DlopenKrb5Context {
        api: &'static GssSymbols,
        target_name: GssNameT,
        ctx: GssCtxIdT,
        req_flags: OmUint32,
    }

    // SAFETY: Access to `DlopenKrb5Context` is serialized through `&mut self`
    // inside `tokio::sync::Mutex` in `linscp-proto`.
    unsafe impl Send for DlopenKrb5Context {}
    // SAFETY: See above.
    unsafe impl Sync for DlopenKrb5Context {}

    impl DlopenKrb5Context {
        pub(super) fn new(service_host: &str, delegate_creds: bool) -> Option<Self> {
            let api = load_gss_api()?;
            let service_str = format!("host@{service_host}");
            let c_service = CString::new(service_str).ok()?;
            let mut name_buf = GssBufferDesc {
                length: c_service.as_bytes().len(),
                value: c_service.as_ptr() as *mut c_void,
            };
            let mut oid_bytes = HOSTBASED_SERVICE_OID_BYTES.to_vec();
            let mut nt_oid = GssOidDesc {
                length: oid_bytes.len() as u32,
                elements: oid_bytes.as_mut_ptr() as *mut c_void,
            };
            let mut target_name: GssNameT = std::ptr::null_mut();
            let mut minor: OmUint32 = 0;
            // SAFETY: Valid input buffer and OID descriptor; `target_name` released in `Drop`.
            let maj =
                unsafe { (api.import_name)(&mut minor, &mut name_buf, &mut nt_oid, &mut target_name) };
            if (maj & 0xffff_0000) != 0 || target_name.is_null() {
                return None;
            }
            let mut req_flags = GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG | GSS_C_INTEG_FLAG;
            if delegate_creds {
                req_flags |= GSS_C_DELEG_FLAG;
            }
            Some(Self {
                api,
                target_name,
                ctx: std::ptr::null_mut(),
                req_flags,
            })
        }

        fn format_gss_error(&self, maj: OmUint32, min: OmUint32) -> String {
            let mut parts = Vec::new();
            let mut mech_bytes = KRB5_MECH_OID_BYTES.to_vec();
            let mut mech_oid = GssOidDesc {
                length: mech_bytes.len() as u32,
                elements: mech_bytes.as_mut_ptr() as *mut c_void,
            };
            for (code, kind) in [(maj, GSS_C_GSS_CODE), (min, GSS_C_MECH_CODE)] {
                if code == 0 {
                    continue;
                }
                let mut msg_ctx: OmUint32 = 0;
                loop {
                    let mut disp_min: OmUint32 = 0;
                    let mut out_buf = GssBufferDesc {
                        length: 0,
                        value: std::ptr::null_mut(),
                    };
                    // SAFETY: Valid output buffer released immediately via `gss_release_buffer`.
                    let rc = unsafe {
                        (self.api.display_status)(
                            &mut disp_min,
                            code,
                            kind,
                            &mut mech_oid,
                            &mut msg_ctx,
                            &mut out_buf,
                        )
                    };
                    if (rc & 0xffff_0000) == 0 && !out_buf.value.is_null() && out_buf.length > 0 {
                        // SAFETY: `out_buf.value`..`+ out_buf.length` was allocated by GSSAPI.
                        let bytes = unsafe {
                            std::slice::from_raw_parts(out_buf.value as *const u8, out_buf.length)
                        };
                        let text = String::from_utf8_lossy(bytes)
                            .trim_end_matches('\0')
                            .trim()
                            .to_string();
                        if !text.is_empty() {
                            parts.push(text);
                        }
                    }
                    // SAFETY: Releases GSSAPI buffer if allocated.
                    unsafe {
                        let mut rel_min = 0;
                        let _ = (self.api.release_buffer)(&mut rel_min, &mut out_buf);
                    }
                    if msg_ctx == 0 || (rc & 0xffff_0000) != 0 {
                        break;
                    }
                }
            }
            if parts.is_empty() {
                format!("GSSAPI error (major=0x{maj:08x}, minor=0x{min:08x})")
            } else {
                parts.join(": ")
            }
        }
    }

    impl SystemGssapiContext for DlopenKrb5Context {
        fn step(
            &mut self,
            input_token: Option<&[u8]>,
            mic_data: &[u8],
        ) -> Result<PlatformGssStep, String> {
            let mut mech_bytes = KRB5_MECH_OID_BYTES.to_vec();
            let mut mech_oid = GssOidDesc {
                length: mech_bytes.len() as u32,
                elements: mech_bytes.as_mut_ptr() as *mut c_void,
            };

            let mut in_copy = input_token.map(|s| s.to_vec()).unwrap_or_default();
            let mut in_buf = GssBufferDesc {
                length: in_copy.len(),
                value: if in_copy.is_empty() {
                    std::ptr::null_mut()
                } else {
                    in_copy.as_mut_ptr() as *mut c_void
                },
            };
            let in_ptr = if input_token.is_some() {
                &mut in_buf as *mut GssBufferDesc
            } else {
                std::ptr::null_mut()
            };

            let mut out_buf = GssBufferDesc {
                length: 0,
                value: std::ptr::null_mut(),
            };
            let mut ret_flags: OmUint32 = 0;
            let mut minor: OmUint32 = 0;

            // SAFETY: Standard RFC 2744 `gss_init_sec_context` invocation; `out_buf`
            // is copied and released immediately below.
            let maj = unsafe {
                (self.api.init_sec_context)(
                    &mut minor,
                    std::ptr::null_mut(),
                    &mut self.ctx,
                    self.target_name,
                    &mut mech_oid,
                    self.req_flags,
                    GSS_C_INDEFINITE,
                    std::ptr::null_mut(),
                    in_ptr,
                    std::ptr::null_mut(),
                    &mut out_buf,
                    &mut ret_flags,
                    std::ptr::null_mut(),
                )
            };

            let out_token = if !out_buf.value.is_null() && out_buf.length > 0 {
                // SAFETY: `out_buf` was populated by `gss_init_sec_context`.
                let slice =
                    unsafe { std::slice::from_raw_parts(out_buf.value as *const u8, out_buf.length) };
                slice.to_vec()
            } else {
                Vec::new()
            };
            // SAFETY: Releases `out_buf` allocated by `gss_init_sec_context`.
            unsafe {
                let mut rel_min = 0;
                let _ = (self.api.release_buffer)(&mut rel_min, &mut out_buf);
            }

            if (maj & 0xffff_0000) != 0 {
                return Err(self.format_gss_error(maj, minor));
            }

            if (maj & GSS_S_CONTINUE_NEEDED) != 0 {
                return Ok(PlatformGssStep::Continue(out_token));
            }

            if maj == GSS_S_COMPLETE {
                if (ret_flags & GSS_C_MUTUAL_FLAG) == 0 {
                    return Err(
                        "GSSAPI mutual authentication was not established by the server."
                            .to_string(),
                    );
                }
                let mut mic_in_copy = mic_data.to_vec();
                let mut mic_in_buf = GssBufferDesc {
                    length: mic_in_copy.len(),
                    value: mic_in_copy.as_mut_ptr() as *mut c_void,
                };
                let mut mic_out_buf = GssBufferDesc {
                    length: 0,
                    value: std::ptr::null_mut(),
                };
                let mut mic_min: OmUint32 = 0;
                // SAFETY: `self.ctx` is an established GSSAPI context with `GSS_C_INTEG_FLAG`.
                let mic_maj = unsafe {
                    (self.api.get_mic)(
                        &mut mic_min,
                        self.ctx,
                        0,
                        &mut mic_in_buf,
                        &mut mic_out_buf,
                    )
                };
                let mic_vec = if (mic_maj & 0xffff_0000) == 0
                    && !mic_out_buf.value.is_null()
                    && mic_out_buf.length > 0
                {
                    // SAFETY: `mic_out_buf` was populated by `gss_get_mic`.
                    unsafe {
                        std::slice::from_raw_parts(mic_out_buf.value as *const u8, mic_out_buf.length)
                            .to_vec()
                    }
                } else {
                    Vec::new()
                };
                // SAFETY: Releases `mic_out_buf`.
                unsafe {
                    let mut rel_min = 0;
                    let _ = (self.api.release_buffer)(&mut rel_min, &mut mic_out_buf);
                }
                if (mic_maj & 0xffff_0000) != 0 || mic_vec.is_empty() {
                    return Err(self.format_gss_error(mic_maj, mic_min));
                }
                return Ok(PlatformGssStep::Complete {
                    token: (!out_token.is_empty()).then_some(out_token),
                    mic: mic_vec,
                });
            }

            Err(self.format_gss_error(maj, minor))
        }
    }

    impl Drop for DlopenKrb5Context {
        fn drop(&mut self) {
            // SAFETY: Releases `self.ctx` and `self.target_name` if non-null.
            unsafe {
                let mut minor: OmUint32 = 0;
                if !self.ctx.is_null() {
                    let _ = (self.api.delete_sec_context)(
                        &mut minor,
                        &mut self.ctx,
                        std::ptr::null_mut(),
                    );
                }
                if !self.target_name.is_null() {
                    let _ = (self.api.release_name)(&mut minor, &mut self.target_name);
                }
            }
        }
    }
}
