//! Narrow Windows CUDA Driver API inventory probe for Rextio development.
//!
//! This unpublished tool never creates a CUDA context and never runs a kernel.
//! Its output is preflight evidence only and always carries
//! `"support_claim": false`.

use std::fmt::Write as _;

const SCHEMA_VERSION: &str = "1";
const PROBE_NAME: &str = "rextio-windows-cuda-probe";

#[derive(Debug, Eq, PartialEq)]
struct DeviceRecord {
    ordinal: i32,
    name: String,
    compute_major: i32,
    compute_minor: i32,
}

#[derive(Debug, Eq, PartialEq)]
struct Report {
    status: &'static str,
    reason_code: Option<&'static str>,
    platform_supported: bool,
    driver_loaded: bool,
    driver_version: Option<i32>,
    device_count: Option<i32>,
    cuda_result: Option<i32>,
    devices: Vec<DeviceRecord>,
}

impl Report {
    #[cfg(any(test, not(all(target_os = "windows", target_arch = "x86_64"))))]
    fn unsupported() -> Self {
        Self {
            status: "unsupported",
            reason_code: Some("UNSUPPORTED_TARGET"),
            platform_supported: false,
            driver_loaded: false,
            driver_version: None,
            device_count: None,
            cuda_result: None,
            devices: Vec::new(),
        }
    }

    fn to_json(&self) -> String {
        let mut output = String::new();
        output.push('{');
        write_json_field(
            &mut output,
            "schema_version",
            &json_string(SCHEMA_VERSION),
            true,
        );
        write_json_field(&mut output, "probe", &json_string(PROBE_NAME), false);
        write_json_field(&mut output, "support_claim", "false", false);
        output.push_str(",\"target\":{");
        write_json_field(&mut output, "os", &json_string(std::env::consts::OS), true);
        write_json_field(
            &mut output,
            "arch",
            &json_string(std::env::consts::ARCH),
            false,
        );
        write_json_field(
            &mut output,
            "environment",
            &json_string(target_environment()),
            false,
        );
        output.push('}');
        write_json_field(
            &mut output,
            "platform_supported",
            if self.platform_supported {
                "true"
            } else {
                "false"
            },
            false,
        );
        write_json_field(&mut output, "status", &json_string(self.status), false);
        write_json_field(
            &mut output,
            "reason_code",
            &optional_string(self.reason_code),
            false,
        );
        write_json_field(
            &mut output,
            "driver_loaded",
            if self.driver_loaded { "true" } else { "false" },
            false,
        );
        write_json_field(
            &mut output,
            "driver_version",
            &optional_i32(self.driver_version),
            false,
        );
        write_json_field(
            &mut output,
            "device_count",
            &optional_i32(self.device_count),
            false,
        );
        write_json_field(
            &mut output,
            "cuda_result",
            &optional_i32(self.cuda_result),
            false,
        );
        output.push_str(",\"devices\":[");
        for (index, device) in self.devices.iter().enumerate() {
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            write_json_field(&mut output, "ordinal", &device.ordinal.to_string(), true);
            write_json_field(&mut output, "name", &json_string(&device.name), false);
            write_json_field(
                &mut output,
                "compute_major",
                &device.compute_major.to_string(),
                false,
            );
            write_json_field(
                &mut output,
                "compute_minor",
                &device.compute_minor.to_string(),
                false,
            );
            write_json_field(
                &mut output,
                "sm",
                &json_string(&format!(
                    "sm_{}{}",
                    device.compute_major, device.compute_minor
                )),
                false,
            );
            output.push('}');
        }
        output.push_str("]}");
        output
    }
}

fn write_json_field(output: &mut String, key: &str, value: &str, first: bool) {
    if !first {
        output.push(',');
    }
    let _ = write!(output, "{}:{}", json_string(key), value);
}

fn optional_string(value: Option<&str>) -> String {
    value.map_or_else(|| "null".to_owned(), json_string)
}

fn optional_i32(value: Option<i32>) -> String {
    value.map_or_else(|| "null".to_owned(), |item| item.to_string())
}

fn json_string(value: &str) -> String {
    let mut output = String::from("\"");
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            value if value <= '\u{1f}' => {
                let _ = write!(output, "\\u{:04x}", value as u32);
            }
            value => output.push(value),
        }
    }
    output.push('"');
    output
}

fn target_environment() -> &'static str {
    #[cfg(target_env = "msvc")]
    {
        return "msvc";
    }
    #[cfg(target_env = "gnu")]
    {
        return "gnu";
    }
    #[cfg(target_env = "musl")]
    {
        return "musl";
    }
    #[allow(unreachable_code)]
    "unknown"
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod windows_probe {
    use super::{DeviceRecord, Report};
    use std::ffi::{c_char, c_void};

    type HModule = *mut c_void;
    type CuDevice = i32;
    type CuResult = i32;

    type CuInit = unsafe extern "system" fn(u32) -> CuResult;
    type CuDriverGetVersion = unsafe extern "system" fn(*mut i32) -> CuResult;
    type CuDeviceGetCount = unsafe extern "system" fn(*mut i32) -> CuResult;
    type CuDeviceGet = unsafe extern "system" fn(*mut CuDevice, i32) -> CuResult;
    type CuDeviceGetName = unsafe extern "system" fn(*mut c_char, i32, CuDevice) -> CuResult;
    type CuDeviceComputeCapability =
        unsafe extern "system" fn(*mut i32, *mut i32, CuDevice) -> CuResult;

    const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;

    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryExW(file_name: *const u16, file: *mut c_void, flags: u32) -> HModule;
        fn GetProcAddress(module: HModule, procedure_name: *const u8) -> *mut c_void;
        fn FreeLibrary(module: HModule) -> i32;
    }

    struct Library(HModule);

    impl Library {
        fn load_nvcuda() -> Option<Self> {
            let mut name: Vec<u16> = "nvcuda.dll".encode_utf16().collect();
            name.push(0);
            // SAFETY: `name` is a live, null-terminated UTF-16 string.  The
            // System32-only flag prevents current-directory/PATH DLL preloading;
            // the handle is owned by `Library` and released in Drop.
            let handle = unsafe {
                LoadLibraryExW(
                    name.as_ptr(),
                    std::ptr::null_mut(),
                    LOAD_LIBRARY_SEARCH_SYSTEM32,
                )
            };
            if handle.is_null() {
                None
            } else {
                Some(Self(handle))
            }
        }

        fn resolve(&self, name: &'static [u8]) -> Option<*mut c_void> {
            // SAFETY: every caller supplies a static null-terminated ASCII
            // symbol name and `self.0` remains live for the returned pointer's
            // complete use.
            let pointer = unsafe { GetProcAddress(self.0, name.as_ptr()) };
            if pointer.is_null() {
                None
            } else {
                Some(pointer)
            }
        }
    }

    impl Drop for Library {
        fn drop(&mut self) {
            // SAFETY: this handle came from a successful LoadLibraryW call and
            // is released exactly once here.
            unsafe {
                FreeLibrary(self.0);
            }
        }
    }

    macro_rules! resolve {
        ($library:expr, $name:literal, $kind:ty) => {{
            let Some(pointer) = $library.resolve(concat!($name, "\0").as_bytes()) else {
                return Report {
                    status: "unavailable",
                    reason_code: Some("REQUIRED_SYMBOL_MISSING"),
                    platform_supported: true,
                    driver_loaded: true,
                    driver_version: None,
                    device_count: None,
                    cuda_result: None,
                    devices: Vec::new(),
                };
            };
            // SAFETY: the symbol name and function-pointer type are fixed next
            // to each invocation below and match the CUDA Driver API headers.
            unsafe { std::mem::transmute::<*mut c_void, $kind>(pointer) }
        }};
    }

    fn cuda_failure(reason_code: &'static str, result: CuResult) -> Report {
        Report {
            status: "unavailable",
            reason_code: Some(reason_code),
            platform_supported: true,
            driver_loaded: true,
            driver_version: None,
            device_count: None,
            cuda_result: Some(result),
            devices: Vec::new(),
        }
    }

    pub(super) fn run() -> Report {
        let Some(library) = Library::load_nvcuda() else {
            return Report {
                status: "unavailable",
                reason_code: Some("NVCUDA_DLL_NOT_FOUND"),
                platform_supported: true,
                driver_loaded: false,
                driver_version: None,
                device_count: None,
                cuda_result: None,
                devices: Vec::new(),
            };
        };

        let cu_init = resolve!(library, "cuInit", CuInit);
        let cu_driver_get_version = resolve!(library, "cuDriverGetVersion", CuDriverGetVersion);
        let cu_device_get_count = resolve!(library, "cuDeviceGetCount", CuDeviceGetCount);
        let cu_device_get = resolve!(library, "cuDeviceGet", CuDeviceGet);
        let cu_device_get_name = resolve!(library, "cuDeviceGetName", CuDeviceGetName);
        let cu_device_compute_capability = resolve!(
            library,
            "cuDeviceComputeCapability",
            CuDeviceComputeCapability
        );

        // SAFETY: resolved pointers have the exact CUDA Driver API signatures.
        // cuInit initializes the driver only; this probe never calls any
        // context-management or kernel-execution symbol.
        let init_result = unsafe { cu_init(0) };
        if init_result != 0 {
            return cuda_failure("CU_INIT_FAILED", init_result);
        }

        let mut driver_version = 0;
        // SAFETY: the pointer is valid for one initialized i32 output.
        let version_result = unsafe { cu_driver_get_version(&mut driver_version) };
        if version_result != 0 {
            return cuda_failure("CU_DRIVER_VERSION_FAILED", version_result);
        }

        let mut device_count = 0;
        // SAFETY: the pointer is valid for one initialized i32 output.
        let count_result = unsafe { cu_device_get_count(&mut device_count) };
        if count_result != 0 {
            return cuda_failure("CU_DEVICE_COUNT_FAILED", count_result);
        }
        if !(0..=1024).contains(&device_count) {
            return Report {
                status: "error",
                reason_code: Some("INVALID_DEVICE_COUNT"),
                platform_supported: true,
                driver_loaded: true,
                driver_version: Some(driver_version),
                device_count: None,
                cuda_result: None,
                devices: Vec::new(),
            };
        }

        let mut devices = Vec::with_capacity(device_count as usize);
        for ordinal in 0..device_count {
            let mut device = 0;
            // SAFETY: the output pointer is valid and the ordinal is bounded
            // by the count returned from the same initialized driver.
            let get_result = unsafe { cu_device_get(&mut device, ordinal) };
            if get_result != 0 {
                return cuda_failure("CU_DEVICE_GET_FAILED", get_result);
            }

            let mut raw_name = [0_i8; 256];
            // SAFETY: the buffer is writable for the exact length supplied and
            // the device handle came from cuDeviceGet.
            let name_result =
                unsafe { cu_device_get_name(raw_name.as_mut_ptr(), raw_name.len() as i32, device) };
            if name_result != 0 {
                return cuda_failure("CU_DEVICE_NAME_FAILED", name_result);
            }

            let mut compute_major = 0;
            let mut compute_minor = 0;
            // SAFETY: both output pointers are valid and the device handle came
            // from cuDeviceGet.
            let capability_result = unsafe {
                cu_device_compute_capability(&mut compute_major, &mut compute_minor, device)
            };
            if capability_result != 0 {
                return cuda_failure("CU_DEVICE_CAPABILITY_FAILED", capability_result);
            }

            let name_bytes: Vec<u8> = raw_name
                .iter()
                .take_while(|value| **value != 0)
                .map(|value| *value as u8)
                .collect();
            let name = sanitized_device_name(&String::from_utf8_lossy(&name_bytes));
            devices.push(DeviceRecord {
                ordinal,
                name,
                compute_major,
                compute_minor,
            });
        }

        let (status, reason_code) = if device_count == 0 {
            ("unavailable", Some("NO_CUDA_DEVICES"))
        } else {
            ("probe-complete", None)
        };
        Report {
            status,
            reason_code,
            platform_supported: true,
            driver_loaded: true,
            driver_version: Some(driver_version),
            device_count: Some(device_count),
            cuda_result: Some(0),
            devices,
        }
    }

    fn sanitized_device_name(value: &str) -> String {
        let sanitized: String = value
            .chars()
            .filter(|character| !character.is_control())
            .take(160)
            .collect();
        let trimmed = sanitized.trim();
        if trimmed.is_empty() {
            "unknown".to_owned()
        } else {
            trimmed.to_owned()
        }
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn run_probe() -> Report {
    windows_probe::run()
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
fn run_probe() -> Report {
    Report::unsupported()
}

fn main() {
    println!("{}", run_probe().to_json());
}

#[cfg(test)]
mod tests {
    use super::{json_string, run_probe, Report};

    #[test]
    fn json_escaping_does_not_allow_control_characters() {
        assert_eq!(json_string("a\n\"b\\c"), "\"a\\n\\\"b\\\\c\"");
    }

    #[test]
    fn every_report_is_explicitly_not_a_support_claim() {
        let json = Report::unsupported().to_json();
        assert!(json.contains("\"support_claim\":false"));
        assert!(json.contains("\"reason_code\":\"UNSUPPORTED_TARGET\""));
    }

    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    #[test]
    fn non_windows_or_non_x64_target_is_truthfully_unsupported() {
        let report = run_probe();
        assert_eq!(report.status, "unsupported");
        assert!(!report.platform_supported);
        assert!(!report.driver_loaded);
    }
}
