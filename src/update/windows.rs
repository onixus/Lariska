//! A held, nonempty mailbox cannot be changed into a Windows junction.
//!
//! Create the guard relative to the directory handle: its path may have been
//! changed into a reparse point since it was opened. Never resolve it again.

use std::ffi::c_void;
use std::fs::File;
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};

const FILE_READ_DATA: u32 = 0x1;
const FILE_READ_ATTRIBUTES: u32 = 0x80;
const SYNCHRONIZE: u32 = 0x0010_0000;
const FILE_SHARE_READ: u32 = 0x1;
const FILE_OPEN_IF: u32 = 0x3;
const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const GUARD_NAME: &str = ".lariska-directory-pin";

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: *mut c_void,
    object_name: *mut UnicodeString,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_quality_of_service: *mut c_void,
}

#[repr(C)]
#[derive(Default)]
struct IoStatusBlock {
    status: usize,
    information: usize,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateFile(
        file_handle: *mut *mut c_void,
        desired_access: u32,
        object_attributes: *mut ObjectAttributes,
        io_status_block: *mut IoStatusBlock,
        allocation_size: *const i64,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: *const c_void,
        ea_length: u32,
    ) -> i32;
    fn RtlNtStatusToDosError(status: i32) -> u32;
}

pub(super) fn pin_directory_guard(directory: &File) -> Result<File, String> {
    let mut utf16: Vec<u16> = GUARD_NAME.encode_utf16().collect();
    let mut name = UnicodeString {
        length: (utf16.len() * 2) as u16,
        maximum_length: (utf16.len() * 2) as u16,
        buffer: utf16.as_mut_ptr(),
    };
    let mut attributes = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: directory.as_raw_handle(),
        object_name: &mut name,
        attributes: 0x40, // OBJ_CASE_INSENSITIVE; the name is one fixed component.
        security_descriptor: std::ptr::null_mut(),
        security_quality_of_service: std::ptr::null_mut(),
    };
    let mut status_block = IoStatusBlock::default();
    let mut handle = std::ptr::null_mut();
    // Read DATA is intentional: attributes alone do not activate Windows share
    // checks. The live handle must prevent deletion, truncation and replacement.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            &mut attributes,
            &mut status_block,
            std::ptr::null(),
            0x80, // FILE_ATTRIBUTE_NORMAL
            FILE_SHARE_READ,
            FILE_OPEN_IF,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        return Err(format!(
            "cannot hold shared directory guard: {}",
            std::io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32)
        ));
    }
    if handle.is_null() {
        return Err("shared directory guard returned an invalid handle".into());
    }
    let guard = unsafe { File::from_raw_handle(handle) };
    let metadata = guard.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.len() != 0
    {
        return Err("shared directory guard must be a regular empty file".into());
    }
    // An attacker may have set a junction while the held directory was empty.
    // The anchored creation stayed in the original directory, and the guard now
    // prevents another conversion; reject a conversion that already happened.
    let attributes = directory
        .metadata()
        .map_err(|e| e.to_string())?
        .file_attributes();
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 || attributes & FILE_ATTRIBUTE_DIRECTORY == 0
    {
        return Err("shared update directory changed into a reparse point".into());
    }
    Ok(guard)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};
    use std::os::windows::fs::OpenOptionsExt;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn DeviceIoControl(
            device: *mut c_void,
            control_code: u32,
            input: *const c_void,
            input_size: u32,
            output: *mut c_void,
            output_size: u32,
            returned: *mut u32,
            overlapped: *mut c_void,
        ) -> i32;
    }

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "lariska-mailbox-guard-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn directory(&self, name: &str) -> PathBuf {
            let path = self.0.join(name);
            fs::create_dir(&path).unwrap();
            path
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            // remove_dir_all does not follow directory junctions on Windows.
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn directory_pin(path: &Path) -> File {
        OpenOptions::new()
            .access_mode(FILE_READ_DATA | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(0x0200_0000 | FILE_OPEN_REPARSE_POINT)
            .open(path)
            .unwrap()
    }

    /// FILE_WRITE_ATTRIBUTES deliberately bypasses the read-only share pin.
    /// Using mklink would request stronger access and fail before reproducing
    /// the vulnerable FSCTL_SET_REPARSE_POINT operation.
    fn set_junction(path: &Path, target: &Path) -> Result<(), std::io::Error> {
        let file = OpenOptions::new()
            .access_mode(0x100) // FILE_WRITE_ATTRIBUTES
            .share_mode(0x7)
            .custom_flags(0x0200_0000 | FILE_OPEN_REPARSE_POINT)
            .open(path)?;
        let target = target.to_string_lossy();
        let substitute: Vec<u16> = format!(r"\??\{target}").encode_utf16().collect();
        let print: Vec<u16> = target.encode_utf16().collect();
        let sub_len = (substitute.len() * 2) as u16;
        let print_len = (print.len() * 2) as u16;
        let payload_len = 8 + sub_len + 2 + print_len + 2;
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&0xa000_0003u32.to_le_bytes());
        buffer.extend_from_slice(&payload_len.to_le_bytes());
        buffer.extend_from_slice(&0u16.to_le_bytes());
        buffer.extend_from_slice(&0u16.to_le_bytes()); // SubstituteNameOffset
        buffer.extend_from_slice(&sub_len.to_le_bytes());
        buffer.extend_from_slice(&(sub_len + 2).to_le_bytes()); // PrintNameOffset
        buffer.extend_from_slice(&print_len.to_le_bytes());
        for value in substitute.into_iter().chain([0]).chain(print).chain([0]) {
            buffer.extend_from_slice(&value.to_le_bytes());
        }
        let mut returned = 0;
        if unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                0x0009_00a4, // FSCTL_SET_REPARSE_POINT
                buffer.as_ptr().cast(),
                buffer.len() as u32,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
            )
        } == 0
        {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    #[test]
    fn guard_blocks_attribute_only_junction_conversion_and_replacement() {
        let fixture = Fixture::new();
        let mailbox = fixture.directory("mailbox");
        let outside = fixture.directory("outside");
        let directory = directory_pin(&mailbox);
        let guard = pin_directory_guard(&directory).unwrap();
        let guard_path = mailbox.join(GUARD_NAME);
        assert!(fs::write(&guard_path, b"replace").is_err());
        assert!(fs::remove_file(&guard_path).is_err());
        assert!(fs::rename(&guard_path, mailbox.join("moved")).is_err());
        assert!(fs::rename(&mailbox, fixture.0.join("moved-mailbox")).is_err());
        let error = set_junction(&mailbox, &outside).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(145)); // ERROR_DIR_NOT_EMPTY
        assert!(!outside.join(GUARD_NAME).exists());
        drop(guard);
        drop(directory);
    }

    #[test]
    fn junction_race_before_guard_cannot_create_a_file_outside_held_directory() {
        let fixture = Fixture::new();
        let mailbox = fixture.directory("mailbox");
        let outside = fixture.directory("outside");
        let directory = directory_pin(&mailbox);
        // Counterfactual: the original read pin permits this attack on an empty
        // directory. The guard's anchored creation and recheck must contain it.
        set_junction(&mailbox, &outside).unwrap();
        assert!(pin_directory_guard(&directory).is_err());
        assert!(!outside.join(GUARD_NAME).exists());
        drop(directory);
    }
}
