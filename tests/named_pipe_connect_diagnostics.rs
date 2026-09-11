#![cfg(windows)]

use device_development_mesh::local_ipc::{LocalEndpoint, LocalProtocolError, open_local_stream};
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, ERROR_SEM_TIMEOUT, GetLastError, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_SHARE_NONE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
    WaitNamedPipeW,
};

#[test]
fn occupied_single_instance_reports_busy_then_public_client_connects_after_rearm() {
    let unique = tempfile::tempdir().unwrap();
    let path = format!(
        r"\\.\pipe\devicelane-connect-diagnostic-{}-{}",
        std::process::id(),
        unique.path().file_name().unwrap().to_str().unwrap()
    );
    let name = wide(&path);
    let endpoint = LocalEndpoint::NamedPipe(path);
    let server = create_single_instance(&name);
    // Successful native open owns the only permitted instance; it stays alive
    // across every busy-state probe. No scheduling delay is used as a fence.
    let occupant = native_open(&name).expect("fixture must occupy its only pipe instance");
    let wait_error = native_wait(&name, 20).expect_err("occupied instance unexpectedly available");
    assert_eq!(wait_error, ERROR_SEM_TIMEOUT);
    let open_error = native_open(&name).expect_err("second client unexpectedly admitted");
    assert_eq!(open_error, ERROR_PIPE_BUSY);
    let public_result = open_local_stream(&endpoint);
    // Capture immediately on this same thread, before any formatting/assertion
    // or unrelated Win32 operation can replace CreateFileW's last-error value.
    let public_error = unsafe { GetLastError() };
    assert!(matches!(public_result, Err(LocalProtocolError::Io)));
    assert_eq!(public_error, ERROR_PIPE_BUSY);
    eprintln!(
        "occupied pipe: WaitNamedPipeW={wait_error}, CreateFileW={open_error}, public client last-error={public_error}"
    );

    drop(occupant);
    drop(server);
    // Deterministically rearm by creating a fresh sole instance, as the service
    // creates its next instance. All old handles were released first.
    let _rearmed_server = create_single_instance(&name);
    let recovered = open_local_stream(&endpoint).expect("public client must connect after rearm");
    drop(recovered);
}

#[test]
fn absent_pipe_reports_file_not_found_instead_of_busy() {
    let unique = tempfile::tempdir().unwrap();
    let path = format!(
        r"\\.\pipe\devicelane-absent-diagnostic-{}-{}",
        std::process::id(),
        unique.path().file_name().unwrap().to_str().unwrap()
    );
    let name = wide(&path);
    assert_eq!(native_wait(&name, 20).unwrap_err(), ERROR_FILE_NOT_FOUND);
    assert_eq!(native_open(&name).unwrap_err(), ERROR_FILE_NOT_FOUND);
    let result = open_local_stream(&LocalEndpoint::NamedPipe(path));
    let error = unsafe { GetLastError() };
    assert!(matches!(result, Err(LocalProtocolError::Io)));
    assert_eq!(error, ERROR_FILE_NOT_FOUND);
    eprintln!("absent pipe: public client last-error={error}");
}

fn wide(path: &str) -> Vec<u16> {
    path.encode_utf16().chain(Some(0)).collect()
}

fn create_single_instance(name: &[u16]) -> OwnedHandle {
    let handle = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            4096,
            4096,
            20,
            std::ptr::null(),
        )
    };
    let error = unsafe { GetLastError() };
    assert_ne!(
        handle, INVALID_HANDLE_VALUE,
        "cannot create fixture pipe: {error}"
    );
    unsafe { OwnedHandle::from_raw_handle(handle.cast()) }
}

fn native_wait(name: &[u16], timeout_ms: u32) -> Result<(), u32> {
    let available = unsafe { WaitNamedPipeW(name.as_ptr(), timeout_ms) };
    let error = unsafe { GetLastError() };
    if available == 0 { Err(error) } else { Ok(()) }
}

fn native_open(name: &[u16]) -> Result<OwnedHandle, u32> {
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_SHARE_NONE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    let error = unsafe { GetLastError() };
    if handle == INVALID_HANDLE_VALUE {
        Err(error)
    } else {
        Ok(unsafe { OwnedHandle::from_raw_handle(handle.cast()) })
    }
}
