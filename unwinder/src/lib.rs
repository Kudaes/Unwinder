#[macro_use]
extern crate litcrypt2;

use_litcrypt!();

use std::{ffi::c_void, ptr::{self}, mem::transmute, vec};
use nanorand::{WyRand, Rng};

use windows::Win32::{System::{Diagnostics::Debug::{IMAGE_OPTIONAL_HEADER32, IMAGE_SECTION_HEADER}, Threading::GetCurrentThread}, Foundation::HANDLE};
use bitreader::BitReader;
use dinvoke_rs::data::{PeMetadata, ImageFileHeader, ImageOptionalHeader64, RuntimeFunction, UNW_FLAG_EHANDLER, UNW_FLAG_CHAININFO, PVOID, JMP_RBX, ADD_RSP, TLS_OUT_OF_INDEXES};

extern "C"
{
    fn spoof_call(structure: PVOID) -> PVOID;
    fn get_current_rsp() -> usize;
}

struct Configuration
{
    first_frame_function_pointer: PVOID,
	second_frame_function_pointer: PVOID,
	jmp_rbx_gadget: PVOID,
	add_rsp_xgadget: PVOID,
    first_frame_size: usize,
	second_frame_size: usize,
	jmp_rbx_gadget_frame_size: usize,
	add_rsp_xgadget_frame_size: usize,
    stack_offset_where_rbp_is_pushed: usize,
	spoof_function_pointer: PVOID,
	return_address: PVOID,
    nargs: usize,
	arg01: PVOID,
	arg02: PVOID,
	arg03: PVOID,
	arg04: PVOID,
	arg05: PVOID,
	arg06: PVOID,
	arg07: PVOID,
	arg08: PVOID,
    arg09: PVOID,
	arg10: PVOID,
	arg11: PVOID,
    syscall: u32,
    syscall_id: u32
}

static mut INDEX: u32 = 0;

/// Call an arbitrary function with a clean call stack.
/// 
/// This macro will make sure the thread has a clean and unwindable call stack
/// before calling the specified function.
/// 
/// The first parameter expected by the macro is the memory address of the function to call. The
/// following parameters should be the arguments to pass to the specified function.
/// 
/// The macro's return parameter is the same value returned by the specified function.
/// 
/// # Example - Calling Sleep() with a clean call stack (using dinvoke_rs)
/// 
/// ```ignore
/// let k32 = dinvoke_rs::dinvoke::get_module_base_address("kernel32.dll");
/// let sleep = dinvoke_rs::dinvoke::get_function_address(k32, "Sleep"); // Memory address of kernel32.dll!Sleep() 
/// let miliseconds = 1000i32;
/// unwinder::call_function!(sleep, seconds);
/// ```
/// 
#[macro_export]
macro_rules! call_function {

    ($($x:expr),*) => {{

        let mut temp_vec = Vec::new();
        $(
            let temp = $x as usize; // This is meant to convert integers with smaller size than 8 bytes
            let pointer: *mut c_void = std::mem::transmute(temp);
            temp_vec.push(pointer);
        )*
            
        let res = $crate::spoof_and_call(temp_vec, false, 0);
        res
    }}
}

/// Execute an indirect syscall with a clean call stack.
/// 
/// This macro will make sure the thread has a clean and unwindable call stack
/// before executing the syscall for the specified NT function.
/// 
/// The first parameter expected by the macro is the name of the function whose syscall wants to be run. The
/// following parameters should be the arguments expected by the specified syscall.
/// 
/// The macro's return parameter is the same value returned by the syscall.
/// 
/// # Example - Calling NtDelayExecution() as indirect syscall with a clean call stack
/// 
/// ```ignore
/// let large = 0x8000000000000000 as u64; // Sleep indefinitely
/// let large: *mut i64 = std::mem::transmute(&large);
/// let alertable = false;
/// let ntstatus = unwinder::indirect_syscall!("NtDelayExecution", alertable, large);
/// println!("ntstatus: {:x}", ntstatus as usize);
/// ```
/// 
#[macro_export]
macro_rules! indirect_syscall {

    ($a:expr, $($x:expr),*) => {{

        let mut temp_vec = Vec::new();
        let t = $crate::prepare_syscall($a);
        let p: *mut c_void = std::mem::transmute(t.1);
        temp_vec.push(p);
        $(
            let temp = $x as usize; // This is meant to convert integers with smaller size than 8 bytes
            let pointer: *mut c_void = std::mem::transmute(temp);
            temp_vec.push(pointer);
        )*
        
        let res = $crate::spoof_and_call(temp_vec, true, t.0);
        res
    }}
}

/// Don't call this function directly, use call_function!() and indirect_syscall!() macros instead.
pub fn spoof_and_call(mut args: Vec<*mut c_void>, is_syscall: bool, id: u32) -> *mut c_void
{
    unsafe
    {
        if is_syscall && (id == 0)
        {
            return ptr::null_mut();
        }

        let mut config: Configuration = std::mem::zeroed();
        let mut black_list: Vec<(u32,u32)> = vec![];
        let kernelbase = dinvoke_rs::dinvoke::get_module_base_address(&lc!("kernelbase.dll")) as usize;

        let mut first_frame_size = 0i32;
        let first_frame_address = find_setfpreg(kernelbase, &mut first_frame_size, &mut black_list);

        let mut push_offset = 0i32;
        let mut second_frame_size = 0i32;
        let second_frame_addr = find_pushrbp(kernelbase, &mut second_frame_size, &mut push_offset, &mut black_list);

        let mut first_gadget_size = 0i32;
        let first_gadget_addr = find_gadget(kernelbase, &mut first_gadget_size, 0, &mut black_list);

        let mut second_gadget_size = 0i32;
        let second_gadget_addr = find_gadget(kernelbase, &mut second_gadget_size, 1, &mut black_list);
        config.first_frame_function_pointer = first_frame_address as *mut _;
        config.first_frame_size = first_frame_size as usize;
        config.second_frame_function_pointer = second_frame_addr as *mut _;
        config.second_frame_size = second_frame_size as usize;
        config.jmp_rbx_gadget = first_gadget_addr as *mut _;
        config.jmp_rbx_gadget_frame_size = first_gadget_size as usize;
        config.add_rsp_xgadget = second_gadget_addr as *mut _;
        config.add_rsp_xgadget_frame_size = second_gadget_size as usize;
        config.stack_offset_where_rbp_is_pushed = push_offset as usize;
        config.spoof_function_pointer = args.remove(0);
        config.syscall = is_syscall as u32;
        config.syscall_id = id;
        
        let mut args_number = args.len();
        config.nargs = args_number;

        while args_number > 0
        {
            match args_number
            {
                11  => config.arg11 = args[args_number-1],
                10  => config.arg10 = args[args_number-1],
                9   => config.arg09 = args[args_number-1],
                8   => config.arg08 = args[args_number-1],
                7   => config.arg07 = args[args_number-1],
                6   => config.arg06 = args[args_number-1],
                5   => config.arg05 = args[args_number-1],
                4   => config.arg04 = args[args_number-1],
                3   => config.arg03 = args[args_number-1],
                2   => config.arg02 = args[args_number-1],
                1   => config.arg01 = args[args_number-1],
                _   => () 
            }

            args_number -= 1;
        }

        let mut spoofy = get_cookie_value();
        if spoofy == 0
        {
            let current_rsp = get_current_rsp();
            spoofy = get_desirable_return_address(current_rsp);           
        }

        config.return_address = spoofy as *mut _; 
        let config: PVOID = std::mem::transmute(&config);
        spoof_call(config)
        
    }
}

// This functions will returns the main module's frame address in the stack.
// If it fails to do so, it will return the BaseThreadInitThunk's frame address instead.
fn get_desirable_return_address(current_rsp: usize) -> usize
{
    unsafe
    {
        let k32 = dinvoke_rs::dinvoke::get_module_base_address(&lc!("kernel32.dll"));
        let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&lc!("ntdll.dll"));
        let mut addr: usize = 0;
        let mut start_address = 1; 
        let mut end_address = 0;
        let base_thread_init_thunk_start = dinvoke_rs::dinvoke::get_function_address(k32, &lc!("BaseThreadInitThunk")) as usize;
        let base_thread_init_thunk_addresses = get_function_size(k32 as usize, base_thread_init_thunk_start);
        let base_thread_init_thunk_end = base_thread_init_thunk_addresses.1;
        let thread_handle = GetCurrentThread();
        let thread_info_class = 9u32;
        let thread_information = 0usize;
        let thread_information: PVOID = std::mem::transmute(&thread_information);
        let thread_info_len = 8u32;
        let ret_len = 0u32;
        let ret_len: *mut u32 = std::mem::transmute(&ret_len);
        let funct: unsafe extern "system" fn (HANDLE, u32, PVOID, u32, *mut u32) -> i32;
        let ret: Option<i32>;
        // Obtain current thread's start address
        dinvoke_rs::dinvoke::dynamic_invoke!(ntdll,&lc!("NtQueryInformationThread"), funct, ret, thread_handle, thread_info_class, thread_information, thread_info_len, ret_len);

        if ret.is_some() && ret.unwrap() == 0 
        {
            let thread_information = thread_information as *mut usize; 

            let flags = 0x00000004;
            let function_address: *const u8 = *thread_information as _;
            let module_handle = 0usize;
            let module_handle: *mut usize = std::mem::transmute(&module_handle);
            let funct: unsafe extern "system" fn (i32,*const u8,*mut usize) -> bool;
            let ret: Option<bool>;
            // Determine the module where the current thread's start function is located at.
            dinvoke_rs::dinvoke::dynamic_invoke!(k32,&lc!("GetModuleHandleExA"),funct,ret,flags,function_address,module_handle);

            if ret.is_some() && ret.unwrap()
            {
                let base_address = *module_handle;
                let function_addresses = get_function_size(base_address, function_address as _);
                start_address = function_addresses.0;
                end_address = function_addresses.1;
            }
        }  

        let mut stack_iterator: *mut usize = current_rsp as *mut usize;
        let mut found = false;

        while !found
        {
            // Check whether the value stored in this stack's address is located at current thread's start function or
            // BaseThreadInitThunk. Otherwise, iterate to the next word in the stack and repeat the process.
            if  (*stack_iterator > start_address && *stack_iterator < end_address) || 
                (*stack_iterator >  base_thread_init_thunk_start && *stack_iterator < base_thread_init_thunk_end)
            {
                addr = stack_iterator as usize;
                let data = dinvoke_rs::dinvoke::tls_get_value(INDEX) as *mut usize;
                *data = addr;
                found = true;
            }

            stack_iterator = stack_iterator.add(1);
        }

        addr
    }
}

// TLS is used to store the main module's/BaseThreadInitThunk's frame address in the stack.
// This allows to efficiently concatenate the spoofing process as many times as needed.
fn get_cookie_value() -> usize
{
    unsafe
    {
        if INDEX == 0
        {
            let r = dinvoke_rs::dinvoke::tls_alloc();
            if r == TLS_OUT_OF_INDEXES
            {
                return 0;
            }

            INDEX = r;
        }

        let value = dinvoke_rs::dinvoke::tls_get_value(INDEX) as *mut usize;
        if value as usize == 0
        {   
            if  dinvoke_rs::dinvoke::get_last_error() != 0 
            {
                let heap_region = dinvoke_rs::dinvoke::local_alloc(0x0040, 8); // 0x0040 = LPTR
                if heap_region != ptr::null_mut()
                {
                    let _ = dinvoke_rs::dinvoke::tls_set_value(INDEX, heap_region);
                }
            }

            return 0;
        }

        *value
    }

}

// Use RuntimeFunction's data to get the size of a function.
fn get_function_size(base_address: usize, function_address: usize) -> (usize, usize)
{
    unsafe
    {
        let exception_directory = get_runtime_table(base_address as _);
        let mut rt = exception_directory.0;
        if rt == ptr::null_mut(){
            return (0,0);
        }
        
        let items = exception_directory.1 / 12;
        let mut count = 0;
        while count < items
        {
            let function_start_address = (base_address + (*rt).begin_addr as usize) as *mut u8;
            let function_end_address = (base_address + (*rt).end_addr as usize) as *mut u8;
            if function_address >= function_start_address as usize && function_address < function_end_address as usize 
            {
                return (function_start_address as usize, function_end_address as usize);
            }

            rt = rt.add(1);
            count += 1;
        }

        (0,0)
    }
}

// Don't call this function directly. Use indirect_syscall!() macro instead.
pub fn prepare_syscall(function_name: &str) -> (u32, usize)
{

    let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&lc!("ntdll.dll"));
    let eat = dinvoke_rs::dinvoke::get_ntdll_eat(ntdll);
    let id = dinvoke_rs::dinvoke::get_syscall_id(&eat, function_name);
    if id != -1
    {
        let max_range = eat.len();
        let mut rng = WyRand::new();
        let mut function = &"".to_string();
        for s in eat.values()
        {
            let index = rng.generate_range(0..max_range);
            if index < max_range / 10
            {
                function = s;
                break;
            }
        }

        let function_addr = dinvoke_rs::dinvoke::get_function_address(ntdll, function);
        let syscall_addr = dinvoke_rs::dinvoke::find_syscall_address(function_addr as usize);

        return (id as u32,syscall_addr);
    }
    
    (0,0)
}

// Function used to find the JMP RBX and ADD RSP gadgets.
fn find_gadget(module: usize, gadget_frame_size: &mut i32, arg: i32, black_list:  &mut Vec<(u32,u32)>) -> usize {
    unsafe
    {
        let exception_directory = get_runtime_table(module as *mut _);
        let mut rt = exception_directory.0;
        if rt == ptr::null_mut(){
            return 0;
        }
        
        let items = exception_directory.1 / 12;
        let mut rng = WyRand::new();
        let rt_offset = rng.generate_range(0..(items/2));
        rt = rt.add(rt_offset as usize);
        let mut count = rt_offset;
        while count < items
        {
            let mut function_start_address = (module + (*rt).begin_addr as usize) as *mut u8;
            let function_end_address = (module + (*rt).end_addr as usize) as *mut u8;
            let item = ((*rt).begin_addr, (*rt).end_addr);
            if black_list.contains(&item)
            {
                rt = rt.add(1);
                count += 1;
                continue;
            }

            while (function_start_address as usize) < (function_end_address as usize) - 3
            {
                if (*(function_start_address as *mut u16) == JMP_RBX && arg == 0) ||
                (*(function_start_address as *mut u32) == ADD_RSP && *(function_start_address.add(4)) == 0xc3 && arg == 1)
                {
                    *gadget_frame_size = get_frame_size_normal(module, *rt);
                    if *gadget_frame_size == 0
                    {
                        function_start_address = function_start_address.add(1);
                        continue;
                    }
                    else 
                    {
                        black_list.push(item);
                        return function_start_address as usize;
                    }
                }

                function_start_address = function_start_address.add(1);
            }

            rt = rt.add(1);
            count += 1;
        }

        0
    }
}

// Find a function with a setfpreg unwind code.
fn find_setfpreg(module: usize, frame_size: &mut i32, black_list: &mut Vec<(u32,u32)>) -> usize {
    
    unsafe 
    {
        let exception_directory = get_runtime_table(module as *mut _);
        let mut rt = exception_directory.0;
        if rt == ptr::null_mut(){
            return 0;
        }
        
        let items = exception_directory.1 / 12;
        let mut rng = WyRand::new();
        let rt_offset = rng.generate_range(0..(items/2));
        rt = rt.add(rt_offset as usize);
        let mut count = rt_offset;
        while count < items
        {   
            let runtime_function = *rt;
            let mut found = false;
            *frame_size = get_frame_size_with_setfpreg(module, runtime_function, &mut found);
            if found && *frame_size != 0
            {
                let random_offset = generate_random_offset(module, runtime_function);
                if random_offset != 0
                {
                    let item = (runtime_function.begin_addr,runtime_function.end_addr);
                    black_list.push(item);
                    return (module + random_offset as usize) as _;
                }
            }

            rt = rt.add(1);
            count += 1;
        }

        0   
    }
}

// Find a function where RBP is pushed to the stack.
fn find_pushrbp(module: usize, frame_size: &mut i32, push_offset: &mut i32, black_list: &mut Vec<(u32,u32)>) -> usize {
    
    unsafe 
    {
        let exception_directory = get_runtime_table(module as *mut _);
        let mut rt = exception_directory.0;
        if rt == ptr::null_mut(){
            return 0;
        }
        
        let items = exception_directory.1 / 12;
        let mut count = 0;
        let mut rng = WyRand::new();
        let rt_offset = rng.generate_range(0..(items/2));
        rt = rt.add(rt_offset as usize);
        while count < items
        {   
            let runtime_function = *rt;
            let item = (runtime_function.begin_addr,runtime_function.end_addr);
            let mut found: bool = false;
            *push_offset = 0;
            *frame_size = 0i32;
            get_frame_size_with_push_rbp(module, runtime_function, &mut found, push_offset, frame_size);
            if found && *frame_size >= *push_offset  && !black_list.contains(&item)
            {
                let random_offset = generate_random_offset(module, runtime_function);
                if random_offset != 0
                {
                    black_list.push(item);
                    return (module + random_offset as usize) as _;
                }
            }

            rt = rt.add(1);
            count += 1;
        }

        0   
    }
}

// Locate a call instruction in an arbitrary function and return the next instruction's address.
fn generate_random_offset(module: usize, runtime_function: RuntimeFunction) -> u32 
{
    
    let start_address = module + runtime_function.begin_addr as usize;
    let end_address = module + runtime_function.end_addr as usize;
    let pattern = vec![0x48,0xff,0x15]; // 0x48 0xff 0x15 00 00 00 00 00 00 = rex.W call QWORD PTR [rip+0x0]
    let address = find_pattern(start_address, end_address, pattern);
    
    if address == -1
    {
        return 0;
    }

    ((address + 7) - module  as isize) as u32
    
}

fn find_pattern(mut start_address: usize, end_address: usize, pattern: Vec<u8>) -> isize
{
    unsafe
    {
        while start_address < (end_address - pattern.len())
        {
            if *(start_address as *mut u8) == pattern[0]
            {
                let temp_iterator = start_address as *mut u8;
                let mut found = true;
                for i in 1..pattern.len()
                {
                    if *temp_iterator.add(i) != pattern[i]
                    {
                        found = false;
                        break;
                    }
                }

                if found
                {
                    return start_address as isize;
                }

            }

            start_address += 1;
        }

        -1
    }
}

fn get_frame_size_normal(module: usize, runtime_function: RuntimeFunction) -> i32 {
    unsafe
    {   
        let unwind_info = (module + runtime_function.unwind_addr as usize) as *mut u8;
        let version_and_flags = (*unwind_info).to_ne_bytes().clone();
        let mut reader = BitReader::new(&version_and_flags);

        // We don't care about the version, we just need the flags to check if there is an Unwind Chain.
        let flags = reader.read_u8(5).unwrap(); 
        if flags == 0x3
        {
            return 0;
        }

        let unwind_codes_count = *(unwind_info.add(2)); 

        // We skip 4 bytes corresponding to Version + flags, Size of prolog, Count of unwind codes
        // and Frame Register + Frame Register offset.
        // This way we reach the Unwind codes array.
        let mut unwind_code = (unwind_info.add(4)) as *mut u8;
        let mut unwind_code_operation_code_info = unwind_code.add(1);
        // This counter stores the size of the stack frame.
        let mut frame_size = 0;
        let mut index = 0;
        while index < unwind_codes_count
        {           
            let operation_code_and_info = (*unwind_code_operation_code_info).to_le_bytes().clone();
            let mut reader = BitReader::new(&operation_code_and_info);

            let operation_info = reader.read_u8(4).unwrap(); // operation info
            let operation_code = reader.read_u8(4).unwrap(); // operation code

            match operation_code
            {
                0 => 
                {
                    // UWOP_PUSH_NONVOL

                    // operation_info == 4 -> RSP
                    if operation_code == 4
                    {
                        return 0;
                    }

                    frame_size += 8;
                }
                1 =>
                {
                    // UWOP_ALLOC_LARGE
                    if operation_info == 0
                    {
                        let size = *(unwind_code_operation_code_info.add(1) as *mut i16);
                        frame_size += size as i32 * 8;

                        unwind_code = unwind_code.add(2);
                        index += 1;

                    }
                    else if operation_info == 1
                    {
                        let size = *(unwind_code_operation_code_info.add(1) as *mut u16) as i32;
                        let size2 = (*(unwind_code_operation_code_info.add(3) as *mut u16) as i32)  << 16;
                        frame_size += size + size2;

                        unwind_code = unwind_code.add(4);
                        index += 2;
                    }
                }
                2 =>
                {
                    // UWOP_ALLOC_SMALL
                    frame_size += (operation_info * 8 + 8) as i32;
                }
                3 =>
                {
                    // UWOP_SET_FPREG
                }
                4 =>
                {
                    // UWOP_SAVE_NONVOL

                    // operation_info == 4 -> RSP
                    if operation_info == 4
                    {
                        return 0;
                    }

                    unwind_code = unwind_code.add(2);
                    index += 1;
                }
                5 =>
                {
                    // UWOP_SAVE_NONVOL_FAR

                    // operation_info == 4 -> RSP
                    if operation_info == 4
                    {
                        return 0;
                    }

                    unwind_code = unwind_code.add(4);
                    index += 2;
                }
                8 => 
                {
                    // UWOP_SAVE_XMM128 
                    unwind_code = unwind_code.add(2);
                    index += 1;
                }
                9 => 
                {
                    // UWOP_SAVE_XMM128_FAR
                    unwind_code = unwind_code.add(4);
                    index += 2;
                }
                10 =>
                {
                    // UWOP_PUSH_MACH_FRAME
                    if operation_info == 0
                    {
                        frame_size += 64; // 0x40h
                    }
                    else if operation_code == 1
                    {
                        frame_size += 72; // 0x48h
                    }
                }
                _=> {}
            }

            unwind_code = unwind_code.add(2);
            unwind_code_operation_code_info = unwind_code.add(1);
            index += 1;
        }

        // In case that the flag UNW_FLAG_CHAININFO is set, we recursively call this function.
        if (flags & UNW_FLAG_CHAININFO) != 0
        {
            if unwind_codes_count % 2 != 0
            {
                unwind_code = unwind_code.add(2);
            }

            let runtime_function: *mut RuntimeFunction = transmute(unwind_code);
            let result = get_frame_size_normal(module, *runtime_function);

            frame_size += result as i32;
        }   

        frame_size
    }
}

fn get_frame_size_with_setfpreg(module: usize, runtime_function: RuntimeFunction, found: &mut bool) -> i32 {

    unsafe
    {
        let unwind_info = (module + runtime_function.unwind_addr as usize) as *mut u8;
        let fp_info = unwind_info.add(3);
        let frame_register_and_offset = (*fp_info).to_ne_bytes().clone(); // Little endian

        let mut reader = BitReader::new(&frame_register_and_offset);
        let frame_register_offset = reader.read_u8(4).unwrap(); 
        let frame_register = reader.read_u8(4).unwrap(); 

        let version_and_flags = (*unwind_info).to_ne_bytes().clone();
        let mut reader = BitReader::new(&version_and_flags);

        // We don't care about the version, we just need the flags to check if there is an Unwind Chain.
        let flags = reader.read_u8(5).unwrap(); 

        let unwind_codes_count = *(unwind_info.add(2)); 

        // We skip 4 bytes corresponding to Version + flags, Size of prolog, Count of unwind codes
        // and Frame Register + Frame Register offset.
        // This way we reach the Unwind codes array.
        let mut unwind_code = (unwind_info.add(4)) as *mut u8;
        let mut unwind_code_operation_code_info = unwind_code.add(1);
        // This counter stores the size of the stack frame.
        let mut frame_size = 0;
        let mut index = 0;
        while index < unwind_codes_count
        {
            let operation_code_and_info = (*unwind_code_operation_code_info).to_ne_bytes().clone();
            let mut reader = BitReader::new(&operation_code_and_info);
    
            let operation_info = reader.read_u8(4).unwrap(); // operation info
            let operation_code = reader.read_u8(4).unwrap(); // operation code

            match operation_code
            {
                0 => 
                {
                    // UWOP_PUSH_NONVOL

                    if operation_info == 4 && !*found
                    {
                        return 0;
                    }

                    frame_size += 8;
                }
                1 =>
                {
                    // UWOP_ALLOC_LARGE
                    if operation_info == 0
                    {
                        let size = *(unwind_code_operation_code_info.add(1) as *mut i16);
                        frame_size += size as i32 * 8;

                        unwind_code = unwind_code.add(2);
                        index += 1;

                    }
                    else if operation_info == 1
                    {
                        let size = *(unwind_code_operation_code_info.add(1) as *mut u16) as i32;
                        let size2 = (*(unwind_code_operation_code_info.add(3) as *mut u16) as i32)  << 16;
                        frame_size += size + size2;

                        unwind_code = unwind_code.add(4);
                        index += 2;
                    }
                }
                2 =>
                {
                    // UWOP_ALLOC_SMALL
                    frame_size += (operation_info * 8 + 8) as i32;
                }
                3 =>
                {
                    // UWOP_SET_FPREG
                    if (flags & UNW_FLAG_EHANDLER) != 0 && (flags & UNW_FLAG_CHAININFO) != 0
                    {
                        *found = false;
                        return 0;
                    }

                    // This checks if the register used as FP is RBP
                    if frame_register != 5
                    {
                        *found = false;
                        return 0;
                    }

                    *found = true;
                    let offset = 16 * frame_register_offset;
                    frame_size -= offset as i32;
                }
                4 =>
                {
                    // UWOP_SAVE_NONVOL
                    unwind_code = unwind_code.add(2);
                    index += 1;
                }
                5 =>
                {
                    // UWOP_SAVE_NONVOL_FAR
                    unwind_code = unwind_code.add(4);
                    index += 2;
                }
                8 => 
                {
                    // UWOP_SAVE_XMM128 
                    unwind_code = unwind_code.add(2);
                    index += 1;
                }
                9 => 
                {
                    // UWOP_SAVE_XMM128_FAR
                    unwind_code = unwind_code.add(4);
                    index += 2;
                }
                10 =>
                {
                    // UWOP_PUSH_MACH_FRAME
                    if operation_info == 0
                    {
                        frame_size += 64; // 0x40h
                    }
                    else if operation_code == 1
                    {
                        frame_size += 72; // 0x48h
                    }
                }
                _=> {}
            }

            unwind_code = unwind_code.add(2);
            unwind_code_operation_code_info = unwind_code.add(1);
            index += 1;
        }

        // In case that the flag UNW_FLAG_CHAININFO is set, we recursively call this function.
        if (flags & UNW_FLAG_CHAININFO) != 0
        {
            if unwind_codes_count % 2 != 0
            {
                unwind_code = unwind_code.add(2);
            }

            let runtime_function: *mut RuntimeFunction = transmute(unwind_code);
            let result = get_frame_size_with_setfpreg(module, *runtime_function, found);

            frame_size += result as i32 ;
        }   

        frame_size
        
    }
    
}

fn get_frame_size_with_push_rbp(module: usize, runtime_function: RuntimeFunction, found: &mut bool, push_offset: &mut i32, frame_size: &mut i32)  
{

    unsafe
    {
        let unwind_info = (module + runtime_function.unwind_addr as usize) as *mut u8;
        let version_and_flags = (*unwind_info).to_ne_bytes().clone();
        let mut reader = BitReader::new(&version_and_flags);

        // We don't care about the version, we just need the flags to check if there is an Unwind Chain.
        let flags = reader.read_u8(5).unwrap(); 
        let unwind_codes_count = *(unwind_info.add(2)); 

        // We skip 4 bytes corresponding to Version + flags, Size of prolog, Count of unwind codes
        // and Frame Register + Frame Register offset.
        // This way we reach the Unwind codes array.
        let mut unwind_code = (unwind_info.add(4)) as *mut u8;
        let mut unwind_code_operation_code_info = unwind_code.add(1);

        let mut index = 0;
        while index < unwind_codes_count
        {
            let operation_code_and_info = (*unwind_code_operation_code_info).to_ne_bytes().clone();
            let mut reader = BitReader::new(&operation_code_and_info);
    
            let operation_info = reader.read_u8(4).unwrap(); // operation info
            let operation_code = reader.read_u8(4).unwrap(); // operation code

            match operation_code
            {
                0 => 
                {
                    // UWOP_PUSH_NONVOL
                    
                    // operation_info == 4 -> RSP
                    if operation_code == 4
                    {
                        *found = false;
                        *frame_size = 0;
                         return;
                    }

                    // operation_info == 5 -> RBP
                    if operation_info == 5
                    {
                        if *found
                        {
                            *found = false;
                            *frame_size = 0;
                            return;
                        }

                        *push_offset = *frame_size;
                        *found = true;
                    }

                    *frame_size += 8;
                }
                1 =>
                {
                    // UWOP_ALLOC_LARGE
                    if operation_info == 0
                    {
                        let size = *(unwind_code_operation_code_info.add(1) as *mut i16);
                        *frame_size += size as i32 * 8;

                        unwind_code = unwind_code.add(2);
                        index += 1;

                    }
                    else if operation_info == 1
                    {
                        let size = *(unwind_code_operation_code_info.add(1) as *mut u16) as i32;
                        let size2 = (*(unwind_code_operation_code_info.add(3) as *mut u16) as i32)  << 16;
                        *frame_size += size + size2;

                        unwind_code = unwind_code.add(4);
                        index += 2;
                    }
                }
                2 =>
                {
                    // UWOP_ALLOC_SMALL
                    *frame_size += (operation_info * 8 + 8) as i32;
                }
                3 =>
                {
                    // UWOP_SET_FPREG
                    *found = false;
                    *frame_size = 0;
                    return;
                }
                4 =>
                {
                    // UWOP_SAVE_NONVOL

                    if operation_info == 4
                    {
                        *found = false;
                        *frame_size = 0;
                        return;
                    }

                    // operation_info == 5 -> RBP
                    if operation_info == 5
                    {
                        if *found
                        {
                            *found = false;
                            *frame_size = 0;
                            return;
                        }

                        // The scaled-by-8 offset is stored in the next unwind code, which is a short (2 bytes)
                        let offset = *(unwind_code_operation_code_info.add(1) as *mut u16) as i32 * 8;
                        *push_offset = *frame_size + offset; 
                        *found = true;

                    }
                    
                    unwind_code = unwind_code.add(2);
                    index += 1;

                }
                5 =>
                {
                    // UWOP_SAVE_NONVOL_FAR

                    if operation_info == 4
                    {
                        *found = false;
                        *frame_size = 0;
                        return;
                    }

                    // operation_info == 5 -> RBP
                    if operation_info == 5
                    {
                        if *found
                        {
                            *found = false;
                            *frame_size = 0;
                            return;
                        }

                        let offset1 = *(unwind_code_operation_code_info.add(1) as *mut u16) as i32;
                        let offset2 = (*(unwind_code_operation_code_info.add(3) as *mut u16) as i32)  << 16;
                        let offset = offset1 + offset2;
                        *push_offset = *frame_size + offset;
                        *found = true;    

                    }

                    unwind_code = unwind_code.add(4);
                    index += 2;

                }
                8 => 
                {
                    // UWOP_SAVE_XMM128 
                    unwind_code = unwind_code.add(2);
                    index += 1;
                }
                9 => 
                {
                    // UWOP_SAVE_XMM128_FAR
                    unwind_code = unwind_code.add(4);
                    index += 2;
                }
                10 =>
                {
                    // UWOP_PUSH_MACH_FRAME
                    if operation_info == 0
                    {
                        *frame_size += 64; // 0x40
                    }
                    else if operation_code == 1
                    {
                        *frame_size += 72; // 0x48
                    }
                }
                _=> {}
            }

            unwind_code = unwind_code.add(2);
            unwind_code_operation_code_info = unwind_code.add(1);
            index += 1;
        }

        // In case that the flag UNW_FLAG_CHAININFO is set, we recursively call this function.
        if (flags & UNW_FLAG_CHAININFO) != 0
        {
            if unwind_codes_count % 2 != 0
            {
                unwind_code = unwind_code.add(2);
            }

            let runtime_function: *mut RuntimeFunction = transmute(unwind_code);
            get_frame_size_with_push_rbp(module, *runtime_function, found, push_offset, frame_size);

        }           
    }
    
}

// Obtain a pointer to the Exception data of an arbitrary module
fn get_runtime_table(image_ptr: *mut c_void) -> (*mut dinvoke_rs::data::RuntimeFunction, u32)
{
    unsafe 
    {
        let mut size: u32 = 0;
        let module_metadata = get_pe_metadata(image_ptr as *const u8);
        if !module_metadata.is_ok()
        {
            return (ptr::null_mut(), size);
        }

        let metadata = module_metadata.unwrap();

        let mut runtime: *mut dinvoke_rs::data::RuntimeFunction = ptr::null_mut();
        for section in &metadata.sections
        {   
            let s = std::str::from_utf8(&section.Name).unwrap();
            if s.contains(".pdata") 
            {
                let base = image_ptr as isize;
                runtime = std::mem::transmute(base + section.VirtualAddress as isize);
                size = section.SizeOfRawData;
            }
        }

        return (runtime, size);
    }

}

// Parse PE metadata of an arbitrary module
fn get_pe_metadata (module_ptr: *const u8) -> Result<PeMetadata,String>
{
    let mut pe_metadata= PeMetadata::default();

    unsafe {

        
        let e_lfanew = *((module_ptr as usize + 0x3C) as *const u32);
        pe_metadata.pe = *((module_ptr as usize + e_lfanew as usize) as *const u32);

        if pe_metadata.pe != 0x4550 
        {
            let m: &String = &lc!("[x] Invalid PE signature.");
            return Err(m.clone());
        }

        pe_metadata.image_file_header = *((module_ptr as usize + e_lfanew as usize + 0x4) as *mut ImageFileHeader);

        let opt_header: *const u16 = (module_ptr as usize + e_lfanew as usize + 0x18) as *const u16; 
        let pe_arch = *(opt_header);

        if pe_arch == 0x010B
        {
            pe_metadata.is_32_bit = true;
            let opt_header_content: *const IMAGE_OPTIONAL_HEADER32 = std::mem::transmute(opt_header);
            pe_metadata.opt_header_32 = *opt_header_content;
        }
        else if pe_arch == 0x020B 
        {
            pe_metadata.is_32_bit = false;
            let opt_header_content: *const ImageOptionalHeader64 = std::mem::transmute(opt_header);
            pe_metadata.opt_header_64 = *opt_header_content;
        } 
        else 
        {
            let m: &String = &lc!("[x] Invalid magic value.");
            return Err(m.clone());
        }

        let mut sections: Vec<IMAGE_SECTION_HEADER> = vec![];

        for i in 0..pe_metadata.image_file_header.number_of_sections
        {
            let section_ptr = (opt_header as usize + pe_metadata.image_file_header.size_of_optional_header as usize + (i * 0x28) as usize) as *const u8;
            let section_ptr: *const IMAGE_SECTION_HEADER = std::mem::transmute(section_ptr);
            sections.push(*section_ptr);
        }

        pe_metadata.sections = sections;

        Ok(pe_metadata)
    }
}