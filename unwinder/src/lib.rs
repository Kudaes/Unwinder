#[macro_use]
extern crate litcrypt2;
use_litcrypt!();

#[cfg(feature = "Experimental")]
use std::collections::HashMap;
#[cfg(feature = "Experimental")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "Experimental")]
use std::mem::size_of;
use std::{ffi::c_void, mem::transmute, ptr::{self}, vec};
use nanorand::{WyRand, Rng};
#[cfg(feature = "Experimental")]
use lazy_static::lazy_static;
#[cfg(feature = "Experimental")]
use windows::Win32::{Foundation::HANDLE, System::{Memory::MEMORY_BASIC_INFORMATION, SystemInformation::SYSTEM_INFO}};
use windows::Win32::System::Threading::GetCurrentThread;
use bitreader::BitReader;
#[cfg(feature = "Experimental")]
use dinvoke_rs::data::{PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_READWRITE};
use dinvoke_rs::data::{RuntimeFunction, ADD_RSP, JMP_RBX, PVOID, TLS_OUT_OF_INDEXES, UNW_FLAG_CHAININFO, UNW_FLAG_EHANDLER};

extern "C"
{
    fn spoof_call(structure: PVOID) -> PVOID;
    #[cfg(feature = "Experimental")]
    fn spoof_call2(structure: PVOID) -> PVOID;
    pub fn get_current_rsp() -> usize;
    #[cfg(feature = "Experimental")]
    pub fn get_current_function_address() -> usize;
    #[cfg(feature = "Experimental")]
    pub fn start_replacement(structure: PVOID);
    #[cfg(feature = "Experimental")]
    pub fn end_replacement(structure: PVOID);
}

#[cfg(feature = "Experimental")]
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct NewStackInfo
{
    rtladdr: usize, 
    rtlsize: usize, 
    baseaddr: usize, 
    basesize: usize,
    current_size: usize,
    total_size: usize,
}

#[repr(C)] 
struct Configuration
{
    god_gadget: usize, // Unsed atm
    rtl_unwind_address: usize, // Unsed atm
    rtl_unwind_target: usize, // Unsed atm
    stub: usize, // Unsed atm
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

static mut TLS_INDEX: u32 = 0;
#[cfg(feature = "Experimental")]
static mut RUNTIME_INFO: (usize, u32) = (0, 0);
#[cfg(feature = "Experimental")]
static mut BASE_ADDRESS: usize = 0; // Current module's base address
#[cfg(feature = "Experimental")]
lazy_static! {
    // Original return address -> key
    // Replacement return address -> value
    pub static ref MAP: Arc<Mutex<HashMap<usize,usize>>> = Arc::new(Mutex::new(HashMap::default()));
}

/// The `replace_and_continue` macro is designed to spoof the last return address in the call stack to conceal the presence of anomalous entries. 
///
/// This macro calculates the size of the last frame at runtime and searches for another function with the same size in a legitimately loaded DLL within 
/// the current process. The legitimate function is used then as replacement return address, allowing to hide the last entry in the call stack.
///
/// The real replaced return addresses are stored in an internal structure so they can be restored later when the `restore` macro is called.
///
/// To use this macro, the `start_replacement` macro must have been called previously to initialize the necessary structures. Any
/// function calling this macro should declare the `#[inline(never)]` attribute (exported functions through the `#[no_mangle]` attribute doest not need to 
/// additionally declare the inline attribute).
///
/// # Example
///
/// ```rust
/// #[inline(never)] // This attribute is mandatory for any function calling this macro
/// fn another_function() -> bool
/// {
///     unwinder::replace_and_continue();
///     ...
///     unwinder::restore();
///     
///     true
/// } 
/// 
/// #[no_mangle]
/// fn your_program_entry(base_address: usize) -> bool
/// {
///     unwinder::start_replacement!(base_address);
///     let r = another_function();
///     unwinder::end_replacement!();
/// 
///     r
/// }
/// ```
///
#[cfg(feature = "Experimental")]
#[macro_export]
macro_rules! replace_and_continue {

    () => {{
        unsafe
        {
            
            //  We get the current function's frame size by iterating the current module's
            //  unwinding info looking for the function's address.
            let current_function_address = $crate::get_current_function_address();
            let current_function_size = $crate::get_frame_size_from_address(current_function_address);

            //  We get the current position of RSP, which combined with the current frame size
            //  allows us to obtain the position in the stack of the return address to spoof.
            let current_rsp = $crate::get_current_rsp() as *mut usize;
            let n = current_function_size/8;
            let return_address_ptr = current_rsp.add(n as _);
            let return_address: usize = *return_address_ptr;

            //  We check if the original return address has already being processed, in which case the pre calculated
            //  replacement return address is retrieved. Otherwise, We calculate a replacement return address. 
            let map = std::sync::Arc::clone(&$crate::MAP);
            let mut map = map.lock().unwrap();
            if let Some(h) = map.get_mut(&return_address) {
                *return_address_ptr = *h;
            }
            else 
            {
                //  We get the last frame size by iterating the current module's unwinding info.
                let replacement_function_size = $crate::get_frame_size_from_address(return_address);
                let mut black_list: Vec<usize> = vec![];
                for (_, value) in map.iter() {
                black_list.push(*value);
                }

                //  We look for a legitimate return address contained in a function with the same frame size as that of
                //  as previously calculated. Once found a legitimate replacement, the return address is spoofed.
                let replacement_frame = $crate::get_frame_of_size(replacement_function_size, black_list, false);
                *return_address_ptr = replacement_frame;
                map.insert(return_address, replacement_frame);
            }
        }
    }}
}

/// The `restore` macro is the inverse of the `replace_and_continue` macro.
///
/// This macro should be called at the end of all functions that have called the `replace_and_continue` macro.
/// Its primary objective is to restore the return address to its original value, allowing the program to continue
/// normal execution.
///
/// Similar to the `replace_and_continue` macro, any function that calls the `restore` macro must declare the attribute
/// `#[inline(never)]`, unless the function is exported using the `#[no_mangle]` attribute, in which case the `#[inline(never)]`
/// attribute is not required.
///
/// # Example
///
/// ```rust
/// #[inline(never)] // This attribute is mandatory for any function calling this macro
/// fn another_function() -> bool
/// {
///     unwinder::replace_and_continue();
///     ...
///     unwinder::restore();
///     
///     true
/// } 
/// 
/// #[no_mangle]
/// fn your_program_entry(base_address: usize) -> bool
/// {
///     unwinder::start_replacement!(base_address);
///     let r = another_function();
///     unwinder::end_replacement!();
/// 
///     r
/// }
/// ```
#[cfg(feature = "Experimental")]
#[macro_export]
macro_rules! restore {

    () => {{
        unsafe
        {
            //  We calculate the position in the stack where the return address is located and we
            //  restore its value to that of the original address, allowing the program to continue the normal execution.
            let current_function_address = $crate::get_current_function_address();
            let current_function_size = $crate::get_frame_size_from_address(current_function_address);

            let current_rsp = $crate::get_current_rsp() as *mut usize;
            let n = current_function_size/8;
            let return_address_ptr = current_rsp.add(n as _);
            let return_address: usize = *return_address_ptr;

            let map = std::sync::Arc::clone(&$crate::MAP);
            let mut map = map.lock().unwrap();
            for (key, value) in map.iter()
            {
                if *value == return_address
                {
                    *return_address_ptr = *key;
                    break;
                }
            }
        }
    }}
}

/// The `start_replacement` macro initiates the stack replacement process.
///
/// This macro expects a single parameter of type `usize`. This parameter represents
/// the base memory address of the current module, or zero if the base address is unknown.
///
/// If a non-zero memory address is provided, the macro will use it to locate information
/// regarding the module. If zero is passed, the macro will perform its own process to
/// determine the base memory address.
///
/// The primary goal of this macro is to initiate the stack replacement process. 
/// To achieve this, it initializes all necessary structures and creates a clean stack
/// on top of the existing one. This new stack will be used by the program until the
/// `end_replacement` macro is called, allowing to have a clean call stack during the execution of your code.
///
/// # Parameters
///
/// - `base_address: usize`: The base memory address of the current module or zero.
///
/// # Example
///
/// ```rust
/// #[no_mangle]
/// fn your_program_entry(base_address: usize) -> bool
/// {
///     unwinder::start_replacement!(base_address);
///     ...
///     unwinder::end_replacement!();
/// 
///     true
/// }
/// ```
#[cfg(feature = "Experimental")]
#[macro_export]
macro_rules! start_replacement {
    ($x:expr) =>
    {
        unsafe
        {
            //  The start_stack_replacement function locates the current module's base address if it has not 
            //  been specified when calling the macro. With that address, it locates the module's unwind data
            //  to be used later on.
            let start = $crate::start_stack_replacement($x);
            
            //  We get the current function's frame size and other data required to create a new stack on top
            //  of the existing one that will be used by this and any nested function being called from now on.
            let address = $crate::get_current_function_address();
            let mut base_pointer = false; // This variable is unused at the moment.
            let current_function_size = $crate::get_frame_size_from_address(address);
            
            let structure = $crate::get_info_structure(current_function_size as usize);
            let structure: *mut c_void = std::mem::transmute(&structure);
            //  The start_replacement stub creates the new stack and moves the current frame's contents to their new locations.
            $crate::start_replacement(structure);
        }
    } 
} 

/// The `end_replacement` macro finalizes the stack replacement process.
///
/// Its primary function is to restore the stack state to what it was before
/// the `start_replacement` macro was called, allowing to continue the execution outside
/// of the current module.
///
/// Calling this macro ends the stack replacement process, ensuring that all necessary
/// structures and states are properly restored.
///
/// This macro should be called at the end of any function that made the call to the
/// `start_replacement` macro.
///  
/// # Example
///
/// ```rust
/// #[no_mangle]
/// fn your_program_entry(base_address: usize) -> bool
/// {
///     unwinder::start_replacement!(base_address);
///     ...
///     unwinder::end_replacement!();
/// 
///     true
/// }
/// ```
#[cfg(feature = "Experimental")]
#[macro_export]
macro_rules! end_replacement {
    () =>
    {
        unsafe
        {
            // We just remove the previously crafted new stack, restoring the previous state.
            let address = $crate::get_current_function_address();
            let current_function_size = $crate::get_frame_size_from_address(address);
    
            let structure = $crate::get_info_structure(current_function_size as usize);
            let structure: *mut c_void = std::mem::transmute(&structure);
            $crate::end_replacement(structure);
        }
    }
} 

/// The `replace_and_call` macro is used to apply stack replacement when calling a function that resides outside of the current module.
///
/// This macro acts as a gateway, spoofing the last entry in the call stack before jumping to the memory address of the specified function.
/// 
/// To use this macro, the `start_replacement` macro must have been called previously to initialize the necessary structures. Any
/// function calling this macro should declare the `#[inline(never)]` attribute (exported functions using the `#[no_mangle]` attribute doest not need to 
/// additionally declare the inline attribute).
/// 
/// The first parameter the macro expects is the memory address of the function to be called after applying the stack replacement process.
/// The rest of the parameters are the arguments to be passed to the specified function.
/// 
/// The return value of the macro is the same as the return value of the function specified in the first parameter.
///
/// # Parameters
///
/// - `function_address: usize`: The memory address of the function to be called.
/// - `args...`: The arguments to be passed to the function.
///
/// # Example
///
/// ```rust
/// #[inline(never)] // This attribute is mandatory for any function calling this macro
/// fn another_function() -> bool
/// {
///     unwinder::replace_and_continue();
///     ...
///     let k32 = dinvoke_rs::dinvoke::get_module_base_address("kernel32.dll");
///     let sleep = dinvoke_rs::dinvoke::get_function_address(k32, "Sleep"); // Memory address of kernel32.dll!Sleep() 
///     let miliseconds = 1000i32;
///     unwinder::replace_and_call!(sleep, false, miliseconds);
///     ...
///     unwinder::restore();
///     
///     true
/// } 
/// 
/// #[no_mangle]
/// fn your_program_entry(base_address: usize) -> bool
/// {
///     unwinder::start_replacement!(base_address);
///     let r = another_function();
///     unwinder::end_replacement!();
/// 
///     r
/// }
/// ```
#[cfg(feature = "Experimental")]
#[macro_export]
macro_rules! replace_and_call {

    ($($x:expr),*) => {{

        unsafe
        {
            let mut temp_vec = Vec::new();
            $(
                let temp = $x as usize; // This is meant to convert integers with smaller size than 8 bytes
                let pointer: *mut c_void = std::mem::transmute(temp);
                temp_vec.push(pointer);
            )*

            let res = $crate::replace_and_call(temp_vec, false, 0);
            res
        }
    }}
}

/// The `replace_and_syscall` macro is used to apply stack replacement when performing an indirect syscall.
///
/// This macro acts as a gateway, spoofing the last entry in the call stack before executing the indirect syscall
/// to the specified NT function.
///
/// To use this macro, the `start_replacement` macro must have been called previously in another function to initialize the necessary structures. Any
/// function calling this macro should declare the `#[inline(never)]` attribute (exported functions using the `#[no_mangle]` attribute doest not need to 
/// additionally declare the inline attribute).
/// 
/// The first parameter the macro expects is the name of the NT function whose indirect syscall is to be executed.
/// The rest of the parameters are the arguments to be passed to the specified NT function.
/// 
/// The return value of the macro is the `NTSTATUS` value returned by the NT function.
///
/// # Parameters
///
/// - `nt_function_name: &str`: The name of the NT function to be called.
/// - `args...`: The arguments to be passed to the NT function.
///
/// # Example
///
/// ```rust
/// #[inline(never)] // This attribute is mandatory for any function calling this macro
/// fn another_function() -> bool
/// {
///     unwinder::replace_and_continue();
///     ...
///     let large = 0x8000000000000000 as u64; // Sleep indefinitely
///     let large: *mut i64 = std::mem::transmute(&large);
///     let alertable = false;
///     let ntstatus = unwinder::replace_and_syscall!("NtDelayExecution", alertable, large);
///     println!("ntstatus: {:x}", ntstatus as usize);
///     ...
///     unwinder::restore();
///     
///     true
/// } 
/// 
/// #[no_mangle]
/// fn your_program_entry(base_address: usize) -> bool
/// {
///     unwinder::start_replacement!(base_address);
///     let r = another_function();
///     unwinder::end_replacement!();
/// 
///     r
/// }
/// ```
#[cfg(feature = "Experimental")]
#[macro_export]
macro_rules! replace_and_syscall {

    ($a:expr, $($x:expr),*) => {{

        unsafe
        {
            let mut temp_vec = Vec::new();
            let t = $crate::prepare_syscall($a);
            let p: *mut c_void = std::mem::transmute(t.1);
            temp_vec.push(p);
            $(
                let temp = $x as usize; // This is meant to convert integers with smaller size than 8 bytes
                let pointer: *mut c_void = std::mem::transmute(temp);
                temp_vec.push(pointer);
            )*
            
            let res = $crate::replace_and_call(temp_vec, true, t.0);
            res
        }
    }}
}

/// This function is reponsible of retrieving all the information required to create the new
/// stack when the stack replacemnent process is started.
/// The returned struct gathers all the required information, including the first three frames sizes, the new stack
/// total size and the first two return addresses (RtlUserThreadStart+0x21 and BaseThreadInitThunk+0x14). 
#[cfg(feature = "Experimental")]
#[inline(never)]
pub fn get_info_structure(current_size: usize) -> NewStackInfo
{
    unsafe
    {
        let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&lc!("ntdll.dll"));
        let kernel32 = dinvoke_rs::dinvoke::get_module_base_address(&lc!("kernel32.dll"));
    
        let rtl_user_thread_start = dinvoke_rs::dinvoke::get_function_address(ntdll, &lc!("RtlUserThreadStart"));
        let size_rtl: i32 = get_frame_size_from_address_any_module(ntdll as _, rtl_user_thread_start as _);
        let rtl_user_thread_start_address = rtl_user_thread_start as usize + 0x21 as usize;
    
        let base_thread_init_thunk = dinvoke_rs::dinvoke::get_function_address(kernel32, &lc!("BaseThreadInitThunk"));
        let size_base = get_frame_size_from_address_any_module(kernel32 as _, base_thread_init_thunk as _);
        let base_thread_init_thunk_address = base_thread_init_thunk as usize + 0x14 as usize;
    
        let mut stack_info: NewStackInfo = std::mem::zeroed(); 
        stack_info.rtladdr = rtl_user_thread_start_address;
        stack_info.rtlsize = size_rtl as usize;
        stack_info.baseaddr = base_thread_init_thunk_address;
        stack_info.basesize = size_base as usize;
        stack_info.current_size = current_size;
        stack_info.total_size = size_rtl as usize + size_base  as usize + current_size + 32 ; // 16 (two return addresses) * 2 (alignment?)
          
        stack_info
    }
}

#[cfg(feature = "Experimental")]
#[inline(never)]
pub fn start_stack_replacement(base_address: usize) -> bool
{
    unsafe
    {
        if BASE_ADDRESS != 0 && RUNTIME_INFO != (0,0) {
            return true;
        }
        
        let runtime_info = get_current_runtime_table(base_address);
        if runtime_info.1 == 0 {
            return false;
        }
    
        RUNTIME_INFO = (runtime_info.0 as _, runtime_info.1);
        true
    }
}

/// Given a module's base address and the address of one of its functions, it will iterate over the module's unwind data
/// in order to get the function's frame size in bytes.
/// In case that the function has not been located, it will return 0.
#[cfg(feature = "Experimental")]
#[inline(never)]
pub fn get_frame_size_from_address_any_module(mut module: usize, address: usize) -> i32
{   
    unsafe
    {
        if module == 0
        {
            let module_handle = 0usize;
            let module_handle: *mut usize = std::mem::transmute(&module_handle);
            dinvoke_rs::dinvoke::get_module_handle_ex_a(0x00000004|0x00000002 , address as _, module_handle);
            if *module_handle == 0 {
                return 0;
            } else {
                module = *module_handle;
            }
        }
    
        let exception_directory = get_runtime_table(module as *mut _);
        let mut rt = exception_directory.0;
        if rt == ptr::null_mut() {
            return 0;
        }
        
        let items = exception_directory.1 / 12;
        let mut count = 0;
        while count < items
        {
            let function_start_address = (module + (*rt).begin_addr as usize) as *mut u8;
            let function_end_address = (module + (*rt).end_addr as usize) as *mut u8;
            if address >= function_end_address as usize || address < function_start_address as usize 
            {
                rt = rt.add(1);
                count += 1;
                continue;
            }
            else 
            {
                let size = get_frame_size_normal(module, *rt, true, &mut false);
                return size;
            }    
            
        }
    
        0  
    }
}

/// Given a function's address, it will iterate over the current module's unwind data
/// in order to get the function's frame size in bytes.
/// In case that the function has not been located, it will return 0.
#[cfg(feature = "Experimental")]
#[inline(never)]
pub fn get_frame_size_from_address(address: usize) -> i32
{   
    unsafe
    {
        let items = RUNTIME_INFO.1 / 12;
        let mut count = 0;
        let mut rt = RUNTIME_INFO.0 as *mut RuntimeFunction;

        while count < items
        {   
            let runtime_function = *rt;
            if address < BASE_ADDRESS + runtime_function.begin_addr as usize || runtime_function.begin_addr == 0 || runtime_function.end_addr == 0 {
                break;
            }
            
            if address >= BASE_ADDRESS + runtime_function.end_addr as usize
            {
                rt = rt.add(1);
                count += 1;
                continue;
            }
            else 
            {
                let size = get_frame_size_normal(BASE_ADDRESS, runtime_function, true, &mut false);
                return size;
            }      
        }
    
        0  
    } 
}


/// Given a frame size, this function will look for a function in kernel32.dll/kernelbase.dll/ntdll.dll with the same
/// frame size. In case it finds it, it will return its memory address; otherwise it returns 0.
/// 
/// The black_list argument allows to specify a list of functions that shouldn't be returned when calling this function.
/// The ignore argument should be set to false in case we want to discard any function that sets a base pointer (UWOP_SET_FPREG unwind code).
#[cfg(feature = "Experimental")]
#[inline(never)]
pub fn get_frame_of_size(desired_size: i32, black_list: Vec<usize>, ignore: bool) -> usize
{
    unsafe
    {
        let k32: usize = dinvoke_rs::dinvoke::get_module_base_address(&lc!("kernel32.dll")) as usize;

        let exception_directory = get_runtime_table(k32 as *mut _);
        let mut rt = exception_directory.0;
        if rt == ptr::null_mut() {
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
            let size = get_frame_size_normal(k32, runtime_function, ignore, &mut false);
            if size == desired_size
            {
                let random_offset = generate_random_offset(k32, runtime_function);
                let final_address = k32 + random_offset as usize;
    
                if random_offset != 0 && !black_list.contains(&final_address){    
                    return  final_address;
                }
            }
    
            rt = rt.add(1);
            count += 1;
        }
    
        let kernelbase = dinvoke_rs::dinvoke::get_module_base_address(&lc!("kernelbase.dll")) as usize;
    
        let exception_directory = get_runtime_table(kernelbase as *mut _);
        let mut rt = exception_directory.0;
        if rt == ptr::null_mut() {
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
            let size = get_frame_size_normal(kernelbase, runtime_function, ignore, &mut false);
            if size == desired_size
            {
                let random_offset = generate_random_offset(kernelbase, runtime_function);
                let final_address = kernelbase + random_offset as usize;
    
                if random_offset != 0 && !black_list.contains(&final_address){        
                    return  final_address;
                }
            }
    
            rt = rt.add(1);
            count += 1;
        }
    
        let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&lc!("ntdll.dll")) as usize;
    
        let exception_directory = get_runtime_table(ntdll as *mut _);
        let mut rt = exception_directory.0;
        if rt == ptr::null_mut() {
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
            let size = get_frame_size_normal(ntdll, runtime_function, ignore, &mut false);
            if size == desired_size
            {
                let random_offset = generate_random_offset(ntdll, runtime_function);
                let final_address = ntdll + random_offset as usize;
    
                if random_offset != 0 && !black_list.contains(&final_address){        
                    return  final_address;
                }
            }
    
            rt = rt.add(1);
            count += 1;
        }
    
        0
    }
}

/// Spoofs the previous return address and jumps to the stub that contains the assembly code responsible for
/// preparing the stack/registers and make the call to the final function. 
#[cfg(feature = "Experimental")]
#[inline(never)]
pub fn replace_and_call(mut args: Vec<*mut c_void>, is_syscall: bool, id: u32) -> *mut c_void
{
    unsafe
    {
        if is_syscall && (id == u32::MAX) {
            return ptr::null_mut();
        }
    
        let mut config: Configuration = std::mem::zeroed();
        let mut black_list: Vec<(u32,u32)> = vec![];
        let kernelbase = dinvoke_rs::dinvoke::get_module_base_address(&lc!("kernelbase.dll")) as usize;
    
        let mut first_gadget_size = 0i32;
        let first_gadget_addr = find_gadget(kernelbase, &mut first_gadget_size, 0, &mut black_list);
    
        let mut second_gadget_size = 0i32;
        let second_gadget_addr = find_gadget(kernelbase, &mut second_gadget_size, 1, &mut black_list);
        
        config.jmp_rbx_gadget = first_gadget_addr as *mut _;
        config.jmp_rbx_gadget_frame_size = first_gadget_size as usize;
        config.add_rsp_xgadget = second_gadget_addr as *mut _;
        config.add_rsp_xgadget_frame_size = second_gadget_size as usize;
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
    
        let current_function_address = get_current_function_address();
        let current_function_size = get_frame_size_from_address(current_function_address);
        let current_function_replacement = get_frame_of_size(current_function_size, Vec::default(), false) as *mut usize;
        config.return_address = current_function_replacement as _; 
    
        let current_rsp = get_current_rsp() as *mut usize;
        let n = current_function_size/8;
        let return_address_ptr = current_rsp.add(n as _);
        let return_address: usize = *return_address_ptr;
     
        let replaced_function_size = get_frame_size_from_address(return_address);
        let replacement_frame = get_frame_of_size(replaced_function_size, Vec::default(), false);
        *return_address_ptr = replacement_frame;
        
        let config: PVOID = std::mem::transmute(&config);
        let r = spoof_call2(config);
        *return_address_ptr = return_address;
    
        r   
    }
}

#[cfg(feature = "Experimental")]
fn get_current_runtime_table(mut base_address: usize) -> (*mut dinvoke_rs::data::RuntimeFunction, u32)
{
    unsafe
    {
        if base_address == 0
        {
            base_address = get_pe_baseaddress();
            if base_address == 0 {
                return (ptr::null_mut(), 0);
            }
        }
    
        BASE_ADDRESS = base_address;
    
        get_runtime_table(BASE_ADDRESS as _)
    }
}

#[cfg(feature = "Experimental")]
fn get_pe_baseaddress () -> usize 
{
    unsafe
    {
        let b = vec![0u8; size_of::<SYSTEM_INFO>()];
        let si: *mut SYSTEM_INFO = std::mem::transmute(b.as_ptr());
        dinvoke_rs::dinvoke::get_system_info(si);
    
        let main_address = get_pe_baseaddress as usize;
    
        let mut mem = 0usize;
        let max = (*si).lpMaximumApplicationAddress as usize;
        let mut previous_region = MEMORY_BASIC_INFORMATION::default();
        while mem < max
        {
            let buffer = MEMORY_BASIC_INFORMATION::default();
            let buffer: *mut MEMORY_BASIC_INFORMATION = std::mem::transmute(&buffer);
            let length = size_of::<MEMORY_BASIC_INFORMATION>();
            let _r = dinvoke_rs::dinvoke::virtual_query_ex(
                HANDLE(-1), 
                mem as *const c_void, 
                buffer, 
                length
            );       
    
            let is_readable: bool = (*buffer).Protect.0 == PAGE_READONLY || (*buffer).Protect.0 == PAGE_READWRITE || (*buffer).Protect.0 == PAGE_EXECUTE_READ || (*buffer).Protect.0 == PAGE_EXECUTE_READWRITE;
            
            if is_readable
            {
                if main_address >= ((*buffer).BaseAddress as usize) && main_address <= ((*buffer).BaseAddress as usize + (*buffer).RegionSize ) {
                    return previous_region.BaseAddress as usize;
                }
    
                previous_region = *buffer;                
            }
    
            mem = (*buffer).BaseAddress as usize + (*buffer).RegionSize;
        }
        0
    }
}


/// Call an arbitrary function with a clean call stack.
/// 
/// This macro will make sure the thread has a clean and unwindable call stack
/// before calling the specified function.
/// 
/// The first parameter expected by the macro is the memory address of the function to call. 
/// The second parameter is a bool indicating whether or not keep the start function frame. If you are not
/// sure about this, set it to false which always guarantees a clean call stack. 
/// 
/// The following parameters should be the arguments to pass to the specified function.
/// 
/// The macro's return parameter is the same value returned by the specified function.
/// 
/// # Example - Calling Sleep() with a clean call stack (using dinvoke_rs)
/// 
/// ```ignore
/// let k32 = dinvoke_rs::dinvoke::get_module_base_address("kernel32.dll");
/// let sleep = dinvoke_rs::dinvoke::get_function_address(k32, "Sleep"); // Memory address of kernel32.dll!Sleep() 
/// let miliseconds = 1000i32;
/// unwinder::call_function!(sleep, false, miliseconds);
/// ```
/// 
#[macro_export]
macro_rules! call_function {

    ($($x:expr),*) => {{

        unsafe
        {
            let mut temp_vec = Vec::new();
            $(
                let temp = $x as usize; // This is meant to convert integers with smaller size than 8 bytes
                let pointer: *mut c_void = std::mem::transmute(temp);
                temp_vec.push(pointer);
            )*
                
            let res = $crate::spoof_and_call(temp_vec, false, 0);
            res
        }
    }}
}

/// Execute an indirect syscall with a clean call stack.
/// 
/// This macro will make sure the thread has a clean and unwindable call stack
/// before executing the syscall for the specified NT function.
/// 
/// The first parameter expected by the macro is the name of the function whose syscall wants to be run. 
/// The second parameter is a bool indicating whether or not keep the start function frame. If you are not
/// sure about this, set it to false which always guarantees a clean call stack. 
/// 
/// The following parameters should be the arguments expected by the specified syscall.
/// 
/// The macro's return parameter is the same value returned by the syscall.
/// 
/// # Example - Calling NtDelayExecution() as indirect syscall with a clean call stack
/// 
/// ```ignore
/// let large = 0x8000000000000000 as u64; // Sleep indefinitely
/// let large: *mut i64 = std::mem::transmute(&large);
/// let alertable = false;
/// let ntstatus = unwinder::indirect_syscall!("NtDelayExecution", false, alertable, large);
/// println!("ntstatus: {:x}", ntstatus as usize);
/// ```
/// 
#[macro_export]
macro_rules! indirect_syscall {

    ($a:expr, $($x:expr),*) => {{

        unsafe
        {
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
        }
    }}
}

/// Don't call this function directly, use call_function!() and indirect_syscall!() macros instead.
pub fn spoof_and_call(mut args: Vec<*mut c_void>, is_syscall: bool, id: u32) -> *mut c_void
{
    unsafe
    {
        if is_syscall && (id == u32::MAX) {
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
    
        let keep = args.remove(0) as usize;
        let keep_start_function_frame;
        if keep == 0 {
            keep_start_function_frame = false;
        } else {
            keep_start_function_frame = true;
        }
    
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
            spoofy = get_desirable_return_address(current_rsp, keep_start_function_frame);           
        }
    
        config.return_address = spoofy as *mut _; 
        let config: PVOID = std::mem::transmute(&config);
        spoof_call(config)
    }
}


// This functions will returns the main module's frame address in the stack.
// If it fails to do so, it will return the BaseThreadInitThunk's frame address instead.
fn get_desirable_return_address(current_rsp: usize, keep_start_function_frame: bool )-> usize
{
    unsafe
    {
        let k32 = dinvoke_rs::dinvoke::get_module_base_address(&lc!("kernel32.dll"));
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
        if keep_start_function_frame
        {
            // Obtain current thread's start address
            let ret = dinvoke_rs::dinvoke::nt_query_information_thread(thread_handle, thread_info_class, thread_information, thread_info_len, ret_len);

            if ret == 0 
            {
                let thread_information = thread_information as *mut usize; 

                let flags = 0x00000004;
                let function_address: *const u8 = *thread_information as _;
                let module_handle = 0usize;
                let module_handle: *mut usize = std::mem::transmute(&module_handle);

                // Determine the module where the current thread's start function is located at.
                let ret = dinvoke_rs::dinvoke::get_module_handle_ex_a(flags, function_address, module_handle);

                if ret
                {
                    let base_address = *module_handle;
                    let function_addresses = get_function_size(base_address, function_address as _);
                    start_address = function_addresses.0;
                    end_address = function_addresses.1;
                }
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
                let data = dinvoke_rs::dinvoke::tls_get_value(TLS_INDEX) as *mut usize;
                *data = addr;
                found = true;
            }

            stack_iterator = stack_iterator.add(1);
        }

        addr
    }
}

// TLS is used to store the main module's/BaseThreadInitThunk's frame top address in the stack.
// This allows to efficiently concatenate the spoofing process as many times as needed.
fn get_cookie_value() -> usize
{
    unsafe
    {
        if TLS_INDEX == 0
        {
            let r = dinvoke_rs::dinvoke::tls_alloc();
            if r == TLS_OUT_OF_INDEXES {
                return 0;
            }
    
            TLS_INDEX = r;
        }
    
        let value = dinvoke_rs::dinvoke::tls_get_value(TLS_INDEX) as *mut usize;
        if value as usize == 0
        {   
            if  dinvoke_rs::dinvoke::get_last_error() != 0 
            {
                let heap_region = dinvoke_rs::dinvoke::local_alloc(0x0040, 8); // 0x0040 = LPTR
                if heap_region != ptr::null_mut() {
                    let _ = dinvoke_rs::dinvoke::tls_set_value(TLS_INDEX, heap_region);
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
        if rt == ptr::null_mut() {
            return (0,0);
        }
        
        let items = exception_directory.1 / 12;
        let mut count = 0;
        while count < items
        {
            let function_start_address = (base_address + (*rt).begin_addr as usize) as *mut u8;
            let function_end_address = (base_address + (*rt).end_addr as usize) as *mut u8;
            if function_address >= function_start_address as usize && function_address < function_end_address as usize  {
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
    if id != u32::MAX
    {
        
        let function_addr = dinvoke_rs::dinvoke::get_function_address(ntdll, function_name);
        let syscall_addr: usize = dinvoke_rs::dinvoke::find_syscall_address(function_addr as usize);
        if syscall_addr != 0 {
            return (id as u32,syscall_addr);
        }

        let max_range = eat.len();
        let mut rng: WyRand = WyRand::new();
        loop 
        {
            let mut function = &"".to_string();
            for s in eat.values()
            {
                let index = rng.generate_range(0..max_range);
                if index < max_range / 5
                {
                    function = s;
                    break;
                }
            }

            let function_addr = dinvoke_rs::dinvoke::get_function_address(ntdll, function);
            let syscall_addr: usize = dinvoke_rs::dinvoke::find_syscall_address(function_addr as usize);
            if syscall_addr != 0 {
                return (id as u32,syscall_addr);
            }   
        }
    }
    
    (u32::MAX,0)
}

// Function used to find the JMP RBX and ADD RSP gadgets.
fn find_gadget(module: usize, gadget_frame_size: &mut i32, arg: i32, black_list:  &mut Vec<(u32,u32)>) -> usize 
{
    unsafe
    {
        let exception_directory = get_runtime_table(module as *mut _);
        let mut rt = exception_directory.0;
        if rt == ptr::null_mut() {
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
                    *gadget_frame_size = get_frame_size_normal(module, *rt, false, &mut false);
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
fn find_setfpreg(module: usize, frame_size: &mut i32, black_list: &mut Vec<(u32,u32)>) -> usize 
{
    unsafe
    {
        let exception_directory = get_runtime_table(module as *mut _);
        let mut rt = exception_directory.0;
        if rt == ptr::null_mut() {
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
fn find_pushrbp(module: usize, frame_size: &mut i32, push_offset: &mut i32, black_list: &mut Vec<(u32,u32)>) -> usize 
{
    unsafe
    {
        let exception_directory = get_runtime_table(module as *mut _);
        let mut rt = exception_directory.0;
        if rt == ptr::null_mut() {
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
    let pattern = vec![0x48,0xff,0x15]; // 0x48 0xff 0x15 00 00 00 00 = rex.W call QWORD PTR [rip+0x0]
    let address = find_pattern(start_address, end_address, pattern);
    
    if address == -1 || address + 7 >= end_address as isize {
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
    
                if found {
                    return start_address as isize;
                }
    
            }
    
            start_address += 1;
        }
    
        -1
    }
}

fn get_frame_size_normal(module: usize, runtime_function: RuntimeFunction, ignore_rsp_and_bp: bool, base_pointer: &mut bool) -> i32 
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
        // This counter stores the size of the stack frame in bytes.
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
                    if operation_code == 4 && !ignore_rsp_and_bp {
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
                    // UWOP_SET_FPREG // Dynamic alloc "does not change" frame's size 
                    *base_pointer = true; // This is not used atm
                    if !ignore_rsp_and_bp {
                        return 0; // This is meant to prevent the use of return addresses corresponding to functions that set a base pointer
                    }
    
                }
                4 =>
                {
                    // UWOP_SAVE_NONVOL
                    // operation_info == 4 -> RSP
                    if operation_info == 4 && !ignore_rsp_and_bp {
                        return 0;
                    }
    
                    unwind_code = unwind_code.add(2);
                    index += 1;
                }
                5 =>
                {
                    // UWOP_SAVE_NONVOL_FAR
                    // operation_info == 4 -> RSP
                    if operation_info == 4 && !ignore_rsp_and_bp {
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
                    if operation_info == 0 {
                        frame_size += 64; // 0x40h
                    } else if operation_code == 1 {
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
            if unwind_codes_count % 2 != 0 {
                unwind_code = unwind_code.add(2);
            }
    
            let runtime_function: *mut RuntimeFunction = transmute(unwind_code);
            let result = get_frame_size_normal(module, *runtime_function, ignore_rsp_and_bp, base_pointer);
    
            frame_size += result as i32;
        }   
    
        frame_size
    }
}

fn get_frame_size_with_setfpreg(module: usize, runtime_function: RuntimeFunction, found: &mut bool) -> i32 
{
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
        // This counter stores the size of the stack frame in bytes.
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
    
                    if operation_info == 4 && !*found {
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
                    if operation_info == 0 {
                        frame_size += 64; // 0x40h
                    } else if operation_code == 1 {
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
            if unwind_codes_count % 2 != 0 {
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
                    if operation_info == 0 {
                        *frame_size += 64; // 0x40
                    } else if operation_code == 1 {
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
            if unwind_codes_count % 2 != 0 {
                unwind_code = unwind_code.add(2);
            }
    
            let runtime_function: *mut RuntimeFunction = transmute(unwind_code);
            get_frame_size_with_push_rbp(module, *runtime_function, found, push_offset, frame_size);
    
        }  
    }             
}

/// Returns a pair containing a pointer to the Exception data of an arbitrary module and the size of the  
/// corresponding PE section (.pdata). In case that it fails to retrieve this information, it returns
/// null values (ptr::null_mut(), 0).
fn get_runtime_table(image_ptr: *mut c_void) -> (*mut dinvoke_rs::data::RuntimeFunction, u32)
{
    unsafe
    {
        let module_metadata = dinvoke_rs::manualmap::get_pe_metadata(image_ptr as *const u8);
        if !module_metadata.is_ok() {
            return (ptr::null_mut(), 0);
        }
    
        let metadata = module_metadata.unwrap();
        
        let mut size: u32 = 0;
        let mut runtime: *mut dinvoke_rs::data::RuntimeFunction = ptr::null_mut();
        for section in &metadata.sections
        {   
            let s = std::str::from_utf8(&section.Name).unwrap();
            if s.contains(".pdata") 
            {
                let base = image_ptr as isize;
                runtime = std::mem::transmute(base + section.VirtualAddress as isize);
                size = section.SizeOfRawData;
                return (runtime, size);
            }
        }
    
        (runtime, size)
    }
}