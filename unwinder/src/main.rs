#![feature(link_llvm_intrinsics)]

use std::{ffi::c_void, ptr, mem::transmute};
use rand::Rng;

use bindings::Windows::Win32::System::Diagnostics::Debug::{IMAGE_SECTION_HEADER, IMAGE_OPTIONAL_HEADER32};
use bitreader::BitReader;
use data::{PeMetadata, IMAGE_FILE_HEADER, IMAGE_OPTIONAL_HEADER64, RUNTIME_FUNCTION};

extern {
    #[link_name = "llvm.addressofreturnaddress"]
    fn return_address() -> *const u8;
}

///
/// List of functions used to spoof the stack. 
/// You can add any Windows APi function that you 
/// want to use, taking into account that not all 
/// unwind codes have been implemented in this PoC.
/// 
const FUNCTIONS: [&str; 12] = [
    "kernelbase.dll!WriteProcessMemory",
    "kernelbase.dll!ReadProcessMemory",
    "kernelbase.dll!CloseHandle",
    "kernelbase.dll!DsFreeNameResultW",
    "kernelbase.dll!K32EnumProcessModulesEx",
    "ntdll.dll!NtCreateProcessEx",
    "ntdll.dll!LdrLoadDll", 
    "ntdll.dll!RtlAdjustPrivilege",
    "kernelbase.dll!VirtualFree",
    "kernelbase.dll!GetCalendarInfoEx",
    "ntdll.dll!RtlUserThreadStart",
    "kernel32.dll!BaseThreadInitThunk"
    ];

fn main() {
    unsafe
    {
        let k32 = dinvoke::get_module_base_address("kernel32.dll");

        loop {
            let mut rng = rand::thread_rng();
            // The number of functions and the functions themselves used to spoof the stack are generated randomly.
            // This allows to obtain a different thread stack each iteration. 
            let spoofing_count =  rng.gen_range(1..FUNCTIONS.len());
            let mut return_addr = return_address() as *mut isize;
            for _ in 0..spoofing_count
            {
                let index = rng.gen_range(0..FUNCTIONS.len());
                let function: Vec<&str> = FUNCTIONS[index].split("!").collect();
                let spoofing_data = get_stack_size(function[0], function[1]);

                if spoofing_data.0 != -1
                {
                    *return_addr = spoofing_data.1;
                    return_addr = return_addr.add(spoofing_data.0 as usize + 1);
                    *return_addr = 0;
                }
                else 
                {
                    println!("[x] Function not found: {}", function[1]);
                }
            }
            
            println!("[+] Thread stack spoofed!");
            let f:data::Sleep;
            let _r: Option<()>;
            println!("[ZzZ] Sleeping... Check the stack!");
            dinvoke::dynamic_invoke!(k32,"Sleep",f,_r,15000);
            println!("--------------------------");

        }
    }
}

/// This is the function where the main logic is implemented.
/// get_stack_size() is in charge of parsing the unwind information of the
/// selected spoofing function, allowing the tool to dynamically obtain the stack offset 
/// where the return address is expected.
/// 
/// The unwind info is not always parsed from the beginning of the struct since in order to add an extra
/// layer of randomness to the spoofing process a random generated offset is added to the function's base address (this offset is always
/// within the range [function's base address, function's base address + prolog size].
///  
/// It returns the stack offset where the return address is expected and the memory address that will be set in that stack location (function base addres + offset).
/// 
fn get_stack_size(dll_name: &str, function_name: &str) -> (i32,isize)
{
    unsafe
    {
        let module = dinvoke::get_module_base_address(dll_name);
        if module == 0
        {
            return (-1,-1);
        }

        let func_base_addr = dinvoke::get_function_address(module, function_name);
        if func_base_addr == 0
        {
            return (-1,-1);
        }

        let module_metadata = get_pe_metadata(module as *const u8);
        if !module_metadata.is_ok()
        {
            return (-1,-1);
        }

        let metadata = module_metadata.unwrap();
        let mut runtime_table = get_runtime_table(&metadata, module as *mut c_void);
        
        // Iterate over the PE RUNTIME FUNCTION until we get the unwind information of the spoofing function. 
        while  (*runtime_table).begin_addr != 0 
        {
            if ((*runtime_table).begin_addr as isize + module ) == func_base_addr
            {
                break;
            }
            runtime_table = runtime_table.add(1);
        }

        // In case that a leaf function has been selected, it will not have unwind information.
        if (*runtime_table).begin_addr == 0
        {
            return (0,func_base_addr);
        }

        // Here we start the parsing of the UNWIND_INFO struct
        let unwind_info = (module + (*runtime_table).unwind_addr as isize) as *mut u8;
        let version_and_flags = (*unwind_info).to_le_bytes().clone();
        let mut reader = BitReader::new(&version_and_flags);

        // We don't care about the version, we just need the flags to check if there is an Unwind Chain.
        let flags = reader.read_u8(5).unwrap(); 
        
        let unwind_codes_count = *(unwind_info.add(2)); 
        let mut start = 0;
        if unwind_codes_count > 1
        {
            // In case that the function has more than one unwind code, 
            // we select a random offset from where we will start the parsing of the
            // Unwind codes array. 
            let mut rng = rand::thread_rng();
            start =  rng.gen_range(1..unwind_codes_count);
        }

        // We skip 4 bytes corresponding to Version + flags, Size of prolog, Count of unwind codes
        // and Frame Register + Frame Register offset.
        // This way we reach the Unwind codes array.
        let unwind_codes = (unwind_info.add(4)) as *mut u16;
        // We add the previously generated offset to start the array parsing from a random position within the fucntion's prolog. 
        let mut unwind_code = unwind_codes.add(start as usize) as *mut u8;
        // We fix any issue that may appear due to the fact that we are starting from a random and unknow
        // position inside the Unwind codes array.
        let check = check_unwind_node(unwind_code);
        unwind_code = check.0;
        start += check.1;
        // We get the Offset in prolog value contained in the first UNWIND_CODE struct that we parse.
        // This offset will be added to the function's memory base address. 
        let offset = *unwind_code; 

        // From this point, we parse the remaining items in the Unwind codes array, obtaining the stack
        // offset where we will have to insert our spoofed address.
        let result = iterate_unwind_array(module, unwind_code,unwind_codes_count,flags,start);
        
        (result, func_base_addr + offset as isize) 
    }

}

fn iterate_unwind_array(module: isize, mut unwind_code: *mut u8, unwind_codes_count: u8, flags:u8, start: u8) -> i32
{
    unsafe
    {
        let mut unwind_code_operation_code_info = unwind_code.add(1);
        // This counter stores the offset of the stack.
        let mut stack_count = 0;
        let mut index = start;
        while index < unwind_codes_count
        {
            let operation_code_and_info = (*unwind_code_operation_code_info).to_be_bytes().clone();
            let mut reader = BitReader::new(&operation_code_and_info);
    
            let operation_info = reader.read_u8(4).unwrap(); // operation info
            let operation_code = reader.read_u8(4).unwrap(); // operation code

            // Since this is a PoC, just some of the unwind codes (the most common of them) have been implemented.
            // If you try to use a function with an unwind code not contemplated below the spoof will 
            // likely fail.
            match operation_code
            {
                0 => 
                {
                    // println!("UWOP_PUSH_NONVOL");
                    stack_count += 1;
                },
                1 =>
                {
                    // println!("UWOP_ALLOC_LARGE");
                    if operation_info == 0
                    {
                        let size = *(unwind_code_operation_code_info.add(1) as *mut i16);
                        stack_count += size as i32;

                        unwind_code = unwind_code.add(2);
                        index += 1;

                    }
                    else if operation_code == 1
                    {
                        let size = *(unwind_code_operation_code_info.add(1) as *mut u16) as i32;
                        let size2 = (*(unwind_code_operation_code_info.add(3) as *mut u16) as i32)  << 16;
                        stack_count += (size + size2) / 8;

                        unwind_code = unwind_code.add(4);
                        index += 2;
                    }
                },
                2 =>
                {
                    // println!("UWOP_ALLOC_SMALL");
                    stack_count += ((operation_info * 8 + 8) / 8) as i32;
                },
                4 =>
                {
                    // println!("UWOP_SAVE_NONVOL ");
                    unwind_code = unwind_code.add(2);
                    index += 1;
                },
                5 =>
                {
                    // println!("UWOP_SAVE_NONVOL_FAR ");
                    unwind_code = unwind_code.add(4);
                    index += 2;
                },
                _=> println!("[x] Unknown unwind code: {}", operation_code),
            }

            unwind_code = unwind_code.add(2);
            unwind_code_operation_code_info = unwind_code.add(1);
            index += 1;
        }

        // In case that the flag UNW_FLAG_CHAININFO is set, we recursively call this function.
        if (flags & 0x4) != 0
        {
            if unwind_codes_count % 2 != 0
            {
                unwind_code = unwind_code.add(2);
            }

            let runtime_table: *mut RUNTIME_FUNCTION = transmute(unwind_code);
            let unwind_info = (module + (*runtime_table).unwind_addr as isize) as *mut u8;
            let version_and_flags = (*unwind_info).to_le_bytes().clone();
            let mut reader = BitReader::new(&version_and_flags);
            let flags = reader.read_u8(5).unwrap(); 

            let unwind_codes_count = *(unwind_info.add(2)); 
            let mut start = 0;
            if unwind_codes_count > 1
            {
                let mut rng = rand::thread_rng();
                start =  rng.gen_range(1..unwind_codes_count);
            }
    
            let unwind_codes = (unwind_info.add(4)) as *mut u16;
            let unwind_code = unwind_codes.add(start as usize) as *mut u8;
            let result = iterate_unwind_array(module, unwind_code, unwind_codes_count, flags, 0);
            stack_count += result;
        }   

        // We just return the stack offset calculated in this function, which is the number of 
        // words that we should add to the stack in order to obtain the memory address where the
        // next return address will be expected.
        stack_count
    }
}

fn check_unwind_node(unwind_code: *mut u8) -> (*mut u8, u8)
{
    unsafe
    {
        let previous_code = unwind_code.sub(2);
        let unwind_code_operation_code_info = previous_code.add(1);
        let operation_code_and_info = (*unwind_code_operation_code_info).to_be_bytes().clone();
        let mut reader = BitReader::new(&operation_code_and_info);

        let operation_info = reader.read_u8(4).unwrap(); // operation info
        let operation_code = reader.read_u8(4).unwrap(); // operation code
        if operation_code == 4 || (operation_code == 1 && operation_info == 0)
        {
            return (unwind_code.add(2),1);
        }

        if operation_code == 5 || (operation_code == 1 && operation_info == 1)
        {
            return (unwind_code.add(4),2);
        }

        let prev_prev_code = previous_code.sub(2);
        let unwind_code_operation_code_info = prev_prev_code.add(1);
        let operation_code_and_info = (*unwind_code_operation_code_info).to_be_bytes().clone();
        let mut reader = BitReader::new(&operation_code_and_info);

        let operation_info = reader.read_u8(4).unwrap(); // operation info
        let operation_code = reader.read_u8(4).unwrap(); // operation code
        if operation_code == 5 || (operation_code == 1 && operation_info == 1)
        {
            return (unwind_code.add(2),1);
        }


        (unwind_code,0)
    }
}
fn get_runtime_table(pe_info: &PeMetadata, image_ptr: *mut c_void) -> *mut data::RUNTIME_FUNCTION 
{
    unsafe 
    {
        let mut runtime: *mut data::RUNTIME_FUNCTION = ptr::null_mut();
        for section in &pe_info.sections
        {   
            let s = std::str::from_utf8(&section.Name).unwrap();
            if s.contains(".pdata")
            {
                let base = image_ptr as isize;
                runtime = std::mem::transmute(base + section.VirtualAddress as isize);
            }
        }

        return runtime;
    }

}

fn get_pe_metadata (module_ptr: *const u8) -> Result<PeMetadata,String>
{
    let mut pe_metadata= PeMetadata::default();

    unsafe {

        
        let e_lfanew = *((module_ptr as usize + 0x3C) as *const u32);
        pe_metadata.pe = *((module_ptr as usize + e_lfanew as usize) as *const u32);

        if pe_metadata.pe != 0x4550 
        {
            return Err("[x] Invalid PE signature.".to_string());
        }

        pe_metadata.image_file_header = *((module_ptr as usize + e_lfanew as usize + 0x4) as *mut IMAGE_FILE_HEADER);

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
            let opt_header_content: *const IMAGE_OPTIONAL_HEADER64 = std::mem::transmute(opt_header);
            pe_metadata.opt_header_64 = *opt_header_content;
        } 
        else 
        {
            return Err("[x] Invalid magic value.".to_string());
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
