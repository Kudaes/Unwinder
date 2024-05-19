# Content

- [SilentMoonWalk](#SilentMoonWalk)
  - [Description](#Description)
  - [Credits](#Credits)
  - [Usage](#usage)
      - [call_function!() macro](#call_function-macro)
      - [indirect_syscall!() macro](#indirect_syscall-macro)
      - [Parameter passing](#Parameter-passing)
  - [Examples](#examples)
      - [Calling kernel32.dll!Sleep()](#Calling-Sleep)
      - [Calling kernel32.dll!OpenProcess()](#Calling-Openprocess)
      - [Calling NtDelayExecution() as indirect syscall](#Calling-NtDelayExecution-as-indirect-syscall)
      - [Concatenate macro calls](#Concatenate-macro-calls)
  - [Considerations](#Considerations)
      - [Initial frame](#Initial-frame)
      - [PoC](#PoC)
- [Stack replacement](#Stack-replacement)
  - [Description](#Technique-description)
  - [Usage](#How-to-use-it)
  - [Practical example](#Example)
  - [Remarks](#Remarks)

# SilentMoonWalk
## Description

Unwinder provides a full weaponization of [SilentMoonWalk](https://github.com/klezVirus/SilentMoonwalk) technique, allowing to obtain complete and stable call stack spoofing in Rust.

This technique comes with the following characteristics:
* Support to run any arbitrary function with up to 11 parameters.
* Support to run indirect syscalls (no additional heap allocations) with up to 11 parameters.
* The crate allows to retrieve the value returned by the functions called through it.
* The spoofing process can be concatenated any number of times without increasing the call stack size.
* TLS is used to increase efficiency during the spoofing process.
* [dinvoke_rs](https://crates.io/crates/dinvoke_rs) is used to make any Windows API call required by the crate.

## Credits
kudos to the creators of the SilentMoonWalk technique:

* [KlezVirus](https://twitter.com/KlezVirus)
* [Waldo-IRC](https://twitter.com/waldoirc)
* [Trickster0](https://twitter.com/trickster012)

And of course a huge shoutout to [namazso](https://twitter.com/namazso) for the [Twitter thread](https://twitter.com/namazso/status/1442313752767045635?s=20&t=wxBHvf95-XtkPEevjcgbPg) that inspired this whole project.

## Usage

Import this crate into your project by adding the following line to your `cargo.toml` and compile on `release` mode:

```rust
[dependencies]
unwinder = "0.1.2"
```

The main functionality of this crate has been wrapped in two macros:
* The `call_function!()` macro allows to run any arbitrary function with a clean call stack.
* The `indirect_syscall!()` macro executes the specified (indirect) syscall with a clean call stack.

To use any of these macros it is required to import `std::ffi::c_void` data type.

Both macros return a `*mut c_void` that can be used to retrieve the value returned by the function executed. More detailed information in the examples section.

### call_function macro

This macro is used to call any desired function with a clean call stack.
The macro expects the following parameters:
* The first parameter is the memory address to call after spoofing the call stack. This parameter should be passed as a `usize`, `isize` or a pointer.
* The second parameter is a bool indicating whether or not keep the start function frame. If you are not sure about this, set it to false which always guarantees a good call stack.
* The following parameters are those arguments to send to the function once the call stack has been spoofed.

### indirect_syscall macro

This macro is used to perform any desired indirect syscall with a clean call stack.
The macro expects the following parameters:
* The first parameter is a string that contains the name of the NT function whose syscall you want to execute.
* The second parameter is a bool indicating whether or not keep the start function frame. If you are not sure about this, set it to false which always guarantees a good call stack.
* The following parameters are those arguments to send to the NT function.

### Parameter passing

In order to pass arguments of different types to these two macros, the following considerations must be taken into account:
* Any basic data type that can be converted to `usize` (u8-u64, i8-i64, bool, etc.) can be passed directly to the macros.
* Structs and unions of size 8, 16, 32, or 64 bits are passed as if they were integers of the same size.
* Structures and unions with a size larger than 64 bits must be passed as a pointer.
* Strings (`&str` and `String`) must be passed as a pointer.
* Null pointers (`ptr::null()`, `ptr::null_mut()`, etc. ) are passed as a 0 (no matter if it is `u8`, `u16`, `i32` or any other).
* Floating-point and double-precision parameters are not currently supported. 
* Any other data type must be passed as a pointer.

## Examples
### Calling Sleep

```rust
let k32 = dinvoke_rs::dinvoke::get_module_base_address("kernel32.dll");
let sleep = dinvoke_rs::dinvoke::get_function_address(k32, "Sleep"); // Memory address of kernel32.dll!Sleep() 
let miliseconds = 1000i32;
unwinder::call_function!(sleep, false, miliseconds);
```
### Calling OpenProcess

```rust
let k32 = dinvoke_rs::dinvoke::get_module_base_address("kernel32.dll"); 
let open_process: isize = dinvoke_rs::dinvoke::get_function_address(k32, "Openprocess");
let desired_access: u32 = 0x1000;
let inherit = 0i32;
let pid = 20628i32;
let handle: *mut c_void = unwinder::call_function!(open_process, false, desired_access, inherit, pid);
let handle: HANDLE = std::mem::transmute(handle);
println!("Handle id: {:x}", handle.0);
```

Notice that the macro returns a `*mut c_void` that can be directly converted to a `HANDLE` since both data types has the same size. This allows to access to the value returned by `OpenProcess`, which is the new handle to the target process.

### Calling NtDelayExecution as indirect syscall

```rust
let large = 0x8000000000000000 as u64; // Sleep indefinitely
let large: *mut i64 = std::mem::transmute(&large);
let alertable = false;
let ntstatus: *mut c_void = unwinder::indirect_syscall!("NtDelayExecution", false, alertable, large);
println!("ntstatus: {:x}", ntstatus as usize);
```
Notice that the macro returns a `*mut c_void` that can be used to retrieve the `NTSTATUS` returned by `NtDelayExecution`.

### Concatenate macro calls

The spoofing process can be concatenated any number of times without an abnormal call stack size increment. The execution flow will be preserved as well. The following code is an example of this:
```rust
fn main()
{
	function_a();
}

fn function_a()
{
	unsafe
	{
		let func_b = function_b as usize;
		call_function!(func_b, false);
		println!("function_a done.");
	}
}

fn function_b()
{
	unsafe
	{
		let func_c = function_c as usize;
		call_function!(func_c, false);
		println!("function_b done.")
	}
}

fn function_c()
{
	unsafe
	{
		let large = 0x0000000000000000 as u64; // Don't sleep so we return to function_b, allowing to check the execution flow preservation.
		let large: *mut i64 = std::mem::transmute(&large);
		let alertable = false;
		let ntstatus = unwinder::indirect_syscall!("NtDelayExecution", false, alertable, large);
		println!("ntstatus: {:x}", (ntstatus as usize) as i32); //NTSTATUS is a i32, although that second casting is not really required in this case.
	}
}
```

## Considerations
### Initial frame

If you set the second parameter to true (both macros), the spoofing process will try to keep the thread start address' frame in the call stack to increase legitimacy.

![Call stack spoofed keeping the main module.](/images/main_kept.jpg "Call stack spoofed keeping the main module")


Sometimes, the thread's start function does not perform a `call` to a subsequent function (e.g. a `jmp` instruction is executed instead), meaning there is not return address pushed to the stack. In that scenario (and also if you set that second parameter to false), the spoofed call stack will start at BaseThreadInitThunk's frame.

![Call stack spoofed without main module.](/images/no_main.png "Call stack spoofed without main module")


### PoC

In order to test the implementation of the technique, [PE-sieve](https://github.com/hasherezade/pe-sieve) has been used with the flag [`/threads`](https://github.com/hasherezade/pe-sieve/wiki/4.9.-Scan-threads-callstack-(threads)). The results of the test shows how the inpection of the call stack does not reveal the pressence of the payload when this crate's functionalities are used. As it can be seen in the second image, the payload is detected when unwinder is not used.

![PE-sieve results when unwinder is used.](/images/spoofed.png "PE-sieve results when unwinder is used")
![PE-sieve results when unwinder is not used.](/images/not_spoofed.png "PE-sieve results when unwinder is used")

# Stack replacement
## Technique description

This is a call stack spoofing alternative to SilentMoonWalk that allows to keep a clean call stack during the execution of your program. The main idea behind this technique is that each called function inside your module takes care of the previously pushed return address, finding at runtime a legitimate function with the same frame size as that of the return address to be spoofed. Once a legitime function with the same frame size has been located, an offset within is is calculated and the final address is used to **replace** the last return address, hiding any anomalous entry in the call stack and keeping it unwindable. The original return address is stored by `unwinder` and it is moved back to the right position in the stack before a return instruction is executed, allowing to continue the normal flow of the program.

<p align="center">
<img src="/images/stack_replacement.png" alt="Stack replacement" width="700" >
</p>

This is an experimental feature that despite being fully functional it is still under development and research, so make sure to test your code if you decide to integrate this technique on it. 

## How to use it

To use the stack replacement functionality you should add the following line to your `cargo.toml` and compile on `release` mode:

```rust
[dependencies]
unwinder = {version = "0.1.2", features = ["Experimental"]}
```

The main functionality of this feature has been wrapped in the following macros:
* The `start_stack_replacement!()`/`end_replacement!()` pair of macros indicates `unwinder` to start/end the stack replacement process. These two macros must be called in your code's entry point (e.g. in your dll's exported functions).
* The `replace_and_continue!()`/`restore!()` pair of macros performs the replacement/restoration of the last return address.
* Finally, the `replace_and_call!()`/`replace_and_syscall!()` pair of macros are used to perform stack replacement when we want to call functions outside of the current module (e.g. when using Windows API or calling any other dll's code). Both of these macros will return a *mut c_void containing the value returned by the function called this way (i.e. they operate the same way as described for the macros `call_function` and `indirect_syscall` used to execute SilentMoonWalk).

To use these macros it is required to import `std::ffi::c_void` data type.
All the functions using any of these macros should be labeled with the `#[no_mangle]` or `#[inline(never)]` attributes to prevent the rust compiler from inlining them during the optimization process.

Before diving into a practical example showing how to use all of this stuff, just a quick inspection of the `replace_and_call`/`replace_and_syscall` pair of macros and how to pass them the expected arguments.

## replace_and_call

This macro is used to call any desired function outside of the current module with a clean call stack while using stack replacement.
The macro expects the following parameters:
* The first parameter is the memory address of the function to call. This parameter should be passed as a `usize`, `isize` or a pointer.
* The following parameters are those arguments to send to the specified function. They follow the same rules specified in the [Parameter passing](#Parameter-passing) section.

## replace_and_syscall

This macro is used to perform any desired indirect syscall with a clean call stack while using stack replacement.
The macro expects the following parameters:
* The first parameter is a string that contains the name of the NT function whose syscall you want to execute.
* The following parameters are those arguments to send to the NT function. They follow the same rules specified in the [Parameter passing](#Parameter-passing) section.


## Example

I think the best way to show how these macros are used is through a practical example. Let's suppose we are creating a dll that will be **reflectively injected** to memory. This dll will export two functions `ExportA` and `ExportB`, so we will consider these two functions as the module's entry points. Both of them must call `start_stack_replacement` macro right at the beginning and also they must call the reverse `end_replacement` macro before returning. The `start_stack_replacement` macro **expects as argument the module's base address**, or you can pass 0 if you dont know that address at runtime, the macro will try to figure it out by itself.

```rust
#[no_mangle]
fn ExportedA(base_address: usize) -> bool
{
    unwinder::start_replacement!(base_address);
    ...
    unwinder::end_replacement!();

    true
}

#[no_mangle]
fn ExportedB() -> bool
{
    unwinder::start_replacement!(0);
    ...
    unwinder::end_replacement!();

    true
}
```
Starting the stack replacement process involves the manual crafting of a new stack that will be used until the `end_replacement` macro is called. The following picture illustrates what is going on under the hood:

<p align="center">
<img src="/images/start_stack_replacement.png" alt="Stack replacement" width="700" >
</p>

Although theoretically it would not be necessary to start a new stack from scratch, I've decided to implement the process this way to ensure stability and to prevent anything from breaking. 

Now, let's assume that our `ExportedA` function makes several calls to another two internal functions. These two internal functions are responsible for replacing/restoring the original return address that will point to some place within `ExportedA`, breaking the call stack unless we take care of it. This replacement process involves wrapping our internal function's code between the `replace_and_continue` and `restore` macros:

```rust
#[no_mangle]
fn ExportedA(base_address: usize) -> bool
{
    unwinder::start_replacement!(base_address);
    let ret_a = internal_a();
    let ret_b = internal_b(ret_a);
    unwinder::end_replacement!();

    ret_b
}

#[inline(never)] // This attribute is mandatory
fn internal_a() -> bool
{
    unwinder::replace_and_continue();
    ...
    unwinder::restore();
    
    some_value
} 

#[inline(never)] // This attribute is mandatory
fn internal_b(value: bool) -> bool
{
    unwinder::replace_and_continue();
    ...
    unwinder::restore();
    
    some_value
} 
```

Finally, both `internal_a` and `internal_b` functions make use of some Windows API functionality. To keep the unwindable call stack, these calls should be performed through the `replace_and_call` (normal call) or `replace_and_syscall` (indirect syscall) macros.

```rust
#[no_mangle] // This attribute is mandatory
fn ExportedA(base_address: usize) -> bool
{
    unwinder::start_replacement!(base_address);
    let ret_a = internal_a();
    let ret_b = internal_b(ret_a);
    unwinder::end_replacement!();

    ret_b
}

#[inline(never)] // This attribute is mandatory
fn internal_a() -> bool
{
    unwinder::replace_and_continue();
    ...
    let module_name = "advapi32.dll";
    let module_name = CString::new(module_name.to_string()).expect("");
    let module_name_ptr: *mut u8 = std::mem::transmute(module_name.as_ptr());
    let k32 = dinvoke::get_module_base_address("kernel32.dll");
    let load_library = dinvoke::get_function_address(k32, "LoadLibraryA");
    let ret = unwinder::replace_and_call!(load_library, module_name_ptr); // Load a dll with an unwindable call stack
    println!("advapi.dll base address: 0x{:x}", ret as usize);
    ...
    unwinder::restore();
    
    some_value
} 

#[inline(never)] // This attribute is mandatory
fn internal_b(value: bool) -> bool
{
    unwinder::replace_and_continue();
    ...
    let large = 0xFFFFFFFFFF676980 as u64; // Sleep one second
    let large: *mut i64 = std::mem::transmute(&large);
    let alertable = false;
    let ntstatus = unwinder::replace_and_syscall!("NtDelayExecution", alertable, large);
    println!("ntstatus: {:x}", ntstatus as usize);
    ...
    unwinder::restore();
    
    some_value
} 
```

## Remarks

Since this is an under development feature, some stuff must be taken into account:
* If you are removing your PE's headers during the loading process, you must pass to the `start_stack_replace` macro the module's base address. Right now, it won't be able to find it by itself (to be solved in the next update).
* In case you are wondering, stack replacement uses the same combination of `jmp rbx` + concealment frame as the SilentMoonWalk technique. This happens only when using `replace_and_call` and `replace_and_syscall` macros and it is planned to be changed in the next update.
* Both `replace_and_call` and `replace_and_syscall` macros return a `*mut c_void` that can be used to retrieve the value returned by the function executed through them. This is the same behaviour as the one described for the `call_function` and `indirect_syscall` macros.
* `replace_and_call` and `replace_and_syscall` macros allow up to 11 arguments.

Please report me any bug that may arise when using this feature.