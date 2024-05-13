# Content

- [Description](#Decription)
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

# Description

Unwinder is a full weaponization of [SilentMoonWalk](https://github.com/klezVirus/SilentMoonwalk) technique, allowing to obtain complete and stable call stack spoofing in Rust.

This crate comes with the following characteristics:
* Support to run any arbitrary function with up to 11 parameters.
* Support to run indirect syscalls (no additional heap allocations) with up to 11 parameters.
* The crate allows to retrieve the value returned by the functions called through it.
* The spoofing process can be concatenated any number of times without increasing the call stack size.
* TLS is used to increase efficiency during the spoofing process.
* [dinvoke_rs](https://crates.io/crates/dinvoke_rs) is used to make any Windows API call required by the crate.

# Credits
kudos to the creators of the SilentMoonWalk technique:

* [KlezVirus](https://twitter.com/KlezVirus)
* [Waldo-IRC](https://twitter.com/waldoirc)
* [Trickster0](https://twitter.com/trickster012)

And of course a huge shoutout to [namazso](https://twitter.com/namazso) for the [Twitter thread](https://twitter.com/namazso/status/1442313752767045635?s=20&t=wxBHvf95-XtkPEevjcgbPg) that inspired this whole project.

# Usage

Import this crate into your project by adding the following line to your `cargo.toml`:

```rust
[dependencies]
unwinder = "0.1.1"
```

The main functionality of this crate has been wrapped in two macros:
* The `call_function!()` macro allows to run any arbitrary function with a clean call stack.
* The `indirect_syscall!()` macro executes the specified (indirect) syscall with a clean call stack.

To use any of these macros it is required to import `std::ffi::c_void` data type.

Both macros return a `PVOID` that can be used to retrieve the value returned by the function executed. More detailed information in the examples section.

## call_function macro

This macro is used to call any desired function with a clean call stack.
The macro expects the following parameters:
* The first parameter is the memory address to call after spoofing the call stack. This parameter should be passed as a `usize`, `isize` or a pointer.
* The second parameter is a bool indicating whether or not keep the start function frame. If you are not sure about this, set it to false which always guarantees a good call stack.
* The following parameters are those arguments to send to the function once the call stack has been spoofed.

## indirect_syscall macro

This macro is used to perform any desired indirect syscall with a clean call stack.
The macro expects the following parameters:
* The first parameter is a string that contains the name of the NT function whose syscall you want to execute.
* The second parameter is a bool indicating whether or not keep the start function frame. If you are not sure about this, set it to false which always guarantees a good call stack.
* The following parameters are those arguments to send to the NT function.

## Parameter passing

In order to pass arguments of different types to these two macros, the following considerations must be taken into account:
* Any basic data type that can be converted to `usize` (u8-u64, i8-i64, bool, etc.) can be passed directly to the macros.
* Structs and unions of size 8, 16, 32, or 64 bits are passed as if they were integers of the same size.
* Structures and unions with a size larger than 64 bits must be passed as a pointer.
* Strings (`&str` and `String`) must be passed as a pointer.
* Null pointers (`ptr::null()`, `ptr::null_mut()`, etc. ) are passed as a 0 (no matter if it is `u8`, `u16`, `i32` or any other).
* Floating-point and double-precision parameters are not currently supported. 
* Any other data type must be passed as a pointer.

# Examples
## Calling Sleep

```rust
let k32 = dinvoke_rs::dinvoke::get_module_base_address("kernel32.dll");
let sleep = dinvoke_rs::dinvoke::get_function_address(k32, "Sleep"); // Memory address of kernel32.dll!Sleep() 
let miliseconds = 1000i32;
unwinder::call_function!(sleep, false, miliseconds);
```
## Calling OpenProcess

```rust
let k32 = dinvoke_rs::dinvoke::get_module_base_address("kernel32.dll"); 
let open_process: isize = dinvoke_rs::dinvoke::get_function_address(k32, "Openprocess");
let desired_access: u32 = 0x1000;
let inherit = 0i32;
let pid = 20628i32;
let handle: *mut c_void = unwinder::call_function!(open_process, desired_access, inherit, pid);
let handle: HANDLE = std::mem::transmute(handle);
println!("Handle id: {:x}", handle.0);
```

Notice that the macro returns a `*mut c_void` that can be directly converted to a `HANDLE` since both data types has the same size. This allows to access to the value returned by `OpenProcess`, which is the new handle to the target process.

## Calling NtDelayExecution as indirect syscall

```rust
let large = 0x8000000000000000 as u64; // Sleep indefinitely
let large: *mut i64 = std::mem::transmute(&large);
let alertable = false;
let ntstatus: *mut c_void = unwinder::indirect_syscall!("NtDelayExecution", false, alertable, large);
println!("ntstatus: {:x}", ntstatus as usize);
```
Notice that the macro returns a `*mut c_void` that can be used to retrieve the `NTSTATUS` returned by `NtDelayExecution`.

## Concatenate macro calls

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
		let ntstatus = indirect_syscall!("NtDelayExecution", false, alertable, large);
		println!("ntstatus: {:x}", (ntstatus as usize) as i32); //NTSTATUS is a i32, although that second casting is not really required in this case.
	}
}
```

# Considerations
## Initial frame

If you set the second parameter to true (both macros), the spoofing process will try to keep the thread start address' frame in the call stack to increase legitimacy.

![Call stack spoofed keeping the main module.](/images/main_kept.jpg "Call stack spoofed keeping the main module")


Sometimes, the thread's start function does not perform a `call` to a subsequent function (e.g. a `jmp` instruction is executed instead), meaning there is not return address pushed to the stack. In that scenario (and also if you set that second parameter to false), the spoofed call stack will start at BaseThreadInitThunk's frame.

![Call stack spoofed without main module.](/images/no_main.png "Call stack spoofed without main module")


## PoC

In order to test the implementation of the technique, [PE-sieve](https://github.com/hasherezade/pe-sieve) has been used with the flag [`/threads`](https://github.com/hasherezade/pe-sieve/wiki/4.9.-Scan-threads-callstack-(threads)). The results of the test shows how the inpection of the call stack does not reveal the pressence of the payload when this crate's functionalities are used. As it can be seen in the second image, the payload is detected when unwinder is not used.

![PE-sieve results when unwinder is used.](/images/spoofed.png "PE-sieve results when unwinder is used")
![PE-sieve results when unwinder is not used.](/images/not_spoofed.png "PE-sieve results when unwinder is used")
