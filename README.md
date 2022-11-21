# Description

This [Twitter thread](https://twitter.com/namazso/status/1442313752767045635?s=20&t=wxBHvf95-XtkPEevjcgbPg) inspired the creation of this tool. 

Unwinder is a PoC of how to parse PE's UNWIND_INFO structs in order to achieve "proper" thread stack spoofing from the point of view of the [x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170). 

For more detailed information about how thread stacks are walked in x64 check the official [x64 exception handling documentation](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170).

The spoofing process overview is as follows:
* We obtain the stack's memory address where the first return address is located. This return address is replaced by the memory address of a randomly selected Windows API function (let's call it FunctionA).
* We walk FunctionA's Unwind codes array in order to dynamically determine where the next return address is expected in the stack.
* The word contained in the stack address obtained in the previous step is replaced by the memory address of another randomly selected Windows API function.
* The steps 2 and 3 are repeated a random number of times, obtaining a different thread stack each iteration of the PoC. All of this thread stacks are correct from the point of view of the x64 unwinding process.
* Once the spoof is completed, the tool calls Sleeps to allow the inpection of the thread stack (I use Process Hacker for this step).

This process repeats indefinitely.

As it can be seen in the following images, we are able to spoof the thread stack in multiple ways. Since the number of spoofing functions and the funcions themselves are randomly selected from a pool of functions each iteration will create a different thread stack. 

![Thread stack spoofed.](/images/spoof1.png "Thread stack spoofed")
![Thread stack spoofed.](/images/spoof2.png "Thread stack spoofed")
![Thread stack spoofed.](/images/spoof3.png "Thread stack spoofed")

Additional spoofing functions can be added to the pool by enlarging the **FUNCTIONS** array located in **src::main.rs**.

# Disclaimer

From the previous images it can be concluded that this tool **is not trying to create logical stack calls** for multiple reasons. For example, some of the thread stacks shown before don't start with ntdll.dll!RtlUserThreadStart and I've never seen kernelbase!GetCalendarInfoEx calling kernelbase.dll!DsFreeNameResultW even thought this tools allows it. The main purpose of this tool is to show how unwind codes walking allows us to effectively and malleably spoof the thread stack.

To use this technique in real environments and tools, it is required to analyzed valid stack secuences in order to mimic real call stacks, but this is beyond this project goals.

On the other hand, im just spoofing a portion of the stack. If you want to fully spoof the stack a little bit of extra work have to be done, even thought it should be easy to implement. Also, im not trying to restore the original values of the stack after each iteration, which should be done if this technique is implemented in any tool.

Finally, not all the unwind codes have been implemented. Although I encourage anyone to add extra spoofing functions to the FUNCTIONS array, take into account that you may end up parsing unwind codes not covered by this tool, which may lead to errors in the spoofing process.

# Compilation 

We need [Rust Nightly](https://web.mit.edu/rust-lang_v1.25/arch/amd64_ubuntu1404/share/doc/rust/html/book/second-edition/ch01-03-how-rust-is-made-and-nightly-rust.html) to compile this project. Once it has been installed, simply compile the code and run the tool:

	C:\Users\User\Desktop\unwinder> cargo build
	C:\Users\User\Desktop\unwinder\target\debug> unwinder.exe

# Credits

* [@mariuszbit](https://twitter.com/mariuszbit) for his [ThreadStackSpoofer](https://github.com/mgeeky/ThreadStackSpoofer) project that inspired me to create this tool.
* [@namazso](https://twitter.com/namazso) for pointing me to the rigth direction.
