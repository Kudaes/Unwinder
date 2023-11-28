fn main()
{
    // Use the `cc` crate to build a C file and statically link it.
    cc::Build::new()
        .file("src/gateway.asm")
        .compile("gateway");
}