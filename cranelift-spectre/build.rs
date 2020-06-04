fn main() {
    cc::Build::new()
        .file("c_src/btb_flush.c")
        .file("c_src/invoke_lfence.S")
        .compile("lucet_runtime_c_api_tests");
}
