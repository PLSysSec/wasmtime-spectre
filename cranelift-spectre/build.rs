fn main() {
    cc::Build::new()
        .file("c_src/btb_flush.c")
        .compile("lucet_runtime_c_api_tests");
}
