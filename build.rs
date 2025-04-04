fn main() {
    cc::Build::new()
        .file("/home/pope/dev/fuzzers/fuzzer_example_one/src/program.c")
        .warnings(false)
        .flag("-Wno-stringop-overflow")
        .compile("libvuln_func.a");
}
