all:
	clang -o program.o -fsanitize-coverage=trace-pc-guard -c program.c -g
	clang -o fuzzer program.o ../target/debug/libexample_fuzzer_one.a -g
