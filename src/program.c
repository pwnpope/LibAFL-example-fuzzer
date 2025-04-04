#include <stdio.h>
#include <stdbool.h>
#include <string.h>


bool vuln_func(char *magic, char *payload, unsigned int payload_len) {
	char buf[0x4] = {0};
	memcpy(buf , magic, sizeof(buf));

	if (buf[0] == 'T' && buf[1] == 'S' && buf[2] == 'T') { 
		char cool_buffer[0x500] = {0};
		memcpy(cool_buffer, payload, payload_len);
		return true;
	}
	return false;
}

extern void fuzzer_main();

int main() {
	fuzzer_main();
}
