// clang -fsanitize=fuzzer libfuzzer-example.c -o libfuzzer-example
// ./libfuzzer-example

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 0 && data[0] == 'L')
        if (size > 1 && data[1] == 'U')
            if (size > 3 && data[2] == 'A')
            __builtin_trap();
    return 0;
}
