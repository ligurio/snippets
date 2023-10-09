/**
 * https://nullprogram.com/blog/2023/10/08/
 * https://github.com/x509cert/banned/blob/master/banned.h
 * https://github.com/sharkdp/dbg-macro
 */

#define assert(c)  while (!(c)) __builtin_unreachable()

void print_hex(const char *s)
{
    while(*s)
        say_warn("(%02x)", (unsigned int) *s++);
    say_warn("\n");
}
