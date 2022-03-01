void print_hex(const char *s)
{
    while(*s)
        say_warn("(%02x)", (unsigned int) *s++);
    say_warn("\n");
}
