/**
 * See helpers:
 * https://nullprogram.com/blog/2023/10/08/
 * https://github.com/x509cert/banned/blob/master/banned.h
 * https://github.com/sharkdp/dbg-macro
 */

#include <assert.h>

#define assert(c) while (!(c)) __builtin_unreachable()

void print_hex(const char *s)
{
    while(*s)
        say_warn("(%02x)", (unsigned int) *s++);
    say_warn("\n");
}

/*
 * Programming by Contract is a programming methodology
 * which binds the caller and the function called to a
 * contract. The contract is represented using Hoare Triple:
 *      {P} C {Q}
 * where {P} is the precondition before executing command C,
 * and {Q} is the postcondition.
 *
 * See also:
 * http://en.wikipedia.org/wiki/Design_by_contract
 * http://en.wikipedia.org/wiki/Hoare_logic
 * http://dlang.org/dbc.html
 *
 * This is an _extremely_ simple example:
 *
 * int divide (int n, int d)
 * {
 *     int ans;
 *
 *     REQUIRE(d != 0);
 *
 *     ans = n / d;
 *
 *     // As code is added to this function throughout its lifetime,
 *     // ENSURE will assert that data will be returned
 *     // according to the contract.  Again this is an
 *     // extremely simple example. :-D
 *     ENSURE( ans == (n / d) );
 *
 *     return ans;
 * }
 */

/*
 * Checks caller responsibility against contract
 */
#define REQUIRE(cond) assert(cond)

/*
 * Checks function reponsability against contract.
 */
#define ENSURE(cond) assert(cond)

/*
 * While REQUIRE and ENSURE apply to functions, INVARIANT
 * applies to classes/structs.  It ensures that intances
 * of the class/struct are consistent. In other words,
 * that the instance has not been corrupted.
 */
#define INVARIANT(invariant_fnc) do{ (invariant_fnc) } while (0);

#else
#define REQUIRE(cond) do { } while (0);
#define ENSURE(cond) do { } while (0);
#define INVARIANT(invariant_fnc) do{ } while (0);
