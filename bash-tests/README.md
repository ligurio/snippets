### Simple Testing In Bash

Sometimes it is required to write a simple tests using Bash.
Bash contains a builtin function ```caller``` (from “man bash”):

```
caller [expr]
	  Returns the context of any active subroutine call (a shell
	  function or a script executed with the . or source builtins).
	  Without expr, caller displays the line number and source
	  filename of the current subroutine call. If a non-negative
	  integer is supplied as expr, caller displays the line number,
	  subroutine name, and source file corresponding to that position
	  in the current execution call stack. This extra information may
	  be used, for example, to print a stack trace. The current frame
	  is frame 0. The return value is 0 unless the shell is not
	  executing a subroutine call or expr does not correspond to a
	  valid position in the call stack.
```

This allows to you to get the call stack back out:

```
~$ ./example.sh
ok - test_func1 # A letter
ok - test_func2 # B letter
ok - test_func3 # C letter
~$
```

For more complicated tests I recommend to use a
[BATS](https://github.com/sstephenson/bats) (Bash Automated Testing System).
