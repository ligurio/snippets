#!/bin/sh

# https://chromium.googlesource.com/chromium/src/+/HEAD/docs/writing_clang_plugins.md
# https://clang.llvm.org/docs/ClangPlugins.html

$ clang++ -v -std=c++11 PrintFunctionNames.cpp  $(llvm-config --cxxflags --ldflags) -o plugin.so -shared -Wl,-undefined,dynamic_lookup
$ apt install -y clang-7.0-examples
$ find . -name "*.cc" | while read f; do echo $f; clang++ -Xclang -load -Xclang ../PrintFunctionNames/plugin.so -Xclang -plugin -Xclang print-fns -c $f; done 2>&1 | tee > functions
$ cat chromium-h-functions | grep top-level-decl | sed -e 's/top-level-decl: "\(.*\)"/\1/'
$
$ egrep -R "\s+$f\s+\(" * 
