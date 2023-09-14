package = "libssh2"
version = "scm-1"
source = {
    url = "git+https://github.com/ligurio/lua-libssh2",
    branch = "master",
}
description = {
    summary = "libssh2 FFI bindings",
    homepage = "https://github.com/ligurio/lua-libssh2",
    license = "MIT/X11"
}
dependencies = {
    -- None.
}
build = {
    type = "builtin",
    modules = {
        ["libssh2.libssh2"] = "libssh2/libssh2.lua",
    },
}
