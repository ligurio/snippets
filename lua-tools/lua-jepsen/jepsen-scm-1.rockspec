package = 'lua-jepsen'
version = 'scm-1'
source = {
    url    = 'git://github.com/ligurio/lua-jepsen',
    branch = 'master',
}
description = {
    summary    = 'A framework for distributed systems verification, with fault injection',
    homepage   = 'https://github.com/ligurio/lua-jepsen',
    maintainer = 'Sergey Bronnikov <sergeyb@tarantool.org>',
    license    = 'BSD2',
}
dependencies = {
    'tarantool >= 1.10',
    'checks',
    'errors',
    'luafun',
}

build = {
    type = 'make',
    -- Nothing to build.
    build_pass = false,
    variables = {
        -- https://github.com/tarantool/modulekit/issues/2
        TARANTOOL_INSTALL_LUADIR='$(LUADIR)',
    },
    -- Don't copy doc/ folder.
    copy_directories = {},
}
