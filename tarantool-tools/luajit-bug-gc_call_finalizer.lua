-- https://github.com/dcurrie/lunit/blob/master/lua/lunit.lua

-- $ luarocks install --local lunitx 0.8-1
-- $ luarocks install --local lua-cjson 2.1.0.6-1
-- $ LUA_PATH=$(luarocks path --lr-path) LUA_CPATH=$(luarocks path --lr-cpath) luajit mini.lua
--
-- LUA_PATH="?/init.lua;./?.lua;/home/sergeyb/.luarocks/share/lua/5.1/?.lua;/home/sergeyb/.luarocks/share/lua/5.1/?/init.lua;/usr/local/share/lua/5.1/?.lua;/usr/local/share/lua/5.1/?/init.lua" LUA_CPATH="/home/sergeyb/.luarocks/lib/lua/5.1/?.so;/usr/local/lib/lua/5.1/?.so" /usr/bin/luajit mini.lua

local lunit = require('lunitx')
local json = require('cjson')

local history_suite = lunit.module('history', 'seeall')
function history_suite.test_to_json()
    local a = json.encode({})
end
