--[[

TAP13 - The Test Anything Protocol v13
Specification:
https://testanything.org/tap-version-13-specification.html

Requirements:

- rex-posix (https://rrthomas.github.io/lrexlib/)
$ apt install -y lua-rex-posix
$ luarocks --local install luaposix
$ luarocks --local install lrexlib-POSIX
]]

local rex = require('rex_posix')
local inspect = require('inspect')

local function trim(s)
   return (s:gsub('^%s*(.-)%s*$', '%1'))
end

local TEST_STATUS = {
    PASSED = 'PASSED',
    FAILED = 'FAILED',
    SKIPPED = 'SKIPPED',
}

local TAP_VERSION_PATTERN = '^\\s*TAP\\s+version\\s+([1-9][0-9]+)'
local PLAN_PATTERN = '^\\s*1\\.\\.([0-9]+)'
local TEST_PATTERN = '^\\s*(ok|not\\s+ok)\\s*([0-9]+)\\s*-?\\s*([ A-z0-9]+)()'
local DIAG_PATTERN = '^#(.+)'

--[[
RE_VERSION = '^\s*TAP version 13\s*$'
RE_PLAN = '^\s*(?P<start>\d+)\.\.(?P<end>\d+)\s*(#\s*(?P<explanation>.*))?\s*$'
RE_TEST_LINE = '^\s*(?P<result>(not\s+)?ok)\s*(?P<id>\d+)?\s*(?P<description>[^#]+)?' ..
        '\s*(#\s*(?P<directive>TODO|SKIP)?\s*(?P<comment>.+)?)?\s*$'
RE_DIAGNOSTIC = '^\s*#\s*(?P<diagnostic>.+)?\s*$'
RE_YAMLISH_START = '^\s*---.*$'
RE_YAMLISH_END = '^\s*\.\.\.\s*$'
]]

--[[
Разбирает строку отчета в формате TestAnythingOutput v.13.
Возвращает таблицу с названием теста, статусом и временем выполнения.
Статусы могут иметь значения из таблицы TEST_STATUS.
]]
local function parse_tap13_line(buffer)
    if buffer == nil then
        return {}
    end

    local test = {
        name = nil,
        status = nil,
        number = 0,
        debug = nil,
    }
    local _, comment
    test.status, test.number, test.name, comment = rex.match(buffer, TEST_PATTERN)
    test.name = trim(test.name)
    if type(comment) == 'string' then
        comment = trim(comment)
        if comment == 'SKIP' then
            test.status = TEST_STATUS.SKIPPED
        end
    end

    if test.status == 'ok' then
        test.status = TEST_STATUS.PASSED
    else
        test.status = TEST_STATUS.FAILED
    end

    return test
end

--[[--
Разбирает результат теста в формате TestAnythingOutput v.13 в многострочном
буфере. Возвращает таблицу с тестами, каждый из которых содержит ключи: name,
number, status (возможные значения в таблице TEST_STATUS).

@param output многострочный буфер
@usage
    local report = {}
    report = parse_tap13_buf(buffer)
    report["TestAsn1Decoder"].name
    report["TestAsn1Decoder"].status
    report["TestAsn1Decoder"].debug
]]
local function parse_tap13_buf(output)
    if output == nil then
        error('buffer is empty')
    end

    local tests = {}
    local planned_tests = 0
    local run_tests = 0
    local test_in_progress = ''
    local is_tap13 = false

    for line in rex.split(output, '\n') do
        if rex.match(line, TAP_VERSION_PATTERN) then
            local version = rex.match(line, TAP_VERSION_PATTERN)
            if tonumber(version) ~= 13 then
                print(string.format('Unsupported version of TAP format - %d', version))
                return {}
            else
                is_tap13 = true
            end
        end
        if rex.match(line, PLAN_PATTERN) then
            planned_tests = tonumber(rex.match(line, PLAN_PATTERN))
            is_tap13 = true
        end
        if rex.match(line, TEST_PATTERN) and is_tap13 == true then
            local test = parse_tap13_line(line)
            test_in_progress = test.name
            table.insert(tests, test)
            -- tests[test.name] = test
            if (tonumber(test.number) == run_tests) then
                print(string.format('WARNING: Wrong test case number %d, should be %d', test.number, run_tests))
            end
            run_tests = run_tests + 1
        end
        if rex.match(line, DIAG_PATTERN) and is_tap13 == true then
            tests[test_in_progress].debug = tests[test_in_progress].debug .. line
        end
    end
    if (run_tests ~= planned_tests) then
        print(string.format('WARNING: Run %d tests, when planned %d tests.', run_tests, planned_tests))
    end

    if run_tests ~= 0 then
        return tests
    else
        return nil
    end
end

local buffer = [[
1..4
ok 1 - Input file opened
not ok 2 - First line of the input valid
ok 3 - Read the rest of the file
not ok 4 - Summarized correctly # TODO Not written yet
]]

local res = parse_tap13_buf(buffer)
print(inspect(res))

return {
    parse_tap13_buf = parse_tap13_buf,
    parse_tap13_line = parse_tap13_line,
}