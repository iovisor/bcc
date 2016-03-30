--[[
        luaunit.lua

Description: A unit testing framework
Homepage: https://github.com/bluebird75/luaunit
Development by Philippe Fremy <phil@freehackers.org>
Based on initial work of Ryu, Gwang (http://www.gpgstudy.com/gpgiki/LuaUnit)
License: BSD License, see LICENSE.txt
Version: 3.2
]]--

require("math")
local M={}

-- private exported functions (for testing)
M.private = {}

M.VERSION='3.2'

--[[ Some people like assertEquals( actual, expected ) and some people prefer
assertEquals( expected, actual ).
]]--
M.ORDER_ACTUAL_EXPECTED = true
M.PRINT_TABLE_REF_IN_ERROR_MSG = false
M.TABLE_EQUALS_KEYBYCONTENT = true
M.LINE_LENGTH=80

-- set this to false to debug luaunit
local STRIP_LUAUNIT_FROM_STACKTRACE=true

M.VERBOSITY_DEFAULT = 10
M.VERBOSITY_LOW     = 1
M.VERBOSITY_QUIET   = 0
M.VERBOSITY_VERBOSE = 20

-- set EXPORT_ASSERT_TO_GLOBALS to have all asserts visible as global values
-- EXPORT_ASSERT_TO_GLOBALS = true

-- we need to keep a copy of the script args before it is overriden
local cmdline_argv = rawget(_G, "arg")

M.FAILURE_PREFIX = 'LuaUnit test FAILURE: ' -- prefix string for failed tests

M.USAGE=[[Usage: lua <your_test_suite.lua> [options] [testname1 [testname2] ... ]
Options:
  -h, --help:             Print this help
  --version:              Print version information
  -v, --verbose:          Increase verbosity
  -q, --quiet:            Set verbosity to minimum
  -e, --error:            Stop on first error
  -f, --failure:          Stop on first failure or error
  -o, --output OUTPUT:    Set output type to OUTPUT
                          Possible values: text, tap, junit, nil
  -n, --name NAME:        For junit only, mandatory name of xml file
  -p, --pattern PATTERN:  Execute all test names matching the Lua PATTERN
                          May be repeated to include severals patterns
                          Make sure you escape magic chars like +? with %
  testname1, testname2, ... : tests to run in the form of testFunction,
                              TestClass or TestClass.testMethod
]]

----------------------------------------------------------------
--
--                 general utility functions
--
----------------------------------------------------------------

local crossTypeOrdering = {
    number = 1,
    boolean = 2,
    string = 3,
    table = 4,
    other = 5
}
local crossTypeComparison = {
    number = function(a, b) return a < b end,
    string = function(a, b) return a < b end,
    other = function(a, b) return tostring(a) < tostring(b) end,
}

local function crossTypeSort(a, b)
    local type_a, type_b = type(a), type(b)
    if type_a == type_b then
        local func = crossTypeComparison[type_a] or crossTypeComparison.other
        return func(a, b)
    end
    type_a = crossTypeOrdering[type_a] or crossTypeOrdering.other
    type_b = crossTypeOrdering[type_b] or crossTypeOrdering.other
    return type_a < type_b
end

local function __genSortedIndex( t )
    -- Returns a sequence consisting of t's keys, sorted.
    local sortedIndex = {}

    for key,_ in pairs(t) do
        table.insert(sortedIndex, key)
    end

    table.sort(sortedIndex, crossTypeSort)
    return sortedIndex
end
M.private.__genSortedIndex = __genSortedIndex

local function sortedNext(state, control)
    -- Equivalent of the next() function of table iteration, but returns the
    -- keys in sorted order (see __genSortedIndex and crossTypeSort).
    -- The state is a temporary variable during iteration and contains the
    -- sorted key table (state.sortedIdx). It also stores the last index (into
    -- the keys) used by the iteration, to find the next one quickly.
    local key

    --print("sortedNext: control = "..tostring(control) )
    if control == nil then
        -- start of iteration
        state.lastIdx = 1
        key = state.sortedIdx[1]
        return key, state.t[key]
    end

    -- normally, we expect the control variable to match the last key used
    if control ~= state.sortedIdx[state.lastIdx] then
        -- strange, we have to find the next value by ourselves
        -- the key table is sorted in crossTypeSort() order! -> use bisection
        local count = #state.sortedIdx
        local lower, upper = 1, count
        repeat
            state.lastIdx = math.modf((lower + upper) / 2)
            key = state.sortedIdx[state.lastIdx]
            if key == control then break; end -- key found (and thus prev index)
            if crossTypeSort(key, control) then
                -- key < control, continue search "right" (towards upper bound)
                lower = state.lastIdx + 1
            else
                -- key > control, continue search "left" (towards lower bound)
                upper = state.lastIdx - 1
            end
        until lower > upper
        if lower > upper then -- only true if the key wasn't found, ...
            state.lastIdx = count -- ... so ensure no match for the code below
        end
    end

    -- proceed by retrieving the next value (or nil) from the sorted keys
    state.lastIdx = state.lastIdx + 1
    key = state.sortedIdx[state.lastIdx]
    if key then
        return key, state.t[key]
    end

    -- getting here means returning `nil`, which will end the iteration
end

local function sortedPairs(tbl)
    -- Equivalent of the pairs() function on tables. Allows to iterate in
    -- sorted order. As required by "generic for" loops, this will return the
    -- iterator (function), an "invariant state", and the initial control value.
    -- (see http://www.lua.org/pil/7.2.html)
    return sortedNext, {t = tbl, sortedIdx = __genSortedIndex(tbl)}, nil
end
M.private.sortedPairs = sortedPairs

local function strsplit(delimiter, text)
-- Split text into a list consisting of the strings in text,
-- separated by strings matching delimiter (which may be a pattern).
-- example: strsplit(",%s*", "Anna, Bob, Charlie,Dolores")
    if string.find("", delimiter, 1, true) then -- this would result in endless loops
        error("delimiter matches empty string!")
    end
    local list, pos, first, last = {}, 1
    while true do
        first, last = text:find(delimiter, pos, true)
        if first then -- found?
            table.insert(list, text:sub(pos, first - 1))
            pos = last + 1
        else
            table.insert(list, text:sub(pos))
            break
        end
    end
    return list
end
M.private.strsplit = strsplit

local function hasNewLine( s )
    -- return true if s has a newline
    return (string.find(s, '\n', 1, true) ~= nil)
end
M.private.hasNewLine = hasNewLine

local function prefixString( prefix, s )
    -- Prefix all the lines of s with prefix
    return prefix .. table.concat(strsplit('\n', s), '\n' .. prefix)
end
M.private.prefixString = prefixString

local function strMatch(s, pattern, start, final )
    -- return true if s matches completely the pattern from index start to index end
    -- return false in every other cases
    -- if start is nil, matches from the beginning of the string
    -- if final is nil, matches to the end of the string
    start = start or 1
    final = final or string.len(s)

    local foundStart, foundEnd = string.find(s, pattern, start, false)
    return foundStart == start and foundEnd == final
end
M.private.strMatch = strMatch

local function xmlEscape( s )
    -- Return s escaped for XML attributes
    -- escapes table:
    -- "   &quot;
    -- '   &apos;
    -- <   &lt;
    -- >   &gt;
    -- &   &amp;

    return string.gsub( s, '.', {
        ['&'] = "&amp;",
        ['"'] = "&quot;",
        ["'"] = "&apos;",
        ['<'] = "&lt;",
        ['>'] = "&gt;",
    } )
end
M.private.xmlEscape = xmlEscape

local function xmlCDataEscape( s )
    -- Return s escaped for CData section, escapes: "]]>"
    return string.gsub( s, ']]>', ']]&gt;' )
end
M.private.xmlCDataEscape = xmlCDataEscape

local function stripLuaunitTrace( stackTrace )
    --[[
    -- Example of  a traceback:
    <<stack traceback:
        example_with_luaunit.lua:130: in function 'test2_withFailure'
        ./luaunit.lua:1449: in function <./luaunit.lua:1449>
        [C]: in function 'xpcall'
        ./luaunit.lua:1449: in function 'protectedCall'
        ./luaunit.lua:1508: in function 'execOneFunction'
        ./luaunit.lua:1596: in function 'runSuiteByInstances'
        ./luaunit.lua:1660: in function 'runSuiteByNames'
        ./luaunit.lua:1736: in function 'runSuite'
        example_with_luaunit.lua:140: in main chunk
        [C]: in ?>>

        Other example:
    <<stack traceback:
        ./luaunit.lua:545: in function 'assertEquals'
        example_with_luaunit.lua:58: in function 'TestToto.test7'
        ./luaunit.lua:1517: in function <./luaunit.lua:1517>
        [C]: in function 'xpcall'
        ./luaunit.lua:1517: in function 'protectedCall'
        ./luaunit.lua:1578: in function 'execOneFunction'
        ./luaunit.lua:1677: in function 'runSuiteByInstances'
        ./luaunit.lua:1730: in function 'runSuiteByNames'
        ./luaunit.lua:1806: in function 'runSuite'
        example_with_luaunit.lua:140: in main chunk
        [C]: in ?>>

    <<stack traceback:
        luaunit2/example_with_luaunit.lua:124: in function 'test1_withFailure'
        luaunit2/luaunit.lua:1532: in function <luaunit2/luaunit.lua:1532>
        [C]: in function 'xpcall'
        luaunit2/luaunit.lua:1532: in function 'protectedCall'
        luaunit2/luaunit.lua:1591: in function 'execOneFunction'
        luaunit2/luaunit.lua:1679: in function 'runSuiteByInstances'
        luaunit2/luaunit.lua:1743: in function 'runSuiteByNames'
        luaunit2/luaunit.lua:1819: in function 'runSuite'
        luaunit2/example_with_luaunit.lua:140: in main chunk
        [C]: in ?>>


    -- first line is "stack traceback": KEEP
    -- next line may be luaunit line: REMOVE
    -- next lines are call in the program under testOk: REMOVE
    -- next lines are calls from luaunit to call the program under test: KEEP

    -- Strategy:
    -- keep first line
    -- remove lines that are part of luaunit
    -- kepp lines until we hit a luaunit line
    ]]

    local function isLuaunitInternalLine( s )
        -- return true if line of stack trace comes from inside luaunit
        return s:find('[/\\]luaunit%.lua:%d+: ') ~= nil
    end

    -- print( '<<'..stackTrace..'>>' )

    local t = strsplit( '\n', stackTrace )
    -- print( prettystr(t) )

    local idx = 2

    -- remove lines that are still part of luaunit
    while t[idx] and isLuaunitInternalLine( t[idx] ) do
        -- print('Removing : '..t[idx] )
        table.remove(t, idx)
    end

    -- keep lines until we hit luaunit again
    while t[idx] and (not isLuaunitInternalLine(t[idx])) do
        -- print('Keeping : '..t[idx] )
        idx = idx + 1
    end

    -- remove remaining luaunit lines
    while t[idx] do
        -- print('Removing : '..t[idx] )
        table.remove(t, idx)
    end

    -- print( prettystr(t) )
    return table.concat( t, '\n')

end
M.private.stripLuaunitTrace = stripLuaunitTrace


local function prettystr_sub(v, indentLevel, keeponeline, printTableRefs, recursionTable )
    local type_v = type(v)
    if "string" == type_v  then
        if keeponeline then v = v:gsub("\n", "\\n") end

        -- use clever delimiters according to content:
        -- enclose with single quotes if string contains ", but no '
        if v:find('"', 1, true) and not v:find("'", 1, true) then
            return "'" .. v .. "'"
        end
        -- use double quotes otherwise, escape embedded "
        return '"' .. v:gsub('"', '\\"') .. '"'

    elseif "table" == type_v then
        --if v.__class__ then
        --    return string.gsub( tostring(v), 'table', v.__class__ )
        --end
        return M.private._table_tostring(v, indentLevel, printTableRefs, recursionTable)
    end

    return tostring(v)
end

local function prettystr( v, keeponeline )
    --[[ Better string conversion, to display nice variable content:
    For strings, if keeponeline is set to true, string is displayed on one line, with visible \n
    * string are enclosed with " by default, or with ' if string contains a "
    * if table is a class, display class name
    * tables are expanded
    ]]--
    local recursionTable = {}
    local s = prettystr_sub(v, 1, keeponeline, M.PRINT_TABLE_REF_IN_ERROR_MSG, recursionTable)
    if recursionTable.recursionDetected and not M.PRINT_TABLE_REF_IN_ERROR_MSG then
        -- some table contain recursive references,
        -- so we must recompute the value by including all table references
        -- else the result looks like crap
        recursionTable = {}
        s = prettystr_sub(v, 1, keeponeline, true, recursionTable)
    end
    return s
end
M.prettystr = prettystr

local function prettystrPadded(value1, value2, suffix_a, suffix_b)
    --[[
    This function helps with the recurring task of constructing the "expected
    vs. actual" error messages. It takes two arbitrary values and formats
    corresponding strings with prettystr().

    To keep the (possibly complex) output more readable in case the resulting
    strings contain line breaks, they get automatically prefixed with additional
    newlines. Both suffixes are optional (default to empty strings), and get
    appended to the "value1" string. "suffix_a" is used if line breaks were
    encountered, "suffix_b" otherwise.

    Returns the two formatted strings (including padding/newlines).
    ]]
    local str1, str2 = prettystr(value1), prettystr(value2)
    if hasNewLine(str1) or hasNewLine(str2) then
        -- line break(s) detected, add padding
        return "\n" .. str1 .. (suffix_a or ""), "\n" .. str2
    end
    return str1 .. (suffix_b or ""), str2
end
M.private.prettystrPadded = prettystrPadded

local function _table_keytostring(k)
    -- like prettystr but do not enclose with "" if the string is just alphanumerical
    -- this is better for displaying table keys who are often simple strings
    if "string" == type(k) and k:match("^[_%a][_%w]*$") then
        return k
    end
    return prettystr(k)
end
M.private._table_keytostring = _table_keytostring

local TABLE_TOSTRING_SEP = ", "
local TABLE_TOSTRING_SEP_LEN = string.len(TABLE_TOSTRING_SEP)

local function _table_tostring( tbl, indentLevel, printTableRefs, recursionTable )
    printTableRefs = printTableRefs or M.PRINT_TABLE_REF_IN_ERROR_MSG
    recursionTable = recursionTable or {}
    recursionTable[tbl] = true

    local result, dispOnMultLines = {}, false

    local entry, count, seq_index = nil, 0, 1
    for k, v in sortedPairs( tbl ) do
        if k == seq_index then
            -- for the sequential part of tables, we'll skip the "<key>=" output
            entry = ''
            seq_index = seq_index + 1
        else
            entry = _table_keytostring( k ) .. "="
        end
        if recursionTable[v] then -- recursion detected!
            recursionTable.recursionDetected = true
            entry = entry .. "<"..tostring(v)..">"
        else
            entry = entry ..
                prettystr_sub( v, indentLevel+1, true, printTableRefs, recursionTable )
        end
        count = count + 1
        result[count] = entry
    end

    -- set dispOnMultLines if the maximum LINE_LENGTH would be exceeded
    local totalLength = 0
    for k, v in ipairs( result ) do
        totalLength = totalLength + string.len( v )
        if totalLength >= M.LINE_LENGTH then
            dispOnMultLines = true
            break
        end
    end

    if not dispOnMultLines then
        -- adjust with length of separator(s):
        -- two items need 1 sep, three items two seps, ... plus len of '{}'
        if count > 0 then
            totalLength = totalLength + TABLE_TOSTRING_SEP_LEN * (count - 1)
        end
        dispOnMultLines = totalLength + 2 >= M.LINE_LENGTH
    end

    -- now reformat the result table (currently holding element strings)
    if dispOnMultLines then
        local indentString = string.rep("    ", indentLevel - 1)
        result = {"{\n    ", indentString,
                  table.concat(result, ",\n    " .. indentString), "\n",
                  indentString, "}"}
    else
        result = {"{", table.concat(result, TABLE_TOSTRING_SEP), "}"}
    end
    if printTableRefs then
        table.insert(result, 1, "<"..tostring(tbl).."> ") -- prepend table ref
    end
    return table.concat(result)
end
M.private._table_tostring = _table_tostring -- prettystr_sub() needs it

local function _table_contains(t, element)
    if t then
        for _, value in pairs(t) do
            if type(value) == type(element) then
                if type(element) == 'table' then
                    -- if we wanted recursive items content comparison, we could use
                    -- _is_table_items_equals(v, expected) but one level of just comparing
                    -- items is sufficient
                    if M.private._is_table_equals( value, element ) then
                        return true
                    end
                else
                    if value == element then
                        return true
                    end
                end
            end
        end
    end
    return false
end

local function _is_table_items_equals(actual, expected )
    if (type(actual) == 'table') and (type(expected) == 'table') then
        for k,v in pairs(actual) do
            if not _table_contains(expected, v) then
                return false
            end
        end
        for k,v in pairs(expected) do
            if not _table_contains(actual, v) then
                return false
            end
        end
        return true
    elseif type(actual) ~= type(expected) then
        return false
    elseif actual == expected then
        return true
    end
    return false
end

local function _is_table_equals(actual, expected)
    if (type(actual) == 'table') and (type(expected) == 'table') then
        if (#actual ~= #expected) then
            return false
        end

        local actualTableKeys = {}
        for k,v in pairs(actual) do
            if M.TABLE_EQUALS_KEYBYCONTENT and type(k) == "table" then
                -- If the keys are tables, things get a bit tricky here as we
                -- can have _is_table_equals(k1, k2) and t[k1] ~= t[k2]. So we
                -- collect actual's table keys, group them by length for
                -- performance, and then for each table key in expected we look
                -- it up in actualTableKeys.
                if not actualTableKeys[#k] then actualTableKeys[#k] = {} end
                table.insert(actualTableKeys[#k], k)
            else
                if not _is_table_equals(v, expected[k]) then
                    return false
                end
            end
        end

        for k,v in pairs(expected) do
            if M.TABLE_EQUALS_KEYBYCONTENT and type(k) == "table" then
                local candidates = actualTableKeys[#k]
                if not candidates then return false end
                local found
                for i, candidate in pairs(candidates) do
                    if _is_table_equals(candidate, k) then
                        found = candidate
                        -- Remove the candidate we matched against from the list
                        -- of candidates, so each key in actual can only match
                        -- one key in expected.
                        candidates[i] = nil
                        break
                    end
                end
                if not(found and _is_table_equals(actual[found], v)) then return false end
            else
                if not _is_table_equals(v, actual[k]) then
                    return false
                end
            end
        end

        if M.TABLE_EQUALS_KEYBYCONTENT then
            for _, keys in pairs(actualTableKeys) do
                -- if there are any keys left in any actualTableKeys[i] then
                -- that is a key in actual with no matching key in expected,
                -- and so the tables aren't equal.
                if next(keys) then return false end
            end
        end

        return true
    elseif type(actual) ~= type(expected) then
        return false
    elseif actual == expected then
        return true
    end
    return false
end
M.private._is_table_equals = _is_table_equals

local function failure(msg, level)
    -- raise an error indicating a test failure
    -- for error() compatibility we adjust "level" here (by +1), to report the
    -- calling context
    error(M.FAILURE_PREFIX .. msg, (level or 1) + 1)
end

local function fail_fmt(level, ...)
     -- failure with printf-style formatted message and given error level
    failure(string.format(...), (level or 1) + 1)
end
M.private.fail_fmt = fail_fmt

local function error_fmt(level, ...)
     -- printf-style error()
    error(string.format(...), (level or 1) + 1)
end

----------------------------------------------------------------
--
--                     assertions
--
----------------------------------------------------------------

local function errorMsgEquality(actual, expected)
    if not M.ORDER_ACTUAL_EXPECTED then
        expected, actual = actual, expected
    end
    if type(expected) == 'string' or type(expected) == 'table' then
        expected, actual = prettystrPadded(expected, actual)
        return string.format("expected: %s\nactual: %s", expected, actual)
    end
    return string.format("expected: %s, actual: %s",
                         prettystr(expected), prettystr(actual))
end

function M.assertError(f, ...)
    -- assert that calling f with the arguments will raise an error
    -- example: assertError( f, 1, 2 ) => f(1,2) should generate an error
    if pcall( f, ... ) then
        failure( "Expected an error when calling function but no error generated", 2 )
    end
end

function M.assertTrue(value)
    if not value then
        failure("expected: true, actual: " ..prettystr(value), 2)
    end
end

function M.assertFalse(value)
    if value then
        failure("expected: false, actual: " ..prettystr(value), 2)
    end
end

function M.assertIsNil(value)
    if value ~= nil then
        failure("expected: nil, actual: " ..prettystr(value), 2)
    end
end

function M.assertNotIsNil(value)
    if value == nil then
        failure("expected non nil value, received nil", 2)
    end
end

function M.assertEquals(actual, expected)
    if type(actual) == 'table' and type(expected) == 'table' then
        if not _is_table_equals(actual, expected) then
            failure( errorMsgEquality(actual, expected), 2 )
        end
    elseif type(actual) ~= type(expected) then
        failure( errorMsgEquality(actual, expected), 2 )
    elseif actual ~= expected then
        failure( errorMsgEquality(actual, expected), 2 )
    end
end

-- Help Lua in corner cases like almostEquals(1.1, 1.0, 0.1), which by default
-- may not work. We need to give margin a small boost; EPSILON defines the
-- default value to use for this:
local EPSILON = 0.00000000001
function M.almostEquals( actual, expected, margin, margin_boost )
    if type(actual) ~= 'number' or type(expected) ~= 'number' or type(margin) ~= 'number' then
        error_fmt(3, 'almostEquals: must supply only number arguments.\nArguments supplied: %s, %s, %s',
            prettystr(actual), prettystr(expected), prettystr(margin))
    end
    if margin <= 0 then
        error('almostEquals: margin must be positive, current value is ' .. margin, 3)
    end
    local realmargin = margin + (margin_boost or EPSILON)
    return math.abs(expected - actual) <= realmargin
end

function M.assertAlmostEquals( actual, expected, margin )
    -- check that two floats are close by margin
    if not M.almostEquals(actual, expected, margin) then
        if not M.ORDER_ACTUAL_EXPECTED then
            expected, actual = actual, expected
        end
        fail_fmt(2, 'Values are not almost equal\nExpected: %s with margin of %s, received: %s',
                 expected, margin, actual)
    end
end

function M.assertNotEquals(actual, expected)
    if type(actual) ~= type(expected) then
        return
    end

    if type(actual) == 'table' and type(expected) == 'table' then
        if not _is_table_equals(actual, expected) then
            return
        end
    elseif actual ~= expected then
        return
    end
    fail_fmt(2, 'Received the not expected value: %s', prettystr(actual))
end

function M.assertNotAlmostEquals( actual, expected, margin )
    -- check that two floats are not close by margin
    if M.almostEquals(actual, expected, margin) then
        if not M.ORDER_ACTUAL_EXPECTED then
            expected, actual = actual, expected
        end
        fail_fmt(2, 'Values are almost equal\nExpected: %s with a difference above margin of %s, received: %s',
                 expected, margin, actual)
    end
end

function M.assertStrContains( str, sub, useRe )
    -- this relies on lua string.find function
    -- a string always contains the empty string
    if not string.find(str, sub, 1, not useRe) then
        sub, str = prettystrPadded(sub, str, '\n')
        fail_fmt(2, 'Error, %s %s was not found in string %s',
                 useRe and 'regexp' or 'substring', sub, str)
    end
end

function M.assertStrIContains( str, sub )
    -- this relies on lua string.find function
    -- a string always contains the empty string
    if not string.find(str:lower(), sub:lower(), 1, true) then
        sub, str = prettystrPadded(sub, str, '\n')
        fail_fmt(2, 'Error, substring %s was not found (case insensitively) in string %s',
                 sub, str)
    end
end

function M.assertNotStrContains( str, sub, useRe )
    -- this relies on lua string.find function
    -- a string always contains the empty string
    if string.find(str, sub, 1, not useRe) then
        sub, str = prettystrPadded(sub, str, '\n')
        fail_fmt(2, 'Error, %s %s was found in string %s',
                 useRe and 'regexp' or 'substring', sub, str)
    end
end

function M.assertNotStrIContains( str, sub )
    -- this relies on lua string.find function
    -- a string always contains the empty string
    if string.find(str:lower(), sub:lower(), 1, true) then
        sub, str = prettystrPadded(sub, str, '\n')
        fail_fmt(2, 'Error, substring %s was found (case insensitively) in string %s',
                 sub, str)
    end
end

function M.assertStrMatches( str, pattern, start, final )
    -- Verify a full match for the string
    -- for a partial match, simply use assertStrContains with useRe set to true
    if not strMatch( str, pattern, start, final ) then
        pattern, str = prettystrPadded(pattern, str, '\n')
        fail_fmt(2, 'Error, pattern %s was not matched by string %s',
                 pattern, str)
    end
end

function M.assertErrorMsgEquals( expectedMsg, func, ... )
    -- assert that calling f with the arguments will raise an error
    -- example: assertError( f, 1, 2 ) => f(1,2) should generate an error
    local no_error, error_msg = pcall( func, ... )
    if no_error then
        failure( 'No error generated when calling function but expected error: "'..expectedMsg..'"', 2 )
    end
    if error_msg ~= expectedMsg then
        error_msg, expectedMsg = prettystrPadded(error_msg, expectedMsg)
        fail_fmt(2, 'Exact error message expected: %s\nError message received: %s\n',
                 expectedMsg, error_msg)
    end
end

function M.assertErrorMsgContains( partialMsg, func, ... )
    -- assert that calling f with the arguments will raise an error
    -- example: assertError( f, 1, 2 ) => f(1,2) should generate an error
    local no_error, error_msg = pcall( func, ... )
    if no_error then
        failure( 'No error generated when calling function but expected error containing: '..prettystr(partialMsg), 2 )
    end
    if not string.find( error_msg, partialMsg, nil, true ) then
        error_msg, partialMsg = prettystrPadded(error_msg, partialMsg)
        fail_fmt(2, 'Error message does not contain: %s\nError message received: %s\n',
                 partialMsg, error_msg)
    end
end

function M.assertErrorMsgMatches( expectedMsg, func, ... )
    -- assert that calling f with the arguments will raise an error
    -- example: assertError( f, 1, 2 ) => f(1,2) should generate an error
    local no_error, error_msg = pcall( func, ... )
    if no_error then
        failure( 'No error generated when calling function but expected error matching: "'..expectedMsg..'"', 2 )
    end
    if not strMatch( error_msg, expectedMsg ) then
        expectedMsg, error_msg = prettystrPadded(expectedMsg, error_msg)
        fail_fmt(2, 'Error message does not match: %s\nError message received: %s\n',
                 expectedMsg, error_msg)
    end
end

--[[
Add type assertion functions to the module table M. Each of these functions
takes a single parameter "value", and checks that its Lua type matches the
expected string (derived from the function name):

M.assertIsXxx(value) -> ensure that type(value) conforms to "xxx"
]]
for _, funcName in ipairs(
    {'assertIsNumber', 'assertIsString', 'assertIsTable', 'assertIsBoolean',
     'assertIsFunction', 'assertIsUserdata', 'assertIsThread'}
) do
    local typeExpected = funcName:match("^assertIs([A-Z]%a*)$")
    -- Lua type() always returns lowercase, also make sure the match() succeeded
    typeExpected = typeExpected and typeExpected:lower()
                   or error("bad function name '"..funcName.."' for type assertion")

    M[funcName] = function(value)
        if type(value) ~= typeExpected then
            fail_fmt(2, 'Expected: a %s value, actual: type %s, value %s',
                     typeExpected, type(value), prettystrPadded(value))
        end
    end
end

--[[
Add non-type assertion functions to the module table M. Each of these functions
takes a single parameter "value", and checks that its Lua type differs from the
expected string (derived from the function name):

M.assertNotIsXxx(value) -> ensure that type(value) is not "xxx"
]]
for _, funcName in ipairs(
    {'assertNotIsNumber', 'assertNotIsString', 'assertNotIsTable', 'assertNotIsBoolean',
     'assertNotIsFunction', 'assertNotIsUserdata', 'assertNotIsThread'}
) do
    local typeUnexpected = funcName:match("^assertNotIs([A-Z]%a*)$")
    -- Lua type() always returns lowercase, also make sure the match() succeeded
    typeUnexpected = typeUnexpected and typeUnexpected:lower()
                   or error("bad function name '"..funcName.."' for type assertion")

    M[funcName] = function(value)
        if type(value) == typeUnexpected then
            fail_fmt(2, 'Not expected: a %s type, actual: value %s',
                     typeUnexpected, prettystrPadded(value))
        end
    end
end

function M.assertIs(actual, expected)
    if actual ~= expected then
        if not M.ORDER_ACTUAL_EXPECTED then
            actual, expected = expected, actual
        end
        expected, actual = prettystrPadded(expected, actual, '\n', ', ')
        fail_fmt(2, 'Expected object and actual object are not the same\nExpected: %sactual: %s',
                 expected, actual)
    end
end

function M.assertNotIs(actual, expected)
    if actual == expected then
        if not M.ORDER_ACTUAL_EXPECTED then
            expected = actual
        end
        fail_fmt(2, 'Expected object and actual object are the same object: %s',
                 prettystrPadded(expected))
    end
end

function M.assertItemsEquals(actual, expected)
    -- checks that the items of table expected
    -- are contained in table actual. Warning, this function
    -- is at least O(n^2)
    if not _is_table_items_equals(actual, expected ) then
        expected, actual = prettystrPadded(expected, actual)
        fail_fmt(2, 'Contents of the tables are not identical:\nExpected: %s\nActual: %s',
                 expected, actual)
    end
end

----------------------------------------------------------------
--                     Compatibility layer
----------------------------------------------------------------

-- for compatibility with LuaUnit v2.x
function M.wrapFunctions(...)
    io.stderr:write( [[Use of WrapFunction() is no longer needed.
Just prefix your test function names with "test" or "Test" and they
will be picked up and run by LuaUnit.]] )
    -- In LuaUnit version <= 2.1 , this function was necessary to include
    -- a test function inside the global test suite. Nowadays, the functions
    -- are simply run directly as part of the test discovery process.
    -- so just do nothing !

    --[[
    local testClass, testFunction
    testClass = {}
    local function storeAsMethod(idx, testName)
        testFunction = _G[testName]
        testClass[testName] = testFunction
    end
    for i,v in ipairs({...}) do
        storeAsMethod( i, v )
    end

    return testClass
    ]]
end

local list_of_funcs = {
    -- { official function name , alias }

    -- general assertions
    { 'assertEquals'            , 'assert_equals' },
    { 'assertItemsEquals'       , 'assert_items_equals' },
    { 'assertNotEquals'         , 'assert_not_equals' },
    { 'assertAlmostEquals'      , 'assert_almost_equals' },
    { 'assertNotAlmostEquals'   , 'assert_not_almost_equals' },
    { 'assertTrue'              , 'assert_true' },
    { 'assertFalse'             , 'assert_false' },
    { 'assertStrContains'       , 'assert_str_contains' },
    { 'assertStrIContains'      , 'assert_str_icontains' },
    { 'assertNotStrContains'    , 'assert_not_str_contains' },
    { 'assertNotStrIContains'   , 'assert_not_str_icontains' },
    { 'assertStrMatches'        , 'assert_str_matches' },
    { 'assertError'             , 'assert_error' },
    { 'assertErrorMsgEquals'    , 'assert_error_msg_equals' },
    { 'assertErrorMsgContains'  , 'assert_error_msg_contains' },
    { 'assertErrorMsgMatches'   , 'assert_error_msg_matches' },
    { 'assertIs'                , 'assert_is' },
    { 'assertNotIs'             , 'assert_not_is' },
    { 'wrapFunctions'           , 'WrapFunctions' },
    { 'wrapFunctions'           , 'wrap_functions' },

    -- type assertions: assertIsXXX -> assert_is_xxx
    { 'assertIsNumber'          , 'assert_is_number' },
    { 'assertIsString'          , 'assert_is_string' },
    { 'assertIsTable'           , 'assert_is_table' },
    { 'assertIsBoolean'         , 'assert_is_boolean' },
    { 'assertIsNil'             , 'assert_is_nil' },
    { 'assertIsFunction'        , 'assert_is_function' },
    { 'assertIsThread'          , 'assert_is_thread' },
    { 'assertIsUserdata'        , 'assert_is_userdata' },

    -- type assertions: assertIsXXX -> assertXxx
    { 'assertIsNumber'          , 'assertNumber' },
    { 'assertIsString'          , 'assertString' },
    { 'assertIsTable'           , 'assertTable' },
    { 'assertIsBoolean'         , 'assertBoolean' },
    { 'assertIsNil'             , 'assertNil' },
    { 'assertIsFunction'        , 'assertFunction' },
    { 'assertIsThread'          , 'assertThread' },
    { 'assertIsUserdata'        , 'assertUserdata' },

    -- type assertions: assertIsXXX -> assert_xxx (luaunit v2 compat)
    { 'assertIsNumber'          , 'assert_number' },
    { 'assertIsString'          , 'assert_string' },
    { 'assertIsTable'           , 'assert_table' },
    { 'assertIsBoolean'         , 'assert_boolean' },
    { 'assertIsNil'             , 'assert_nil' },
    { 'assertIsFunction'        , 'assert_function' },
    { 'assertIsThread'          , 'assert_thread' },
    { 'assertIsUserdata'        , 'assert_userdata' },

    -- type assertions: assertNotIsXXX -> assert_not_is_xxx
    { 'assertNotIsNumber'       , 'assert_not_is_number' },
    { 'assertNotIsString'       , 'assert_not_is_string' },
    { 'assertNotIsTable'        , 'assert_not_is_table' },
    { 'assertNotIsBoolean'      , 'assert_not_is_boolean' },
    { 'assertNotIsNil'          , 'assert_not_is_nil' },
    { 'assertNotIsFunction'     , 'assert_not_is_function' },
    { 'assertNotIsThread'       , 'assert_not_is_thread' },
    { 'assertNotIsUserdata'     , 'assert_not_is_userdata' },

    -- type assertions: assertNotIsXXX -> assertNotXxx (luaunit v2 compat)
    { 'assertNotIsNumber'       , 'assertNotNumber' },
    { 'assertNotIsString'       , 'assertNotString' },
    { 'assertNotIsTable'        , 'assertNotTable' },
    { 'assertNotIsBoolean'      , 'assertNotBoolean' },
    { 'assertNotIsNil'          , 'assertNotNil' },
    { 'assertNotIsFunction'     , 'assertNotFunction' },
    { 'assertNotIsThread'       , 'assertNotThread' },
    { 'assertNotIsUserdata'     , 'assertNotUserdata' },

    -- type assertions: assertNotIsXXX -> assert_not_xxx
    { 'assertNotIsNumber'       , 'assert_not_number' },
    { 'assertNotIsString'       , 'assert_not_string' },
    { 'assertNotIsTable'        , 'assert_not_table' },
    { 'assertNotIsBoolean'      , 'assert_not_boolean' },
    { 'assertNotIsNil'          , 'assert_not_nil' },
    { 'assertNotIsFunction'     , 'assert_not_function' },
    { 'assertNotIsThread'       , 'assert_not_thread' },
    { 'assertNotIsUserdata'     , 'assert_not_userdata' },

    -- all assertions with Coroutine duplicate Thread assertions
    { 'assertIsThread'          , 'assertIsCoroutine' },
    { 'assertIsThread'          , 'assertCoroutine' },
    { 'assertIsThread'          , 'assert_is_coroutine' },
    { 'assertIsThread'          , 'assert_coroutine' },
    { 'assertNotIsThread'       , 'assertNotIsCoroutine' },
    { 'assertNotIsThread'       , 'assertNotCoroutine' },
    { 'assertNotIsThread'       , 'assert_not_is_coroutine' },
    { 'assertNotIsThread'       , 'assert_not_coroutine' },
}

-- Create all aliases in M
for _,v in ipairs( list_of_funcs ) do
    funcname, alias = v[1], v[2]
    M[alias] = M[funcname]

    if EXPORT_ASSERT_TO_GLOBALS then
        _G[funcname] = M[funcname]
        _G[alias] = M[funcname]
    end
end

----------------------------------------------------------------
--
--                     Outputters
--
----------------------------------------------------------------

----------------------------------------------------------------
--                     class TapOutput
----------------------------------------------------------------


local TapOutput = { __class__ = 'TapOutput' } -- class
local TapOutput_MT = { __index = TapOutput } -- metatable

    -- For a good reference for TAP format, check: http://testanything.org/tap-specification.html

    function TapOutput:new()
        return setmetatable( { verbosity = M.VERBOSITY_LOW }, TapOutput_MT)
    end
    function TapOutput:startSuite()
        print("1.."..self.result.testCount)
        print('# Started on '..self.result.startDate)
    end
    function TapOutput:startClass(className)
        if className ~= '[TestFunctions]' then
            print('# Starting class: '..className)
        end
    end
    function TapOutput:startTest(testName) end

    function TapOutput:addFailure( node )
        io.stdout:write("not ok ", self.result.currentTestNumber, "\t", node.testName, "\n")
        if self.verbosity > M.VERBOSITY_LOW then
           print( prefixString( '    ', node.msg ) )
        end
        if self.verbosity > M.VERBOSITY_DEFAULT then
           print( prefixString( '    ', node.stackTrace ) )
        end
    end
    TapOutput.addError = TapOutput.addFailure

    function TapOutput:endTest( node )
        if node:isPassed() then
            io.stdout:write("ok     ", self.result.currentTestNumber, "\t", node.testName, "\n")
        end
    end

    function TapOutput:endClass() end

    function TapOutput:endSuite()
        print( '# '..M.LuaUnit.statusLine( self.result ) )
        return self.result.notPassedCount
    end


-- class TapOutput end

----------------------------------------------------------------
--                     class JUnitOutput
----------------------------------------------------------------

-- See directory junitxml for more information about the junit format
local JUnitOutput = { __class__ = 'JUnitOutput' } -- class
local JUnitOutput_MT = { __index = JUnitOutput } -- metatable

    function JUnitOutput:new()
        return setmetatable(
            { testList = {}, verbosity = M.VERBOSITY_LOW }, JUnitOutput_MT)
    end
    function JUnitOutput:startSuite()

        -- open xml file early to deal with errors
        if self.fname == nil then
            error('With Junit, an output filename must be supplied with --name!')
        end
        if string.sub(self.fname,-4) ~= '.xml' then
            self.fname = self.fname..'.xml'
        end
        self.fd = io.open(self.fname, "w")
        if self.fd == nil then
            error("Could not open file for writing: "..self.fname)
        end

        print('# XML output to '..self.fname)
        print('# Started on '..self.result.startDate)
    end
    function JUnitOutput:startClass(className)
        if className ~= '[TestFunctions]' then
            print('# Starting class: '..className)
        end
    end
    function JUnitOutput:startTest(testName)
        print('# Starting test: '..testName)
    end

    function JUnitOutput:addFailure( node )
        print('# Failure: ' .. node.msg)
        -- print('# ' .. node.stackTrace)
    end

    function JUnitOutput:addError( node )
        print('# Error: ' .. node.msg)
        -- print('# ' .. node.stackTrace)
    end

    function JUnitOutput:endTest( node )
    end

    function JUnitOutput:endClass()
    end

    function JUnitOutput:endSuite()
        print( '# '..M.LuaUnit.statusLine(self.result))

        -- XML file writing
        self.fd:write('<?xml version="1.0" encoding="UTF-8" ?>\n')
        self.fd:write('<testsuites>\n')
        self.fd:write(string.format(
            '    <testsuite name="LuaUnit" id="00001" package="" hostname="localhost" tests="%d" timestamp="%s" time="%0.3f" errors="%d" failures="%d">\n',
            self.result.runCount, self.result.startIsodate, self.result.duration, self.result.errorCount, self.result.failureCount ))
        self.fd:write("        <properties>\n")
        self.fd:write(string.format('            <property name="Lua Version" value="%s"/>\n', _VERSION ) )
        self.fd:write(string.format('            <property name="LuaUnit Version" value="%s"/>\n', M.VERSION) )
        -- XXX please include system name and version if possible
        self.fd:write("        </properties>\n")

        for i,node in ipairs(self.result.tests) do
            self.fd:write(string.format('        <testcase classname="%s" name="%s" time="%0.3f">\n',
                node.className, node.testName, node.duration ) )
            if node:isNotPassed() then
                self.fd:write(node:statusXML())
            end
            self.fd:write('        </testcase>\n')
        end

        -- Next two lines are needed to validate junit ANT xsd, but really not useful in general:
        self.fd:write('    <system-out/>\n')
        self.fd:write('    <system-err/>\n')

        self.fd:write('    </testsuite>\n')
        self.fd:write('</testsuites>\n')
        self.fd:close()
        return self.result.notPassedCount
    end


-- class TapOutput end

----------------------------------------------------------------
--                     class TextOutput
----------------------------------------------------------------

--[[

-- Python Non verbose:

For each test: . or F or E

If some failed tests:
    ==============
    ERROR / FAILURE: TestName (testfile.testclass)
    ---------
    Stack trace


then --------------
then "Ran x tests in 0.000s"
then OK or FAILED (failures=1, error=1)

-- Python Verbose:
testname (filename.classname) ... ok
testname (filename.classname) ... FAIL
testname (filename.classname) ... ERROR

then --------------
then "Ran x tests in 0.000s"
then OK or FAILED (failures=1, error=1)

-- Ruby:
Started
 .
 Finished in 0.002695 seconds.

 1 tests, 2 assertions, 0 failures, 0 errors

-- Ruby:
>> ruby tc_simple_number2.rb
Loaded suite tc_simple_number2
Started
F..
Finished in 0.038617 seconds.

  1) Failure:
test_failure(TestSimpleNumber) [tc_simple_number2.rb:16]:
Adding doesn't work.
<3> expected but was
<4>.

3 tests, 4 assertions, 1 failures, 0 errors

-- Java Junit
.......F.
Time: 0,003
There was 1 failure:
1) testCapacity(junit.samples.VectorTest)junit.framework.AssertionFailedError
    at junit.samples.VectorTest.testCapacity(VectorTest.java:87)
    at sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
    at sun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)
    at sun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)

FAILURES!!!
Tests run: 8,  Failures: 1,  Errors: 0


-- Maven

# mvn test
-------------------------------------------------------
 T E S T S
-------------------------------------------------------
Running math.AdditionTest
Tests run: 2, Failures: 1, Errors: 0, Skipped: 0, Time elapsed:
0.03 sec <<< FAILURE!

Results :

Failed tests:
  testLireSymbole(math.AdditionTest)

Tests run: 2, Failures: 1, Errors: 0, Skipped: 0


-- LuaUnit
---- non verbose
* display . or F or E when running tests
---- verbose
* display test name + ok/fail
----
* blank line
* number) ERROR or FAILURE: TestName
   Stack trace
* blank line
* number) ERROR or FAILURE: TestName
   Stack trace

then --------------
then "Ran x tests in 0.000s (%d not selected, %d skipped)"
then OK or FAILED (failures=1, error=1)


]]

local TextOutput = { __class__ = 'TextOutput' } -- class
local TextOutput_MT = { __index = TextOutput } -- metatable

    function TextOutput:new()
        return setmetatable(
            { errorList = {}, verbosity = M.VERBOSITY_DEFAULT }, TextOutput_MT )
    end

    function TextOutput:startSuite()
        if self.verbosity > M.VERBOSITY_DEFAULT then
            print( 'Started on '.. self.result.startDate )
        end
    end

    function TextOutput:startClass(className)
        -- display nothing when starting a new class
    end

    function TextOutput:startTest(testName)
        if self.verbosity > M.VERBOSITY_DEFAULT then
            io.stdout:write( "    ", self.result.currentNode.testName, " ... " )
        end
    end

    function TextOutput:addFailure( node )
        -- nothing
    end

    function TextOutput:addError( node )
        -- nothing
    end

    function TextOutput:endTest( node )
        if node:isPassed() then
            if self.verbosity > M.VERBOSITY_DEFAULT then
                io.stdout:write("Ok\n")
            else
                io.stdout:write(".")
            end
        else
            if self.verbosity > M.VERBOSITY_DEFAULT then
                print( node.status )
                print( node.msg )
                --[[
                -- find out when to do this:
                if self.verbosity > M.VERBOSITY_DEFAULT then
                    print( node.stackTrace )
                end
                ]]
            else
                -- write only the first character of status
                io.stdout:write(string.sub(node.status, 1, 1))
            end
        end
    end

    function TextOutput:endClass()
        -- nothing
    end

    function TextOutput:displayOneFailedTest( index, failure )
        print(index..") "..failure.testName )
        print( failure.msg )
        print( failure.stackTrace )
        print()
    end

    function TextOutput:displayFailedTests()
        if self.result.notPassedCount == 0 then return end
        print("Failed tests:")
        print("-------------")
        for i,v in ipairs(self.result.notPassed) do
            self:displayOneFailedTest( i, v )
        end
    end

    function TextOutput:endSuite()
        if self.verbosity > M.VERBOSITY_DEFAULT then
            print("=========================================================")
        else
            print()
        end
        self:displayFailedTests()
        print( M.LuaUnit.statusLine( self.result ) )
        local ignoredString = ""
        if self.result.notPassedCount == 0 then
            print('OK')
        end
    end

-- class TextOutput end


----------------------------------------------------------------
--                     class NilOutput
----------------------------------------------------------------

local function nopCallable()
    --print(42)
    return nopCallable
end

local NilOutput = { __class__ = 'NilOuptut' } -- class
local NilOutput_MT = { __index = nopCallable } -- metatable

function NilOutput:new()
    return setmetatable( { __class__ = 'NilOutput' }, NilOutput_MT )
end

----------------------------------------------------------------
--
--                     class LuaUnit
--
----------------------------------------------------------------

M.LuaUnit = {
    outputType = TextOutput,
    verbosity = M.VERBOSITY_DEFAULT,
    __class__ = 'LuaUnit'
}
local LuaUnit_MT = { __index = M.LuaUnit }

if EXPORT_ASSERT_TO_GLOBALS then
    LuaUnit = M.LuaUnit
end

    function M.LuaUnit:new()
        return setmetatable( {}, LuaUnit_MT )
    end

    -----------------[[ Utility methods ]]---------------------

    function M.LuaUnit.asFunction(aObject)
        -- return "aObject" if it is a function, and nil otherwise
        if 'function' == type(aObject) then return aObject end
    end

    function M.LuaUnit.isClassMethod(aName)
        -- return true if aName contains a class + a method name in the form class:method
        return string.find(aName, '.', nil, true) ~= nil
    end

    function M.LuaUnit.splitClassMethod(someName)
        -- return a pair className, methodName for a name in the form class:method
        -- return nil if not a class + method name
        -- name is class + method
        local hasMethod, methodName, className
        hasMethod = string.find(someName, '.', nil, true )
        if not hasMethod then return nil end
        methodName = string.sub(someName, hasMethod+1)
        className = string.sub(someName,1,hasMethod-1)
        return className, methodName
    end

    function M.LuaUnit.isMethodTestName( s )
        -- return true is the name matches the name of a test method
        -- default rule is that is starts with 'Test' or with 'test'
        return string.sub(s, 1, 4):lower() == 'test'
    end

    function M.LuaUnit.isTestName( s )
        -- return true is the name matches the name of a test
        -- default rule is that is starts with 'Test' or with 'test'
        return string.sub(s, 1, 4):lower() == 'test'
    end

    function M.LuaUnit.collectTests()
        -- return a list of all test names in the global namespace
        -- that match LuaUnit.isTestName

        local testNames = {}
        for k, v in pairs(_G) do
            if M.LuaUnit.isTestName( k ) then
                table.insert( testNames , k )
            end
        end
        table.sort( testNames )
        return testNames
    end

    function M.LuaUnit.parseCmdLine( cmdLine )
        -- parse the command line
        -- Supported command line parameters:
        -- --verbose, -v: increase verbosity
        -- --quiet, -q: silence output
        -- --error, -e: treat errors as fatal (quit program)
        -- --output, -o, + name: select output type
        -- --pattern, -p, + pattern: run test matching pattern, may be repeated
        -- --name, -n, + fname: name of output file for junit, default to stdout
        -- [testnames, ...]: run selected test names
        --
        -- Returns a table with the following fields:
        -- verbosity: nil, M.VERBOSITY_DEFAULT, M.VERBOSITY_QUIET, M.VERBOSITY_VERBOSE
        -- output: nil, 'tap', 'junit', 'text', 'nil'
        -- testNames: nil or a list of test names to run
        -- pattern: nil or a list of patterns

        local result = {}
        local state = nil
        local SET_OUTPUT = 1
        local SET_PATTERN = 2
        local SET_FNAME = 3

        if cmdLine == nil then
            return result
        end

        local function parseOption( option )
            if option == '--help' or option == '-h' then
                result['help'] = true
                return
            elseif option == '--version' then
                result['version'] = true
                return
            elseif option == '--verbose' or option == '-v' then
                result['verbosity'] = M.VERBOSITY_VERBOSE
                return
            elseif option == '--quiet' or option == '-q' then
                result['verbosity'] = M.VERBOSITY_QUIET
                return
            elseif option == '--error' or option == '-e' then
                result['quitOnError'] = true
                return
            elseif option == '--failure' or option == '-f' then
                result['quitOnFailure'] = true
                return
            elseif option == '--output' or option == '-o' then
                state = SET_OUTPUT
                return state
            elseif option == '--name' or option == '-n' then
                state = SET_FNAME
                return state
            elseif option == '--pattern' or option == '-p' then
                state = SET_PATTERN
                return state
            end
            error('Unknown option: '..option,3)
        end

        local function setArg( cmdArg, state )
            if state == SET_OUTPUT then
                result['output'] = cmdArg
                return
            elseif state == SET_FNAME then
                result['fname'] = cmdArg
                return
            elseif state == SET_PATTERN then
                if result['pattern'] then
                    table.insert( result['pattern'], cmdArg )
                else
                    result['pattern'] = { cmdArg }
                end
                return
            end
            error('Unknown parse state: '.. state)
        end


        for i, cmdArg in ipairs(cmdLine) do
            if state ~= nil then
                setArg( cmdArg, state, result )
                state = nil
            else
                if cmdArg:sub(1,1) == '-' then
                    state = parseOption( cmdArg )
                else
                    if result['testNames'] then
                        table.insert( result['testNames'], cmdArg )
                    else
                        result['testNames'] = { cmdArg }
                    end
                end
            end
        end

        if result['help'] then
            M.LuaUnit.help()
        end

        if result['version'] then
            M.LuaUnit.version()
        end

        if state ~= nil then
            error('Missing argument after '..cmdLine[ #cmdLine ],2 )
        end

        return result
    end

    function M.LuaUnit.help()
        print(M.USAGE)
        os.exit(0)
    end

    function M.LuaUnit.version()
        print('LuaUnit v'..M.VERSION..' by Philippe Fremy <phil@freehackers.org>')
        os.exit(0)
    end

    function M.LuaUnit.patternInclude( patternFilter, expr )
        -- check if any of patternFilter is contained in expr. If so, return true.
        -- return false if None of the patterns are contained in expr
        -- if patternFilter is nil, return true (no filtering)
        if patternFilter == nil then
            return true
        end

        for i,pattern in ipairs(patternFilter) do
            if string.find(expr, pattern) then
                return true
            end
        end

        return false
    end

----------------------------------------------------------------
--                     class NodeStatus
----------------------------------------------------------------

    local NodeStatus = { __class__ = 'NodeStatus' } -- class
    local NodeStatus_MT = { __index = NodeStatus } -- metatable
    M.NodeStatus = NodeStatus

    -- values of status
    NodeStatus.PASS  = 'PASS'
    NodeStatus.FAIL  = 'FAIL'
    NodeStatus.ERROR = 'ERROR'

    function NodeStatus:new( number, testName, className )
        local t = { number = number, testName = testName, className = className }
        setmetatable( t, NodeStatus_MT )
        t:pass()
        return t
    end

    function NodeStatus:pass()
        self.status = self.PASS
        -- useless but we know it's the field we want to use
        self.msg = nil
        self.stackTrace = nil
    end

    function NodeStatus:fail(msg, stackTrace)
        self.status = self.FAIL
        self.msg = msg
        self.stackTrace = stackTrace
    end

    function NodeStatus:error(msg, stackTrace)
        self.status = self.ERROR
        self.msg = msg
        self.stackTrace = stackTrace
    end

    function NodeStatus:isPassed()
        return self.status == NodeStatus.PASS
    end

    function NodeStatus:isNotPassed()
        -- print('hasFailure: '..prettystr(self))
        return self.status ~= NodeStatus.PASS
    end

    function NodeStatus:isFailure()
        return self.status == NodeStatus.FAIL
    end

    function NodeStatus:isError()
        return self.status == NodeStatus.ERROR
    end

    function NodeStatus:statusXML()
        if self:isError() then
            return table.concat(
                {'            <error type="', xmlEscape(self.msg), '">\n',
                 '                <![CDATA[', xmlCDataEscape(self.stackTrace),
                 ']]></error>\n'})
        elseif self:isFailure() then
            return table.concat(
                {'            <failure type="', xmlEscape(self.msg), '">\n',
                 '                <![CDATA[', xmlCDataEscape(self.stackTrace),
                 ']]></failure>\n'})
        end
        return '            <passed/>\n' -- (not XSD-compliant! normally shouldn't get here)
    end

    --------------[[ Output methods ]]-------------------------

    function M.LuaUnit.statusLine(result)
        -- return status line string according to results
        local s = string.format('Ran %d tests in %0.3f seconds, %d successes',
            result.runCount, result.duration, result.passedCount )
        if result.notPassedCount > 0 then
            if result.failureCount > 0 then
                s = s..string.format(', %d failures', result.failureCount )
            end
            if result.errorCount > 0 then
                s = s..string.format(', %d errors', result.errorCount )
            end
        else
            s = s..', 0 failures'
        end
        if result.nonSelectedCount > 0 then
            s = s..string.format(", %d non-selected", result.nonSelectedCount )
        end
        return s
    end

    function M.LuaUnit:startSuite(testCount, nonSelectedCount)
        self.result = {}
        self.result.testCount = testCount
        self.result.nonSelectedCount = nonSelectedCount
        self.result.passedCount = 0
        self.result.runCount = 0
        self.result.currentTestNumber = 0
        self.result.currentClassName = ""
        self.result.currentNode = nil
        self.result.suiteStarted = true
        self.result.startTime = os.clock()
        self.result.startDate = os.date(os.getenv('LUAUNIT_DATEFMT'))
        self.result.startIsodate = os.date('%Y-%m-%dT%H:%M:%S')
        self.result.patternFilter = self.patternFilter
        self.result.tests = {}
        self.result.failures = {}
        self.result.errors = {}
        self.result.notPassed = {}

        self.outputType = self.outputType or TextOutput
        self.output = self.outputType:new()
        self.output.runner = self
        self.output.result = self.result
        self.output.verbosity = self.verbosity
        self.output.fname = self.fname
        self.output:startSuite()
    end

    function M.LuaUnit:startClass( className )
        self.result.currentClassName = className
        self.output:startClass( className )
    end

    function M.LuaUnit:startTest( testName  )
        self.result.currentTestNumber = self.result.currentTestNumber + 1
        self.result.runCount = self.result.runCount + 1
        self.result.currentNode = NodeStatus:new(
            self.result.currentTestNumber,
            testName,
            self.result.currentClassName
        )
        self.result.currentNode.startTime = os.clock()
        table.insert( self.result.tests, self.result.currentNode )
        self.output:startTest( testName )
    end

    function M.LuaUnit:addStatus( err )
        -- "err" is expected to be a table / result from protectedCall()
        if err.status == NodeStatus.PASS then return end

        local node = self.result.currentNode

        --[[ As a first approach, we will report only one error or one failure for one test.

        However, we can have the case where the test is in failure, and the teardown is in error.
        In such case, it's a good idea to report both a failure and an error in the test suite. This is
        what Python unittest does for example. However, it mixes up counts so need to be handled carefully: for
        example, there could be more (failures + errors) count that tests. What happens to the current node ?

        We will do this more intelligent version later.
        ]]

        -- if the node is already in failure/error, just don't report the new error (see above)
        if node.status ~= NodeStatus.PASS then return end

        table.insert( self.result.notPassed, node )

        if err.status == NodeStatus.FAIL then
            node:fail( err.msg, err.trace )
            table.insert( self.result.failures, node )
            self.output:addFailure( node )
        elseif err.status == NodeStatus.ERROR then
            node:error( err.msg, err.trace )
            table.insert( self.result.errors, node )
            self.output:addError( node )
        end
    end

    function M.LuaUnit:endTest()
        local node = self.result.currentNode
        -- print( 'endTest() '..prettystr(node))
        -- print( 'endTest() '..prettystr(node:isNotPassed()))
        node.duration = os.clock() - node.startTime
        node.startTime = nil
        self.output:endTest( node )

        if node:isPassed() then
            self.result.passedCount = self.result.passedCount + 1
        elseif node:isError() then
            if self.quitOnError or self.quitOnFailure then
                -- Runtime error - abort test execution as requested by
                -- "--error" option. This is done by setting a special
                -- flag that gets handled in runSuiteByInstances().
                print("\nERROR during LuaUnit test execution:\n" .. node.msg)
                self.result.aborted = true
            end
        elseif node:isFailure() then
            if self.quitOnFailure then
                -- Failure - abort test execution as requested by
                -- "--failure" option. This is done by setting a special
                -- flag that gets handled in runSuiteByInstances().
                print("\nFailure during LuaUnit test execution:\n" .. node.msg)
                self.result.aborted = true
            end
        end
        self.result.currentNode = nil
    end

    function M.LuaUnit:endClass()
        self.output:endClass()
    end

    function M.LuaUnit:endSuite()
        if self.result.suiteStarted == false then
            error('LuaUnit:endSuite() -- suite was already ended' )
        end
        self.result.duration = os.clock()-self.result.startTime
        self.result.suiteStarted = false

        -- Expose test counts for outputter's endSuite(). This could be managed
        -- internally instead, but unit tests (and existing use cases) might
        -- rely on these fields being present.
        self.result.notPassedCount = #self.result.notPassed
        self.result.failureCount = #self.result.failures
        self.result.errorCount = #self.result.errors

        self.output:endSuite()
    end

    function M.LuaUnit:setOutputType(outputType)
        -- default to text
        -- tap produces results according to TAP format
        if outputType:upper() == "NIL" then
            self.outputType = NilOutput
            return
        end
        if outputType:upper() == "TAP" then
            self.outputType = TapOutput
            return
        end
        if outputType:upper() == "JUNIT" then
            self.outputType = JUnitOutput
            return
        end
        if outputType:upper() == "TEXT" then
            self.outputType = TextOutput
            return
        end
        error( 'No such format: '..outputType,2)
    end

    --------------[[ Runner ]]-----------------

    function M.LuaUnit:protectedCall(classInstance, methodInstance, prettyFuncName)
        -- if classInstance is nil, this is just a function call
        -- else, it's method of a class being called.

        local function err_handler(e)
            -- transform error into a table, adding the traceback information
            return {
                status = NodeStatus.ERROR,
                msg = e,
                trace = string.sub(debug.traceback("", 3), 2)
            }
        end

        local ok, err
        if classInstance then
            -- stupid Lua < 5.2 does not allow xpcall with arguments so let's use a workaround
            ok, err = xpcall( function () methodInstance(classInstance) end, err_handler )
        else
            ok, err = xpcall( function () methodInstance() end, err_handler )
        end
        if ok then
            return {status = NodeStatus.PASS}
        end

        -- determine if the error was a failed test:
        -- We do this by stripping the failure prefix from the error message,
        -- while keeping track of the gsub() count. A non-zero value -> failure
        local failed
        err.msg, failed = err.msg:gsub(M.FAILURE_PREFIX, "", 1)
        if failed > 0 then
            err.status = NodeStatus.FAIL
        end

        -- reformat / improve the stack trace
        if prettyFuncName then -- we do have the real method name
            err.trace = err.trace:gsub("in (%a+) 'methodInstance'", "in %1 '"..prettyFuncName.."'")
        end
        if STRIP_LUAUNIT_FROM_STACKTRACE then
            err.trace = stripLuaunitTrace(err.trace)
        end

        return err -- return the error "object" (table)
    end


    function M.LuaUnit:execOneFunction(className, methodName, classInstance, methodInstance)
        -- When executing a test function, className and classInstance must be nil
        -- When executing a class method, all parameters must be set

        if type(methodInstance) ~= 'function' then
            error( tostring(methodName)..' must be a function, not '..type(methodInstance))
        end

        local prettyFuncName
        if className == nil then
            className = '[TestFunctions]'
            prettyFuncName = methodName
        else
            prettyFuncName = className..'.'..methodName
        end

        if self.lastClassName ~= className then
            if self.lastClassName ~= nil then
                self:endClass()
            end
            self:startClass( className )
            self.lastClassName = className
        end

        self:startTest(prettyFuncName)

        -- run setUp first (if any)
        if classInstance then
            local func = self.asFunction( classInstance.setUp )
                         or self.asFunction( classInstance.Setup )
                         or self.asFunction( classInstance.setup )
                         or self.asFunction( classInstance.SetUp )
            if func then
                self:addStatus(self:protectedCall(classInstance, func, className..'.setUp'))
            end
        end

        -- run testMethod()
        if self.result.currentNode:isPassed() then
            self:addStatus(self:protectedCall(classInstance, methodInstance, prettyFuncName))
        end

        -- lastly, run tearDown (if any)
        if classInstance then
            local func = self.asFunction( classInstance.tearDown )
                         or self.asFunction( classInstance.TearDown )
                         or self.asFunction( classInstance.teardown )
                         or self.asFunction( classInstance.Teardown )
            if func then
                self:addStatus(self:protectedCall(classInstance, func, className..'.tearDown'))
            end
        end

        self:endTest()
    end

    function M.LuaUnit.expandOneClass( result, className, classInstance )
        -- add all test methods of classInstance to result
        for methodName, methodInstance in sortedPairs(classInstance) do
            if M.LuaUnit.asFunction(methodInstance) and M.LuaUnit.isMethodTestName( methodName ) then
                table.insert( result, { className..'.'..methodName, classInstance } )
            end
        end
    end

    function M.LuaUnit.expandClasses( listOfNameAndInst )
        -- expand all classes (provided as {className, classInstance}) to a list of {className.methodName, classInstance}
        -- functions and methods remain untouched
        local result = {}

        for i,v in ipairs( listOfNameAndInst ) do
            local name, instance = v[1], v[2]
            if M.LuaUnit.asFunction(instance) then
                table.insert( result, { name, instance } )
            else
                if type(instance) ~= 'table' then
                    error( 'Instance must be a table or a function, not a '..type(instance)..', value '..prettystr(instance))
                end
                if M.LuaUnit.isClassMethod( name ) then
                    local className, methodName = M.LuaUnit.splitClassMethod( name )
                    local methodInstance = instance[methodName]
                    if methodInstance == nil then
                        error( "Could not find method in class "..tostring(className).." for method "..tostring(methodName) )
                    end
                    table.insert( result, { name, instance } )
                else
                    M.LuaUnit.expandOneClass( result, name, instance )
                end
            end
        end

        return result
    end

    function M.LuaUnit.applyPatternFilter( patternFilter, listOfNameAndInst )
        local included, excluded = {}, {}
        for i, v in ipairs( listOfNameAndInst ) do
            -- local name, instance = v[1], v[2]
            if M.LuaUnit.patternInclude( patternFilter, v[1] ) then
                table.insert( included, v )
            else
                table.insert( excluded, v )
            end
        end
        return included, excluded
    end

    function M.LuaUnit:runSuiteByInstances( listOfNameAndInst )
        -- Run an explicit list of tests. All test instances and names must be supplied.
        -- each test must be one of:
        --   * { function name, function instance }
        --   * { class name, class instance }
        --   * { class.method name, class instance }

        local expandedList, filteredList, filteredOutList, className, methodName, methodInstance
        expandedList = self.expandClasses( listOfNameAndInst )

        filteredList, filteredOutList = self.applyPatternFilter( self.patternFilter, expandedList )

        self:startSuite( #filteredList, #filteredOutList )

        for i,v in ipairs( filteredList ) do
            local name, instance = v[1], v[2]
            if M.LuaUnit.asFunction(instance) then
                self:execOneFunction( nil, name, nil, instance )
            else
                if type(instance) ~= 'table' then
                    error( 'Instance must be a table or a function, not a '..type(instance)..', value '..prettystr(instance))
                else
                    assert( M.LuaUnit.isClassMethod( name ) )
                    className, methodName = M.LuaUnit.splitClassMethod( name )
                    methodInstance = instance[methodName]
                    if methodInstance == nil then
                        error( "Could not find method in class "..tostring(className).." for method "..tostring(methodName) )
                    end
                    self:execOneFunction( className, methodName, instance, methodInstance )
                end
            end
            if self.result.aborted then break end -- "--error" or "--failure" option triggered
        end

        if self.lastClassName ~= nil then
            self:endClass()
        end

        self:endSuite()

        if self.result.aborted then
            print("LuaUnit ABORTED (as requested by --error or --failure option)")
            os.exit(-2)
        end
    end

    function M.LuaUnit:runSuiteByNames( listOfName )
        -- Run an explicit list of test names

        local  className, methodName, instanceName, instance, methodInstance
        local listOfNameAndInst = {}

        for i,name in ipairs( listOfName ) do
            if M.LuaUnit.isClassMethod( name ) then
                className, methodName = M.LuaUnit.splitClassMethod( name )
                instanceName = className
                instance = _G[instanceName]

                if instance == nil then
                    error( "No such name in global space: "..instanceName )
                end

                if type(instance) ~= 'table' then
                    error( 'Instance of '..instanceName..' must be a table, not '..type(instance))
                end

                methodInstance = instance[methodName]
                if methodInstance == nil then
                    error( "Could not find method in class "..tostring(className).." for method "..tostring(methodName) )
                end

            else
                -- for functions and classes
                instanceName = name
                instance = _G[instanceName]
            end

            if instance == nil then
                error( "No such name in global space: "..instanceName )
            end

            if (type(instance) ~= 'table' and type(instance) ~= 'function') then
                error( 'Name must match a function or a table: '..instanceName )
            end

            table.insert( listOfNameAndInst, { name, instance } )
        end

        self:runSuiteByInstances( listOfNameAndInst )
    end

    function M.LuaUnit.run(...)
        -- Run some specific test classes.
        -- If no arguments are passed, run the class names specified on the
        -- command line. If no class name is specified on the command line
        -- run all classes whose name starts with 'Test'
        --
        -- If arguments are passed, they must be strings of the class names
        -- that you want to run or generic command line arguments (-o, -p, -v, ...)

        local runner = M.LuaUnit.new()
        return runner:runSuite(...)
    end

    function M.LuaUnit:runSuite( ... )

        local args = {...}
        if type(args[1]) == 'table' and args[1].__class__ == 'LuaUnit' then
            -- run was called with the syntax M.LuaUnit:runSuite()
            -- we support both M.LuaUnit.run() and M.LuaUnit:run()
            -- strip out the first argument
            table.remove(args,1)
        end

        if #args == 0 then
            args = cmdline_argv
        end

        local no_error, val = pcall( M.LuaUnit.parseCmdLine, args )
        if not no_error then
            print(val) -- error message
            print()
            print(M.USAGE)
            os.exit(-1)
        end

        local options = val

        -- We expect these option fields to be either `nil` or contain
        -- valid values, so it's safe to always copy them directly.
        self.verbosity     = options.verbosity
        self.quitOnError   = options.quitOnError
        self.quitOnFailure = options.quitOnFailure
        self.fname         = options.fname
        self.patternFilter = options.pattern

        if options.output and options.output:lower() == 'junit' and options.fname == nil then
            print('With junit output, a filename must be supplied with -n or --name')
            os.exit(-1)
        end

        if options.output then
            no_error, val = pcall(self.setOutputType, self, options.output)
            if not no_error then
                print(val) -- error message
                print()
                print(M.USAGE)
                os.exit(-1)
            end
        end

        self:runSuiteByNames( options.testNames or M.LuaUnit.collectTests() )

        return self.result.notPassedCount
    end
-- class LuaUnit

-- For compatbility with LuaUnit v2
M.run = M.LuaUnit.run
M.Run = M.LuaUnit.run

function M:setVerbosity( verbosity )
    M.LuaUnit.verbosity = verbosity
end
M.set_verbosity = M.setVerbosity
M.SetVerbosity = M.setVerbosity


return M
