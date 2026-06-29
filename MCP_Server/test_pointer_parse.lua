-- Offline unit tests for UNIT-24 pure pointer-analysis logic.
-- Run: lua MCP_Server/test_pointer_parse.lua   (from repo root, or from MCP_Server/)
local here = arg[0]:match("^(.*)[/\\]") or "."

-- The whole bridge will not compile under stock Lua 5.4+ (a const difference in
-- the JSON codec at line 357), so extract and load only the UNIT-24 slice over a
-- small toHex fixture (UNIT-24's only chunk-local dependency).
local function loadUnit24()
    local f = assert(io.open(here .. "/ce_mcp_bridge.lua", "r"))
    local src = f:read("*a"); f:close()
    local slice = src:match("(%-%- >>> BEGIN UNIT%-24.-END UNIT%-24)")
    assert(slice, "could not find UNIT-24 slice (markers missing?)")
    local prelude = [[
local function toHex(num)
    if not num then return "nil" end
    if num >= 0 and num <= 0xFFFFFFFF then return string.format("0x%08X", num) end
    return string.format("0x%X", num)
end
]]
    assert(load(prelude .. "\n" .. slice))()
end
loadUnit24()

assert(type(parseMemoryOperand) == "function", "UNIT-24 slice did not define parseMemoryOperand")

local pass, fail = 0, 0
local function check(name, cond, got)
    if cond then
        pass = pass + 1
    else
        fail = fail + 1
        print("FAIL: " .. name .. (got ~= nil and ("  (got: " .. tostring(got) .. ")") or ""))
    end
end

-- form / base / index / scale / disp
local function P(instr) return parseMemoryOperand(instr) end

local r
r = P("mov [rcx+04],eax");        check("reg+disp form",   r and r.form=="register_indirect")
                                  check("reg+disp base",   r and r.base=="rcx")
                                  check("reg+disp disp",   r and r.disp==4, r and r.disp)
r = P("mov [rbp-08],eax");        check("reg-disp neg",    r and r.disp==-8, r and r.disp)
r = P("mov [rax+rcx*4+8],edx");   check("indexed form",    r and r.form=="indexed")
                                  check("indexed base",    r and r.base=="rax")
                                  check("indexed index",   r and r.index=="rcx")
                                  check("indexed scale",   r and r.scale==4, r and r.scale)
                                  check("indexed disp",    r and r.disp==8, r and r.disp)
r = P("mov [rax+rcx*4],edx");     check("indexed no disp", r and r.form=="indexed" and r.disp==0)
r = P("mov [rsi],eax");           check("bare reg form",   r and r.form=="register_indirect" and r.disp==0)
r = P("mov [rip+12345],eax");     check("rip form",        r and r.form=="rip_relative")
                                  check("rip disp hex",    r and r.disp==0x12345, r and r.disp)
r = P("mov dword ptr [rcx+10],eax"); check("ptr prefix",   r and r.base=="rcx" and r.disp==0x10, r and r.disp)
r = P("mov [7FF6ABCD],eax");      check("absolute form",   r and r.form=="absolute")
                                  check("absolute disp",   r and r.disp==0x7FF6ABCD, r and r.disp)
r = P("mov eax,[rdx+1C]");        check("src operand",     r and r.base=="rdx" and r.disp==0x1C, r and r.disp)
r = P("mov [ds:rcx+4],eax");      check("segment strip",   r and r.base=="rcx" and r.disp==4)
r = P("mov [rax+rcx],eax");       check("bail implicit scale", r==nil)
r = P("nop");                     check("bail no operand", r==nil)

print(string.format("\n%d passed, %d failed", pass, fail))
os.exit(fail == 0 and 0 or 1)
