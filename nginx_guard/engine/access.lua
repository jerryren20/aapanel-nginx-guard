-- Nginx Guard request hook.
--
-- Native Nginx maps and limit_req do the cheap metadata/CC checks.  This
-- hook only asks the Lua engine to inspect a bounded text request body and to
-- keep the temporary-ban state.  It never installs a location, response
-- filter, or proxy setting, so WebSocket and SSE requests keep the site's
-- original behavior.
local engine = rawget(_G, "ng_guard_engine")

local function set_event_rule(result)
    -- The variable is declared by the generated http-level map.  A pcall is
    -- intentional: an old hand-edited configuration must fail open instead
    -- of turning a request into a 500/503 merely because the log variable is
    -- unavailable.
    local rule_id = ""
    if type(result) == "table" and result.rule_id then
        rule_id = tostring(result.rule_id)
    end
    pcall(function()
        ngx.var.ng_guard_lua_rule_id = rule_id
    end)
end

if not engine then
    ngx.log(ngx.ERR, "nginx_guard: engine unavailable; fail-open")
    return
end

local ok, result = pcall(engine.inspect)
if not ok then
    ngx.log(ngx.ERR, "nginx_guard: request inspection failed; fail-open: ", result)
    return
end

set_event_rule(result)

if result and result.action == "block" then
    local status = tonumber(result.status) or 403
    if status ~= 403 and status ~= 404 and status ~= 429 and status ~= 444 then
        status = 403
    end
    if status == 444 then
        return ngx.exit(444)
    end
    return ngx.exit(status)
end
