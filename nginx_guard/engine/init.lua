-- Loaded once in init_by_lua_file. File parsing is intentionally outside the
-- request access phase.
package.path = "/www/server/nginx_guard/engine/?.lua;" .. package.path
local ok, engine = pcall(require, "ng_guard_engine")
if not ok then
    ngx.log(ngx.ERR, "nginx_guard: cannot load engine: ", engine)
else
    _G.ng_guard_engine = engine
    pcall(engine.reload)
end
