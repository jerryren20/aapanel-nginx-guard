-- Worker timer performs hot rule snapshot refresh without an Nginx reload.
local engine = rawget(_G, "ng_guard_engine")
if not engine then
    return
end

local function refresh()
    local ok, err = pcall(engine.reload_if_changed)
    if not ok then
        ngx.log(ngx.ERR, "nginx_guard: worker refresh failed: ", err)
    end
end

local ok, err = ngx.timer.every(5, refresh)
if not ok then
    ngx.log(ngx.ERR, "nginx_guard: cannot start refresh timer: ", err)
end
