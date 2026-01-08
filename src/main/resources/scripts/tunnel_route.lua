-- Combined tunnel lookup with server health check
-- KEYS[1] = tunnel:{subdomain}

local tunnel_data = redis.call('GET', KEYS[1])

if not tunnel_data then
    return cjson.encode({status = 'not_found'})
end

local parsed = cjson.decode(tunnel_data)
local server_id = parsed['server_id']

if not server_id then
    return cjson.encode({status = 'invalid'})
end

local health_key = 'server:' .. server_id .. ':health'
local is_alive = redis.call('EXISTS', health_key)

if is_alive == 1 then
    return cjson.encode({
        status = 'ok',
        tunnel = tunnel_data
    })
else
    return cjson.encode({
        status = 'server_dead',
        tunnel = tunnel_data
    })
end