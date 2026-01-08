-- Atomic tunnel registration with duplicate check
-- KEYS[1] = tunnel:{subdomain}
-- ARGV[1] = tunnel data JSON
-- ARGV[2] = TTL in seconds
-- ARGV[3] = user_id attempting registration

local existing = redis.call('GET', KEYS[1])

if existing then
    local parsed = cjson.decode(existing)
    if parsed['user_id'] == ARGV[3] then
        -- Same user, allow takeover
        redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
        return cjson.encode({status = 'takeover', previous = existing})
    else
        -- Different user, reject
        return cjson.encode({status = 'conflict', owner = parsed['user_id']})
    end
end

-- Not in use, register
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
return cjson.encode({status = 'created'})