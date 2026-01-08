-- Atomic increment with TTL for rate limiting
-- KEYS[1] = ratelimit:{subdomain}:{window}
-- ARGV[1] = TTL in seconds

local count = redis.call('INCR', KEYS[1])
if count == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return count