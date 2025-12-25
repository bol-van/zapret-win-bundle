-- test case : --in-range=a --out-range=a --lua-desync=wgobfs:secret=mycoolpassword
-- encrypt standard wireguard messages - initiation, response, cookie - and change udp packet size
-- do not encrypt data messages and keepalives
-- wgobfs adds maximum of 30+padmax bytes to udp size
-- reduce MTU of wireguard interface to avoid ip fragmentation !
-- without knowing the secret encrypted packets should be crypto strong white noise with no signature
-- arg : secret - shared secret. any string. must be the same on both peers
-- arg : padmin - min random garbage bytes. 0 by default
-- arg : padmax - max random garbage bytes. 16 by default
function wgobfs(ctx, desync)
	local padmin = desync.arg.padmin and tonumber(desync.arg.padmin) or 0
	local padmax = desync.arg.padmax and tonumber(desync.arg.padmax) or 16
	local function genkey()
		-- cache key in a global var bound to instance name
		local key_cache_name = desync.func_instance.."_key"
		key = _G[key_cache_name]
		if not key then
			key = hkdf("sha256", "wgobfs_salt", desync.arg.secret, nil, 16)
			_G[key_cache_name] = key
		end
		return key
	end
	local function maybe_encrypted_payload(payload)
		for k,plsize in pairs({2+12+16+148, 2+12+16+92, 2+12+16+64}) do
			if #payload>=(plsize+padmin) and #payload<=(plsize+padmax) then
				return true
			end
		end
		return false
	end
	local function wg_payload_from_size(payload)
		if #payload==148 then return "wireguard_initiation"
		elseif #payload==92 then return "wireguard_response"
		elseif #payload==64 then return "wireguard_cookie"
		else return nil
		end
	end

	if not desync.dis.udp then
		instance_cutoff(ctx)
		return
	end
	if not desync.arg.secret or #desync.arg.secret==0 then
		error("wgobfs requires secret")
	end
	if padmin>padmax then
		error("wgobfs: padmin>padmax")
	end
	if desync.l7payload=="wireguard_initiation" or desync.l7payload=="wireguard_response" or desync.l7payload=="wireguard_cookie" and #desync.dis.payload<65506 then
		DLOG("wgobfs: encrypting '"..desync.l7payload.."'. size "..#desync.dis.payload)
		local key = genkey()
		-- in aes-gcm every message require it's own crypto secure random iv
		-- encrypting more than one message with the same iv is considered catastrophic failure
		-- iv must be sent with encrypted message
		local iv = bcryptorandom(12)
		local encrypted, atag = aes_gcm(true, key, iv, bu16(#desync.dis.payload)..desync.dis.payload..brandom(math.random(padmin,padmax)), nil)
		desync.dis.payload = iv..atag..encrypted
		return VERDICT_MODIFY
	end

	if desync.l7payload=="unknown" and maybe_encrypted_payload(desync.dis.payload) then
		local key = genkey()
		local iv = string.sub(desync.dis.payload,1,12)
		local atag = string.sub(desync.dis.payload,13,28)
		local decrypted, atag2 = aes_gcm(false, key, iv, string.sub(desync.dis.payload,29))
		if atag==atag2 then
			local plen = u16(decrypted)
			if plen>(#decrypted-2) then
				DLOG("wgobfs: bad decrypted payload data")
			else
				desync.dis.payload = string.sub(decrypted, 3, 3+plen-1)
				if b_debug then DLOG("wgobfs: decrypted '"..(wg_payload_from_size(desync.dis.payload) or "unknown").."' message. size "..plen) end
				return VERDICT_MODIFY
			end
		else
			DLOG("wgobfs: decrypt auth tag mismatch")
		end
	end
end
