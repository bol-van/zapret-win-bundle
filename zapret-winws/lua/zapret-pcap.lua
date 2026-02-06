function pcap_write_header(file)
	-- big endian, nanoseconds in timestamps, ver 2.4, max packet size - 0x4000 (16384), 0x65 - l3 packets without l2
	file:write("\xA1\xB2\x3C\x4D\x00\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x65")
end
function pcap_write_packet(file, raw)
	local sec, nsec = clock_gettime();
	file:write(bu32(sec)..bu32(nsec)..bu32(#raw)..bu32(#raw))
	file:write(raw)
end
function pcap_write(file, raw)
	local pos = file:seek()
	if (pos==0) then
		pcap_write_header(file)
	end
	pcap_write_packet(file, raw)
end

-- test case : --writeable=zdir --in-range=a --lua-desync=pcap:file=test.pcap
-- arg : file=<filename> - file for storing pcap data. if --writeable is specified and filename is relative - append filename to writeable path
-- arg : keep - do not overwrite file, append packets to existing
function pcap(ctx, desync)
	if not desync.arg.file or #desync.arg.file==0 then
		error("pcap requires 'file' parameter")
	end
	local fn_cache_name = desync.func_instance.."_fn"
	if not _G[fn_cache_name] then
		_G[fn_cache_name] = writeable_file_name(desync.arg.file)
		if not desync.arg.keep then
			-- overwrite file
			os.remove(_G[fn_cache_name])
		end
	end
	local f = io.open(_G[fn_cache_name], "ab")
	if not f then
		error("pcap: could not write to '".._G[fn_cache_name].."'")
	end
	pcap_write(f, raw_packet(ctx))
	f:close()
end
