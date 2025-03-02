-- yapp_u.lua - Unidirectional YAPP Transfer

-- Some module-specific constants
local proto_shortname = "yapp_u"
local proto_fullname  = "Unidirectional YAPP Transfer"

-- Protocol Definition
p_yapp_u = Proto ( proto_shortname, proto_fullname)

local function yapp_u_checksum( buffer)
	local len = buffer():len()
	local csum = 0
	local i
	
	for i=0, len-1, 1 do
		csum = csum + buffer(i,1):uint()
	end
	
	return bit.band(csum, 0xFF)
end

local function yapp_u_unpack( buffer, unpacked_bytes)
	local len = buffer():len()
	local payload_size = 0
	local segment_size = 0
	local i = 0
	
	if( buffer(0,1):uint() ~= 0x01 ) then return end
	
	while ( i < len) do
		local cur_byte = buffer(i,1):uint()
		
		-- Invalid frame
		if ( i+1 >= len ) then return nil end
		
		if( cur_byte == 0x01 ) then
			i = i + 2 + buffer(i+1,1):uint() -- Two for the header, plus the payload
			
		elseif( cur_byte == 0x02 ) then
			segment_size = buffer(i+1,1):uint()
			payload_size = payload_size + segment_size
			unpacked_bytes:append( buffer( i+2, segment_size):bytes())
			i = i + 2 + buffer(i+1,1):uint() -- Two for the header, plus the payload
			
		elseif( cur_byte == 0x04 ) then
			return payload_size  -- One for the extra byte, and 1 for the fencepost
		else
			-- Invalid Frame
			return nil
		end
	end
	
	-- Incomplete file
	return nil
end

function p_yapp_u.dissector ( buffer, pinfo, tree)
	local len = buffer():len()
	local subtree = tree:add( p_yapp_u, buffer, "")
	
	local unpacked_bytes = ByteArray.new()

	yapp_u_unpack( buffer, unpacked_bytes)
	local unpacked_tvb = unpacked_bytes:tvb("Unpacked Payload")
	local metadata = buffer( 2, buffer(1,1):uint())
	local fname_sz = metadata:stringz():len()
	local offset = buffer( 2+fname_sz+1, buffer(1,1):uint()-fname_sz-1)

	local filename_tree = subtree:add( p_yapp_u, buffer(2,fname_sz), "Filename/Title: \"" .. metadata:stringz() .. "\"")
	local offset_tree = subtree:add( p_yapp_u, offset, "Offset: " .. tonumber( offset:stringz(), 10) .. " byte(s)")
	local payload_tree = subtree:add( p_yapp_u, unpacked_tvb(), "Payload" )
	local csum_tree = subtree:add( p_yapp_u, buffer( len-1, 1), "Checksum")
	
	-- Validate checksum
	if ( yapp_u_checksum( unpacked_tvb) == buffer( len-1, 1):uint() ) then
		subtree:add_expert_info( PI_MALFORMED, PI_ERROR, "Checksum validation failed")
		return
	else
		csum_tree.text = csum_tree.text .. " [valid]"
	end
		
	if ( pinfo.private["yapp_u_payload_format"] ~= nil ) then
		if ( pinfo.private["yapp_u_payload_format"] == "lzhuf") then
			Dissector.get("lzhuf"):call( unpacked_tvb, pinfo, tree)
			
		elseif ( encoding == "gzip" ) then
			unpacked_tvb:buf_encap("gzip")
			-- TODO: Invoke payload_dissector
			
		end
	end
end

