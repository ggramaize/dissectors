-- dvst.lua
-- Digital Voice Streaming Protocol
p_dvst = Proto ( "dvst", "Digital Voice Streaming Protocol")

local function is_config_frame( buffer)
	return buffer(4,1):uint() == 0x10 
end

local function is_ambe_voice_frame( buffer)
	return buffer(4,1):uint() == 0x20
end

local function is_voice_stream( buffer)
	return buffer(8,1):uint() == 0x20
end

local function get_frame_type_string( buffer)
	if ( is_config_frame(buffer) ) then return "Configuration" end
	if ( is_ambe_voice_frame(buffer) ) then return "AMBE Voice" end
	return "Unknown"
end

local function get_stream_type_string( buffer)
	if ( is_voice_stream(buffer) ) then return "Voice" end
	return "Unknown"
end

function p_dvst.dissector ( buffer, pinfo, tree)
	-- Validate packet length
	--if ( buffer:len() ~= 27 or buffer:len() ~= 56 ) then return end
	
	-- Validate signature field
	if( buffer(0,4):string() ~= "DSVT" ) then return end
	
	-- Set protocol name
	--pinfo.cols.protocol = "DPLUS"
	pinfo.cols.info = "DVST"
	
	-- Variables
	local stream_id = buffer(12,2);
	local seq_num = buffer(14,1);
	
	-- Fill the diagnostic tree
	local subtree = tree:add( p_dvst, buffer(), "Digital Voice Streaming Protocol")
	subtree:add( buffer(0,4) , "Signature: " .. buffer(0,4):string())
	subtree:add( buffer(4,1) , "Frame Type: " .. get_frame_type_string( buffer() ) .. " (0x" .. buffer(4,1) .. ")")
	subtree:add( buffer(5,3) , "Reserved: " .. buffer(5,3))
	subtree:add( buffer(8,1) , "Stream type: " .. get_stream_type_string( buffer() ) .. " (0x" .. buffer(8,1) .. ")")
	subtree:add( buffer(9,3) , "Reserved: " .. buffer(9,3))
	subtree:add( buffer(12,2), "Stream id: 0x" .. stream_id)
	subtree:add( buffer(14,1), "Sequence: 0x" .. seq_num)
	
	-- Configuration Frame
	if ( is_voice_stream(buffer()) and is_config_frame(buffer()) ) then
		pinfo.cols.info:append(" Stream Configuration SID=" .. stream_id:uint() )
		-- subtree:add( buffer(,8), ": " .. buffer(,):string())
		-- Subtree for the flag fields
		--local subtree_flags = subtree:add( buffer(15,3) , "D-Star flags" )
		Dissector.get("dstarflags"):call( buffer(15,3):tvb(), pinfo, subtree)
		
		-- Next fields
		subtree:add( buffer(18,8), "RPT1: " .. buffer(18,8):string())
		subtree:add( buffer(26,8), "RPT2: " .. buffer(26,8):string())
		subtree:add( buffer(34,8), "UR: " .. buffer(34,8):string())
		subtree:add( buffer(42,12), "MY: " .. buffer(42,8):string() .. "/" .. buffer(50,4):string())
		subtree:add( buffer(54,2), "Checksum: " .. buffer(54,2))
	end
	
	-- AMBE Voice Frame
	if ( is_voice_stream(buffer()) and is_ambe_voice_frame(buffer()) ) then
		pinfo.cols.info:append(" Voice Fragment SID=" .. stream_id:uint() .. " SEQ=0x" .. seq_num .. " [Codec: AMBE]")
		subtree:add( buffer(15,9), "AMBE voice fragment: " .. buffer(15,9))
		subtree:add( buffer(24,3), "DV data fragment: " .. buffer(24,3))
	end
	--subtree:add( buffer(,), ": " .. buffer(,):string())
end
