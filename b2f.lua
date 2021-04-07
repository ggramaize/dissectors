-- b2f.lua
-- B2F Dissector
p_b2f = Proto ( "B2F", "B2F Message forwarding protocol")
p_b2f.fields.cmd = ProtoField.new( "B2F Command", "b2f.cmd", ftypes.STRING )
-------------------------------------------------------------------------------
-- SID features
-------------------------------------------------------------------------------
local features = {
	F_PERS_MSG_ACK=1, 	-- A
	F_COMP_XFER=2, 		-- B
	F_DATE_DISTR=4, 	-- C
	--F_=8, 		-- D
	F_BASIC_XFER=16, 	-- F
	F_GZIP=32, 		-- G
	F_HLOC=64, 		-- H
	F_NULLCMD=128, 		-- I
	--F_=256, 		-- J
	F_G1NNA_COMP=512, 	-- L
	F_MID=1024, 		-- M
	F_AA4RE_EXT_REJ=2048, 	-- R
	F_AA4RE_EXT_S=4096, 	-- S
	F_WLNK_T=8192, 		-- T
	F_WLNK_U=16384, 	-- U
	--F_=32768, 		-- W
	F_COMP_BATCH_FWD=65536,	-- X
	F_BID=131072, 		-- $
}

local function feat_to_str( val)
	if     ( val == F_PERS_MSG_ACK ) then return "Acknowledge for personal messages"
	elseif ( val == F_COMP_XFER ) then return "FBB compressed protocol support"
	elseif ( val == F_DATE_DISTR ) then return "Automatic distribution of current date / time (obsolete)"
	--elseif ( val ==  ) then return ""
	elseif ( val == F_BASIC_XFER ) then return "FBB basic protocol support"
	elseif ( val == F_GZIP ) then return "GZIP compression"
	elseif ( val == F_HLOC ) then return "Hierarchical Location designators"
	elseif ( val == F_NULLCMD ) then return "Calling station ID support"
	--elseif ( val ==  ) then return ""
	elseif ( val == F_G1NNA_COMP ) then return "G1NNA Compression"
	elseif ( val == F_MID ) then return "Message Identifier support"
	elseif ( val == F_AA4RE_EXT_REJ ) then return "AA4RE Extended reject responses"
	elseif ( val == F_AA4RE_EXT_S ) then return "AA4RE Extended S commands support"
	elseif ( val == F_WLNK_T ) then return "Winlink (undocumented feature T)"
	elseif ( val == F_WLNK_U ) then return "Winlink (undocumented feature U)"
	--elseif ( val ==  ) then return ""
	elseif ( val == F_COMP_BATCH_FWD ) then return "Compressed batch forwarding"
	elseif ( val == F_BID ) then return "BID supported"
	end
	return "Unknown Extension"
end

local function find_next_cr( buffer)
	local len = buffer:len()
	for i=0 , len-1 , 1 do
		if( buffer(i,1):uint() == 0x0a or buffer(i,1):uint() == 0x0d ) then return i end 
	end
	return len
end
-------------------------------------------------------------------------------
-- Main Dissector
-------------------------------------------------------------------------------
function p_b2f.dissector( buffer, pinfo, tree)
	if ( buffer:len() < 1 ) then return end

	local pk_size = buffer():len()

	-- Set protocol name
	pinfo.cols.protocol = "B2F"

	if( buffer(0,1):uint() < 0x20 ) then return end
	
	local cur_line = 0
	local len_line = 0

	print( "*** New packet" )
	local subtree = tree:add( p_b2f, buffer(), "Open B2F Commands")	

	repeat
		::next_line::
		-- Check for the next line
		cur_line = cur_line + len_line
		len_line = find_next_cr( buffer( cur_line))+1
		
		-- Skip new lines
		if( buffer():len() >= 1 and buffer( cur_line, 1):uint() == 0x0a or buffer( cur_line, 1):uint() == 0x0d ) then goto next_line end
		
		-- Process the line
		subtree:add( buffer( cur_line, len_line-1), "B2F Command: " .. buffer( cur_line, len_line-1 ):string() )
		print( "   " .. buffer( cur_line, len_line-1 ):string() )

		-- Break the loop once we reach the end of the buffer
		if ( cur_line+len_line >= pk_size ) then break end
	until ( false )

	
	--if (  ) then end
end




