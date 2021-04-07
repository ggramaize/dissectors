-- dplus.lua
-- DPlus Protocol
p_dplus = Proto ( "dplus", "DPlus Protocol")

local function get_pk_type_name(pk_type)
	if( pk_type == 0x00 ) then return "Connection frame" end
	if( pk_type == 0x60 ) then return "Management frame" end
	if( pk_type == 0x80 ) then return "DVST frame" end
	return "Unknown"
end

function p_dplus.dissector ( buffer, pinfo, tree)
	-- Validate packet length
	if ( buffer:len() < 3 ) then return end
	
	-- Set protocol name
	pinfo.cols.protocol = "DPLUS"
	
	-- Variables
	local pk_len = buffer(0,1):uint()
	local pk_type = buffer(1,1):uint()

	-- Subtree
	local subtree = tree:add( p_dplus, buffer(), "DPlus Protocol")
	subtree:add( buffer(0,1) , "Length: " .. pk_len .. " byte(s)")
	subtree:add( buffer(1,1) , "Type: " .. get_pk_type_name(pk_type))
	
	if ( pk_type == 0x00 ) then
		if( pk_len == 5 and buffer(2,1):uint() == 0x18 and buffer(3,1):uint() == 0x00 ) then
			if( buffer(4,1):uint() == 0x01 ) then
				-- Connect
				pinfo.cols.info = "DPlus Connection"
		    elseif( buffer(4,1):uint() == 0x00 ) then
				-- Disconnect
				pinfo.cols.info = "DPlus Disconnection"
			else
			    -- Unknown
			end
		end
	end
	
	if( pk_type == 0x60) then
		-- Command Frame
		
	end
	
	if( pk_type == 0x80) then
		-- DVST Frame
		Dissector.get("dvst"):call( buffer(2, buffer:len()-2):tvb(), pinfo, tree)
	end
end

local udp_dissector_table = DissectorTable.get("udp.port")
udp_dissector_table:add( 20001, p_dplus)


