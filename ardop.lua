-- ardop.lua

-- ARDOP Dissectors
p_ardop = Proto ( "ARDOP", "ARDOP Interface")
p_ardop_c = Proto ( "ARDOP_C", "ARDOP Control Plane")
p_ardop_d = Proto ( "ARDOP_D", "ARDOP Data Plane")

-- Used to read the TCP source port
local f_tcp_srcport    = Field.new("tcp.srcport")
local original_dissector

-- Ternary operator
local function fif(condition, if_true, if_false)
	if condition then return if_true else return if_false end
end

-- Check if a value exists in a table
local function val_exists( haystack, needle)
    for key, val in pairs(haystack) do
        if ( val == needle ) then return true end
    end
    return false
end

-------------------------------------------------------------------------------
-- Global settings
-------------------------------------------------------------------------------
local ardop_settings =
{
    enabled      = true, -- whether this dissector is enabled or not
    port         = 8515, -- default TCP port number
    decode_b2f   = true, -- should this dissector interpret the payload as B2F
}

-------------------------------------------------------------------------------
-- Control Plane dissector
-------------------------------------------------------------------------------
function p_ardop_c.dissector ( buffer, pinfo, tree)
	-- Validate packet length
	if ( buffer:len() < 2 ) then return end
end

-------------------------------------------------------------------------------
-- Data Plane dissector
-------------------------------------------------------------------------------
-- Safely returns the data plane received packet type
local function dp_get_pk_type( buffer, is_dce_to_dte)
	if ( is_dce_to_dte == true and buffer:len() >= 5) then
		return buffer(2,3):string()
	end
	return nil
end

local function dp_print_rx_type ( p_type)
	if( p_type == "IDF" ) then return "ID Frame" end
	if( p_type == "ARQ" ) then return "Connected data" end
	if( p_type == "FEC" ) then return "Unconnected data" end
	if( p_type == "ERR" ) then return "Errored unconnected data" end
	return "Unknown"
end


function p_ardop_d.dissector ( buffer, pinfo, tree)
	-- Validate packet length
	if ( buffer:len() < 2 ) then return end
	
	-- Set protocol name
	pinfo.cols.protocol = "ARDOP_D"
	
	-- Call the original dissector & check the direction
	pcall( function() original_dissector:call( buffer, pinfo, tree) end )
	local is_dce_to_dte = ( pinfo.src_port == ardop_settings.port+1 )

	-- Variables
	local pk_len = buffer(0,2):uint()
	local pk_type = dp_get_pk_type( buffer, is_dce_to_dte)
	local data_offset = fif( is_dce_to_dte, 5, 2)
	local pk_data = buffer(data_offset)

	-- Subtree title
	local subtree_title = "ARDOP Data Plane, " .. fif( is_dce_to_dte, "Modem to Client, " .. dp_print_rx_type( pk_type), "Client to Modem")

	-- Update the info column
	pinfo.cols.info = subtree_title

	-- Subtree
	local subtree = tree:add( p_ardop_d, buffer(), subtree_title)
	subtree:add( buffer(0,2) , "Length: " .. pk_len .. " byte(s)")

	-- Modem to Client packet
	if ( is_dce_to_dte ) then
		subtree:add( buffer(2,3), "Type: " .. pk_type)
	end

	subtree:add( pk_data, "ARDOP Payload (" .. pk_data:len() .. " byte(s))")

	-- Attempt to invoke the B2F dissector for received connected mode data, or transmitted data, if it exists
	if( ardop_settings.decode_b2f and val_exists( Dissector.list(), "b2f" ) and ( not is_dce_to_dte or pk_type == "ARQ" ) ) then
		Dissector.get("b2f"):call( pk_data:tvb(), pinfo, tree)
	end
end


-------------------------------------------------------------------------------
-- Register settings & dissectors
-------------------------------------------------------------------------------
p_ardop.prefs.enabled = Pref.bool("Dissector enabled", ardop_settings.enabled,
                                        "Whether the ARDOP dissectors are enabled or not")

p_ardop.prefs.portnum = Pref.uint("Port Number", ardop_settings.port,
                                        "The port on which the ARDOP modem is listening")

p_ardop.prefs.decode_b2f = Pref.bool("Decode payload as B2F", ardop_settings.decode_b2f,
                                        "Whether the ARDOP data plane should interpret its payload as B2F")
-- Register the dissectors
local function regDissectors()
	DissectorTable.get("tcp.port"):add( ardop_settings.port, p_ardop_c)
	DissectorTable.get("tcp.port"):add( ardop_settings.port+1, p_ardop_d)
end
-- call it now, because we're enabled by default
regDissectors()

-- Unregister the dissectors
local function unregDissectors()
	DissectorTable.get("tcp.port"):remove( ardop_settings.port, p_ardop_c)
	DissectorTable.get("tcp.port"):remove( ardop_settings.port+1, p_ardop_d)
end

-- Track the settings change
function p_ardop.prefs_changed()
	local must_change_port = ardop_settings.port ~= p_ardop.prefs.portnum
	local must_change_state = ardop_settings.enabled ~= p_ardop.prefs.enabled
	local must_change_decb2f = ardop_settings.decode_b2f ~= p_ardop.prefs.decode_b2f
	local must_reload = must_change_port or must_change_state or must_change_decb2f
	
	-- B2F decoding change
	ardop_settings.decode_b2f = p_ardop.prefs.decode_b2f

	-- Port change
	if ( must_change_port ) then
		-- Disable dissectors if they were previously enabled
		if( ardop_settings.enabled ) then unregDissectors() end

		-- Update preferences
		ardop_settings.port = p_ardop.prefs.portnum
		ardop_settings.enabled = p_ardop.prefs.enabled

		-- Enable back the dissectors if they are enabled
		if( ardop_settings.enabled ) then regDissectors() end
	end

	-- Simple state change
	if( must_change_state and not must_change_port ) then
		ardop_settings.enabled = p_ardop.prefs.enabled

		if( ardop_settings.enabled ) then
			regDissectors()
		else
			unregDissectors()
		end
	end

	-- Reload the capture file
	if (must_reload) then reload() end
end

