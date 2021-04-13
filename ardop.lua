-- ardop.lua

-- ARDOP Dissectors
p_ardop = Proto ( "ARDOP", "ARDOP Interface")
p_ardop_c = Proto ( "ARDOP_C", "ARDOP Control Plane")
p_ardop_d = Proto ( "ARDOP_D", "ARDOP Data Plane")

-- Used to read the TCP source port
local f_tcp_srcport    = Field.new("tcp.srcport")
local original_dissector

-- Direction info (shim for versions < 3.4.4)
if( P2P_DIR_RECV == nil ) then
	P2P_DIR_UNKNOWN = -1
	P2P_DIR_SENT    =  0
	P2P_DIR_RECV    =  1
end

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
-- Fields
-------------------------------------------------------------------------------
local pf_b2f_stream = ProtoField.string( "b2f.stream", "B2F stream index")
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
	local pkt_len = buffer:len()
	-- Validate packet length
	if ( pkt_len < 1 ) then return end

	-- Set protocol name
	pinfo.cols.protocol = "ARDOP_C"

	-- Call the original dissector & check the direction
	pcall( function() original_dissector:call( buffer, pinfo, tree) end )
	local is_dce_to_dte = ( pinfo.src_port == ardop_settings.port )

	-- Update packet direction
	pinfo.cols.direction = fif( is_dce_to_dte, P2P_DIR_RECV, P2P_DIR_SENT)

	local subtree = tree:add( p_ardop_c, buffer())
	subtree:add( p_ardop_c, buffer(0,0), "[Direction: " .. fif( is_dce_to_dte, "DCE to DTE", "DTE to DCE")  .. "]")

	local data = buffer( 0, pkt_len-1)
	
	if ( is_dce_to_dte == true and pkt_len > 8 and buffer(0,4):string() == "PTT " ) then
		-- PTT event
		local ptt_status = "Status: Transceiver now " .. fif( buffer(4,4):string() == "TRUE", "transmitting", "receiving")
		subtree:add( p_ardop_c, data, ptt_status)
		pinfo.cols.info = ptt_status

	elseif ( pkt_len > 7 and buffer(0,7):string() == "VERSION" ) then
		-- Version
		local ver_status
		if ( is_dce_to_dte ) then
			if ( pkt_len > 8 ) then
				ver_status = "TNC Version: " .. buffer( 8, pkt_len-9):string()
				subtree:add( p_ardop_c, data, ver_status)
				pinfo.cols.info = ver_status
			else
				subtree:add( p_ardop_c, data, "TNC Version (malformed)")
				subtree:add_expert_info( PI_PROTOCOL, PI_ERROR, "Malformed field")
			end
		else
			ver_status = "TNC Version query"
			subtree:add( p_ardop_c, data, ver_status)
			pinfo.cols.info = ver_status
		end

	elseif ( pkt_len > 11 and buffer(0,7):string() == "LISTEN " ) then
		local list_status
		if ( is_dce_to_dte ) then
			list_status = ( pkt_len > 15 and buffer(11,4):string():lower() == "true" )
			list_status = "Status: " .. fif( list_status, "Listening", "Not listening") .. " to incoming connections"
		else
			list_status = ( pkt_len > 10 and buffer(7,4):string():lower() == "true" )
			list_status = "Query: " .. fif( list_status, "Listen", "Don't listen") .. " incoming connections"
		end
		subtree:add( p_ardop_c, data, list_status)
		pinfo.cols.info = list_status
		
	elseif ( pkt_len > 8 and buffer(0,7):string() == "BUFFER " ) then
		local buf_status
		local rx_buf_bytes = tonumber(buffer(7,pkt_len-8):string())
		if ( is_dce_to_dte ) then
			buf_status = "Status: " .. rx_buf_bytes .. " byte(s) currently in TNC's Rx buffer"
			subtree:add( p_ardop_c, data, buf_status)
			pinfo.cols.info = buf_status
		end	

	-- STATE
	elseif ( pkt_len > 5 and buffer(0,5):string() == "STATE" ) then
		local mdmstate_status

		if ( is_dce_to_dte) then
			-- STATE *_
			if( pkt_len > 7 ) then
				local modem_state = buffer(6,pkt_len-7):string()
				mdmstate_status = "Status: Modem internal state is " .. modem_state
				subtree:add( p_ardop_c, data, mdmstate_status)
				pinfo.cols.info = mdmstate_status
			else
				local mdm_tree = subtree:add( p_ardop_c, data, "Modem state")
				mdm_tree:add_expert_info( PI_PROTOCOL, PI_ERROR, "Malformed field")
			end
		else
			mdmstate_status = "Query: Get modem current internal status"
			subtree:add( p_ardop_c, data, mdmstate_status)
			pinfo.cols.info = mdmstate_status
		end

	-- NEWSTATE
	elseif ( pkt_len > 10 and buffer(0,9):string() == "NEWSTATE " ) then
		local mdmstate_status
		local modem_state = buffer(9,pkt_len-10):string()
		if ( is_dce_to_dte ) then
			mdmstate_status = "Status: Modem internal state transitioned to " .. modem_state
			subtree:add( p_ardop_c, data, mdmstate_status)
			pinfo.cols.info = mdmstate_status
		end

	-- MYCALL
	elseif ( pkt_len > 6 and buffer(0,6):string() == "MYCALL" ) then
		local csgn_status
		if ( is_dce_to_dte ) then
			if( pkt_len > 12 and buffer(7,4):string() == "now ") then
				csgn_status = "Status: My callsign set to \"" .. buffer( 11, pkt_len-12):string() .. "\""
			else
				csgn_status = "Status: My callsign is \"" .. buffer( 7, pkt_len-8):string() .. "\""
			end
		else
			-- MYCALL xxxx
			if( pkt_len > 8) then
				csgn_status = "Query: Change my callsign to \"" .. buffer( 7, pkt_len-8):string() .. "\""
			else
				csgn_status = "Query: Request my current callsign"
			end
		end

		subtree:add( p_ardop_c, data, csgn_status)
		pinfo.cols.info = csgn_status

	-- INPUTPEAKS X Y_
	elseif ( pkt_len > 14 and buffer(0,11):string() == "INPUTPEAKS " ) then
		if ( is_dce_to_dte ) then
			local peaks_status, separator=11
			for i=11, pkt_len-1, 1 do
				if( buffer(i,1):string() == " " ) then
					separator = i
					break
				end
			end

			if ( separator ~= 11 and separator ~= pkt_len-1 ) then
				local lower_peak = buffer( 11, separator-11)
				local upper_peak = buffer( separator+1, pkt_len-separator-1)
				peaks_status = "Diag: Modem samples between " .. lower_peak:string() .. " and " .. upper_peak:string()
				local pk_subtr = subtree:add( p_ardop_c, data, "Modem peaks")
				pk_subtr:add( p_ardop_c, lower_peak, "Lower peak: " .. lower_peak:string())
				pk_subtr:add( p_ardop_c, upper_peak, "Upper peak: " .. upper_peak:string())
				pinfo.cols.info = peaks_status
			else
				local in_subtr = subtree:add( p_ardop_c, data, "Modem peaks (malformed)")
				in_subtr:add_expert_info( PI_PROTOCOL, PI_ERROR, "Malformed field")
			end
		end

	-- DISCONNECT
	elseif ( pkt_len > 10 and buffer(0,10):string() == "DISCONNECT" ) then
		local disc_status
		if ( is_dce_to_dte ) then
			if( pkt_len > 12 and buffer(0,12):string() == "DISCONNECTED" ) then
				disc_status = "Status: Current connection terminated"
			else
				disc_status = "Status: Acknowledged connection termination query"
			end
		else
			disc_status = "Query: Terminate current connection"
		end
		
		subtree:add( p_ardop_c, data, disc_status)
		pinfo.cols.info = disc_status

	-- BUSY
	elseif ( pkt_len > 9 and buffer(0,5):string() == "BUSY " ) then
		local chan_status
		if ( is_dce_to_dte ) then
			chan_status = "Status: RF Channel is currently " .. fif( buffer(5,pkt_len-6):string():upper() == "TRUE", "busy", "available")
			subtree:add( p_ardop_c, data, chan_status)
			pinfo.cols.info = chan_status
		end

	-- STATUS
	elseif ( pkt_len > 8 and buffer(0,7):string() == "STATUS " ) then
		if ( is_dce_to_dte ) then
			local ftxt_status = "Full text status"
			local arg = buffer( 7, pkt_len-8)
			local ftxt_subtree = subtree:add( p_ardop_c, data, ftxt_status)
			ftxt_subtree:add( p_ardop_c, arg, "Status: " .. arg:string())
			pinfo.cols.info = ftxt_status .. ": " .. arg:string()
		end
	end
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

	-- Update packet direction
	pinfo.cols.direction = fif( is_dce_to_dte, P2P_DIR_RECV, P2P_DIR_SENT)

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

	local direct_str = "[Direction: " .. fif( is_dce_to_dte, "Incoming", "Outgoing") .. "]"
	subtree:add( buffer(0,0), direct_str)

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

