-- agwpe.lua
-- AGWPE protocol
-- Spec reference: docs/agwpe-api.htm

p_agwpe = Proto ( "agwpe", "AGWPE Protocol")

local settings = 
{
	enabled = true,
	port = 8000,
	max_len = 1024
}

--- [ Dissector helper functions ] ---

-- Convert the datakind field into the matching packet name in the DTE->DCE direction
local function agw_get_tx_dkind_name ( datakind)
	if( datakind == 0x50 ) then return "Application login request" end -- 'P'
	if( datakind == 0x58 ) then return "Register callsign" end -- 'X'
	if( datakind == 0x78 ) then return "Unregister callsign" end -- 'x'
	if( datakind == 0x47 ) then return "Request port information" end -- 'G'
	if( datakind == 0x6D ) then return "Enable reception of monitoring frames" end -- 'm'
	if( datakind == 0x52 ) then return "AGWPE Version Info" end -- 'R'
	if( datakind == 0x67 ) then return "Request port capabilities" end -- 'g'
	if( datakind == 0x48 ) then return "Request heard callsign list" end -- 'H'
	if( datakind == 0x79 ) then return "Request number of frames waiting on a port" end -- 'y'
	if( datakind == 0x59 ) then return "Request number of frames waiting on a connection" end -- 'Y'
	if( datakind == 0x4D ) then return "UI Frame" end -- 'M'
	if( datakind == 0x43 ) then return "Initiate direct AX.25 connection" end -- 'C'
	if( datakind == 0x44 ) then return "Connected data" end -- 'D'
	if( datakind == 0x64 ) then return "Terminate AX.25 connection" end -- 'd'
	if( datakind == 0x76 ) then return "Initate digipeated AX.25 connection" end -- 'v'
	if( datakind == 0x56 ) then return "UI Frame (digipeated)" end -- 'V'
	if( datakind == 0x63 ) then return "Non-standard AX.25 connection (custom PID)" end -- 'c'
	if( datakind == 0x4B ) then return "Raw data frame" end -- 'K'
	if( datakind == 0x6B ) then return "Enable reception in raw format" end -- 'k'
	return "Undocumented"
end

-- Convert the datakind field into the matching packet name in the DCE->DTE direction
local function agw_get_rx_dkind_name ( datakind)
	if( datakind == 0x52 ) then return "Version" end -- 'R'
	if( datakind == 0x58 ) then return "Callsign registration" end -- 'X'
	if( datakind == 0x47 ) then return "Port Information" end -- 'G'
	if( datakind == 0x67 ) then return "Port Capabilities" end -- 'g'
	if( datakind == 0x79 ) then return "Outstanding frames on a port" end -- 'y'
	if( datakind == 0x59 ) then return "Outstanding frames on a connection" end -- 'Y'
	if( datakind == 0x48 ) then return "Head stations list" end -- 'H'
	if( datakind == 0x43 ) then return "AX.25 Connection Request" end -- 'C'
	if( datakind == 0x44 ) then return "Connected Data" end -- 'D'
	if( datakind == 0x49 ) then return "Monitored I frame" end -- 'I'
	if( datakind == 0x53 ) then return "Monitored S frame" end -- 'S'
	if( datakind == 0x55 ) then return "Monitored UI frame" end -- 'U'
	if( datakind == 0x54 ) then return "Monitoring own information" end -- 'T'
	if( datakind == 0x4B ) then return "Monitored Raw frame" end -- 'K'
	return "Undocumented"
end

-- Safely extract a sometimes-not-null terminated string from a TVB
local function agw_get_string( buffer)
	local first_null_pos = -1
	local length = buffer:len()
	for i=0,length-1,1 do
		if( buffer:bytes():get_index(i) == 0 ) then
			first_null_pos = i
			break
		end
	end 

	if( first_null_pos == -1 ) then
		return buffer(0):string()
	end
	return buffer(0):stringz()
end

-- Is a packet from, or to the DTE
local function is_dte_to_dce ( pinfo)
	return pinfo.dst_port == settings.port
end

--- [ Protocol dissector ] ---
function p_agwpe.dissector ( buffer, pinfo, tree)
	-- Validate minimal packet length
	if ( buffer:len() < 36 ) then return end

	-- Set protocol name
	pinfo.cols.protocol = "AGWPE"

	-- Variables
	local agw_port     = buffer(0,1):uint()
        local agw_rsv1     = buffer(1,3)
	local agw_datakind = buffer(4,1):uint()
	local agw_rsv2     = buffer(5,1)
	local agw_pid      = buffer(6,1):uint()
	local agw_rsv3     = buffer(7,1)
	local agw_callfrom = agw_get_string( buffer(8,10):tvb())
	local agw_callto   = agw_get_string( buffer(18,10):tvb())
	local agw_datalen  = buffer(28,4):le_uint()
	local agw_userrsv  = buffer(32,4):uint()

	-- Subtree title
	local subtree_title = "AGWPE Protocol, Src: \"" .. agw_callfrom .. "\", Dst: \"" .. agw_callto .. "\", PID:" .. agw_pid

	-- Subtree
	local subtree = tree:add( p_agwpe, buffer(), subtree_title)
	subtree:add( buffer( 0, 1), "Engine Port: " .. agw_port)
	subtree:add( buffer( 1, 3), "Reserved")
	subtree:add( buffer( 4, 1), "DataKind: ".. agw_get_tx_dkind_name(agw_datakind))
	subtree:add( buffer( 5, 1), "Reserved")
	subtree:add( buffer( 6, 1), "PID: " .. agw_pid)
	subtree:add( buffer( 7, 1), "Reserved")
	subtree:add( buffer( 8,10), "Call From: \"" .. agw_callfrom .. "\"")
	subtree:add( buffer(18,10), "Call To: \"" .. agw_callto .. "\"")
	subtree:add_le( buffer(28, 4), "Data length: ".. agw_datalen)
	if( agw_datalen ~= 0 ) then
		-- The packet has a payload
		--subtree:add( buffer(32, 4), "User (4 bytes)")
		--subtree:add( buffer(36), "Payload (" .. agw_datalen .. " bytes)")
		if( agw_datakind == 0x4B ) then
			-- The packet has a payload
			subtree:add( buffer(32, 4), "User (4 bytes)")
			subtree:add( buffer(36), "Payload (" .. agw_datalen .. " bytes)")
			-- Raw data frame, both DTE and DCE initiated
			-- KISS port identification
			-- subtree:add( buffer(36,1), "")

			-- We set the dissector to skip the first byte, which isn't the standard
			-- 0x7E flag
			Dissector.get("ax25"):call( buffer(37, buffer:len()-37):tvb(), pinfo, tree)
		end

		if( agw_datakind == 0x50 and is_dte_to_dce( pinfo) ) then
			-- Application Login
			if( buffer(32):len() == agw_datalen+4 ) then
				-- Non-compliant implementation
				local subtree_applogpad = subtree:add( buffer(32, 4), "Unexpected padding (4 bytes)")
				subtree_applogpad:add_expert_info( PI_PROTOCOL, PI_WARN, "The User field is 255 bytes zero-padded string for an application login request.")

				subtree:add( buffer(36, 255), "Username: "..agw_get_string( buffer(36, 255):tvb()))
				subtree:add( buffer(291, 255), "Password: "..agw_get_string( buffer(291, 255):tvb()))
				subtree:add_expert_info( PI_PROTOCOL, PI_WARN, "Non-standard implementation of application login")
				
			else
				subtree:add( buffer(32, 255), "Username: "..agw_get_string( buffer(32, 255):tvb()))
				subtree:add( buffer(287, 255), "Password: "..agw_get_string( buffer(287, 255):tvb()))
			end
		end
			
			
		
	else
		-- The packet doesn't have a payload
		subtree:add( buffer(32, 4), "User (4 bytes)")
	end
	
end

--- Dissector enable/disable functions
local function enableDissector()
	DissectorTable.get("tcp.port"):add( settings.port, p_agwpe)
end

local function disableDissector()
	DissectorTable.get("tcp.port"):remove( settings.port, p_agwpe) 
end

--- Initial dissector register
enableDissector()

--- Preferences handler
p_agwpe.prefs.enabled = Pref.bool( "Dissector enabled", settings.enabled,
				   "Whether the AGWPE dissector is enabled or not")

p_agwpe.prefs.port     = Pref.uint( "Dissector port", settings.port,
				   "Which TCP port the dissector will trigger on")

function p_agwpe.prefs_changed()
	settings.port = p_agwpe.prefs.port
	if settings.enabled ~= p_agwpe.prefs.enabled then
		settings.enabled = p_agwpe.prefs.enabled
		if settings.enabled then
			enableDissector()
		else
			disableDissector()
		end
		-- Reload the capture file
		reload()
	end
end

