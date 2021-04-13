-- wl2k.lua
-- Winlink over TCP Dissector
p_wl2k = Proto ( "WL2K", "Winlink over TCP")

-- Used to read the TCP stream
local f_tcp_stream   = Field.new("tcp.stream")
local original_dissector

-- B2F Stream index
local pf_b2f_stream = ProtoField.string( "b2f.stream", "B2F stream index")

-- Direction info (shim for versions < 3.4.4)
if( P2P_DIR_RECV == nil ) then
	P2P_DIR_UNKNOWN = -1
	P2P_DIR_SENT    =  0
	P2P_DIR_RECV    =  1
end

-- Stream info
local wl2k_stream_infos = {}

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
local wl2k_settings =
{
    enabled      = true, -- whether this dissector is enabled or not
    port         = 8772, -- default TCP port number
    decode_b2f   = true, -- should this dissector interpret the payload as B2F
}


function p_wl2k.dissector ( buffer, pinfo, tree)
	-- Validate packet length
	if ( buffer:len() < 1 ) then return end
	
	-- Set protocol name
	pinfo.cols.protocol = "WL2K"
	
	-- Call the original dissector & check the direction
	pcall( function() original_dissector:call( buffer, pinfo, tree) end )
	local is_s2c = ( pinfo.src_port == wl2k_settings.port )

	local stream_id = f_tcp_stream().value

	-- Update packet direction
	pinfo.cols.direction = fif( is_s2c, P2P_DIR_RECV, P2P_DIR_SENT)

	-- Update the info column
	pinfo.cols.info = "Winlink over TCP"

	if ( wl2k_stream_infos[ stream_id ] == nil ) then
		wl2k_stream_infos[ stream_id ]= {}
		wl2k_stream_infos[ stream_id ]["dndecode"]= {}
		wl2k_stream_infos[ stream_id ]["next_proto"] = false
	end
	
	local subtree = tree:add( p_wl2k, buffer(), "Winlink over TCP")
	local direct_str = "[Direction: " .. fif( is_s2c, "Incoming", "Outgoing") .. "]"
	subtree:add( p_wl2k, buffer(0,0), direct_str)
	
	if( wl2k_stream_infos[ stream_id ]["next_proto"] == false ) then
		-- We've not yet reached the B2 exchange
		if( buffer(0,1):uint() == 0x5B and wl2k_settings.decode_b2f and val_exists( Dissector.list(), "b2f" ) ) then
			-- Following packets are to be decoded as B2
			wl2k_stream_infos[ stream_id ]["next_proto"] = true
			Dissector.get("b2f"):call( buffer, pinfo, tree)
		else
			-- Mark the packet not to be decoded as B2 later
			wl2k_stream_infos[ stream_id ]["dndecode"][pinfo.number] = true
			
			-- Display the info
			local title = fif( is_s2c, "Challenge: \"", "Response: \"") .. buffer():string() .. "\""
			pinfo.cols.info = title
			subtree:add( p_wl2k, buffer(), title)
		end
	else
		-- Initial packets,
		if( wl2k_stream_infos[ stream_id ]["dndecode"][pinfo.number] ~= nil ) then
			-- Display the info
			local title = fif( is_s2c, "Challenge: \"", "Response: \"") .. buffer():string() .. "\""
			pinfo.cols.info = title
			subtree:add( p_wl2k, buffer(), title)
			return
		else
			-- Attempt to invoke the B2F dissector
			if( wl2k_settings.decode_b2f and val_exists( Dissector.list(), "b2f" ) ) then
				Dissector.get("b2f"):call( buffer, pinfo, tree)
			end
		end
	end
end


-------------------------------------------------------------------------------
-- Register settings & dissectors
-------------------------------------------------------------------------------
p_wl2k.prefs.enabled = Pref.bool("Dissector enabled", wl2k_settings.enabled,
                                        "Whether the Winlink over TCP dissector is enabled or not")

p_wl2k.prefs.portnum = Pref.uint("Port Number", wl2k_settings.port,
                                        "The default Winlink over TCP port")

p_wl2k.prefs.decode_b2f = Pref.bool("Decode payload as B2F", wl2k_settings.decode_b2f,
                                        "Whether the dissector should interpret its payload as B2F")
-- Register the dissectors
local function regDissectors()
	DissectorTable.get("tcp.port"):add( wl2k_settings.port, p_wl2k)
end
-- call it now, because we're enabled by default
regDissectors()

-- Unregister the dissectors
local function unregDissectors()
	DissectorTable.get("tcp.port"):remove( wl2k_settings.port, p_wl2k)
end

-- Track the settings change
function p_wl2k.prefs_changed()
	local must_change_port = wl2k_settings.port ~= p_wl2k.prefs.portnum
	local must_change_state = wl2k_settings.enabled ~= p_wl2k.prefs.enabled
	local must_change_decb2f = wl2k_settings.decode_b2f ~= p_wl2k.prefs.decode_b2f
	local must_reload = must_change_port or must_change_state or must_change_decb2f
	
	-- B2F decoding change
	wl2k_settings.decode_b2f = p_wl2k.prefs.decode_b2f

	-- Port change
	if ( must_change_port ) then
		-- Disable dissectors if they were previously enabled
		if( wl2k_settings.enabled ) then unregDissectors() end

		-- Update preferences
		wl2k_settings.port = p_wl2k.prefs.portnum
		wl2k_settings.enabled = p_wl2k.prefs.enabled

		-- Enable back the dissectors if they are enabled
		if( wl2k_settings.enabled ) then regDissectors() end
	end

	-- Simple state change
	if( must_change_state and not must_change_port ) then
		wl2k_settings.enabled = p_wl2k.prefs.enabled

		if( wl2k_settings.enabled ) then
			regDissectors()
		else
			unregDissectors()
		end
	end

	-- Reload the capture file
	if (must_reload) then reload() end
end

