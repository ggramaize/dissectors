-- kiss.lua
-- KISS over TCP Dissector
p_kiss = Proto ( "KISS", "KISS Frames over TCP")

-- Used to read the TCP stream
local f_tcp_stream   = Field.new("tcp.stream")
local original_dissector

-- Direction info (shim for versions < 3.4.4)
if( P2P_DIR_RECV == nil ) then
	P2P_DIR_UNKNOWN = -1
	P2P_DIR_SENT    =  0
	P2P_DIR_RECV    =  1
end

-- Stream info
local kiss_stream_infos = {}

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
local kiss_settings =
{
    enabled      = true, -- whether this dissector is enabled or not
    port         = 8001, -- default TCP port number
    decode_ax25   = true, -- should this dissector interpret the payload as KISS
}

local kiss_commands = {
    [0] = "Data Frame",
    [1] = "Tx Delay",
    [2] = "Persistence",
    [3] = "Slot time",
    [4] = "TX Tail",
    [5] = "Duplex",
    [6] = "Set hardware (vendor specific)"
}

local pf_command      = ProtoField.new( "KISS Command", "kiss.command", ftypes.UINT8, nil, base.DEC)
local pf_command_port = ProtoField.uint8( "kiss.port", "KISS Port", base.DEC, nil, 0xF0)
local pf_command_num  = ProtoField.uint8( "kiss.cmdnum", "KISS Command Number", base.DEC, kiss_commands, 0x0F)

p_kiss.fields = { 
	pf_command, 
	pf_command_port,
	pf_command_num
}


function p_kiss.dissector ( buffer, pinfo, tree)
	-- Validate packet length
	if ( buffer:len() < 1 ) then return end
	
	-- Set protocol name
	pinfo.cols.protocol = "KISS"

	
	-- Call the original dissector & check the direction
	pcall( function() original_dissector:call( buffer, pinfo, tree) end )
	local is_s2c = ( pinfo.src_port == kiss_settings.port )

	local stream_id = f_tcp_stream().value

	-- Update packet direction
	pinfo.cols.direction = fif( is_s2c, P2P_DIR_RECV, P2P_DIR_SENT)

	-- Update the info column
	pinfo.cols.info = "KISS over TCP"

	if ( kiss_stream_infos[ stream_id ] == nil ) then
		kiss_stream_infos[ stream_id ]= {}
		kiss_stream_infos[ stream_id ]["dndecode"]= {}
		kiss_stream_infos[ stream_id ]["next_proto"] = false
	end
	
	local subtree = tree:add( p_kiss, buffer(), "KISS over TCP")
	local direct_str = "[Direction: " .. fif( is_s2c, "Incoming", "Outgoing") .. "]"
	subtree:add( p_kiss, buffer(0,0), direct_str)
	
	local head = buffer(0,1):uint()
	local pk_type = buffer(1,1):uint()
	local pk_cmd = bit.band( pk_type, 0x0F)
	local tail = buffer(buffer:len()-1,1):uint()
	
	if( head == 0xC0 and tail == 0xC0 ) then
		subtree:add( p_kiss, buffer(0,1), "Packet head")
		
		if( pk_type == 0xFF ) then
			subtree:add( p_kiss, buffer(0,1), "KISS Command: exit KISS mode (255)")
		else
			local cmd_tree = subtree:add( pf_command, buffer:range(1,1))
			cmd_tree:add( pf_command_port, buffer:range(1,1))
			cmd_tree:add( pf_command_num, buffer:range(1,1))
			if( pk_cmd == 0x01 or pk_cmd == 0x03 or pk_cmd == 0x04 ) then
				subtree:add( p_kiss, buffer(2,1), "Value: " .. buffer(2,1):uint()*10 .. " ms")
				pinfo.cols.info = "KISS, set " .. kiss_commands[bit.band(pk_type,0x0F)] .. " to " .. buffer(2,1):uint()*10 .. " ms."
				
			elseif( pk_cmd == 0x02 ) then
				subtree:add( p_kiss, buffer(2,1), "Value: " .. buffer(2,1):uint()*256-1 ) 
				pinfo.cols.info = "KISS, set " .. kiss_commands[bit.band(pk_type,0x0F)] .. " to " .. buffer(2,1):uint()*256-1
				
			elseif( pk_cmd == 0x05 ) then
				subtree:add( p_kiss, buffer(2,1), "Duplex: " .. fif( buffer(2,1):uint() == 1, "Full", "Half") ) 
				pinfo.cols.info = "KISS, set " .. fif( buffer(2,1):uint() == 1, "Full", "Half") .. " Duplex"
				
			elseif( pk_cmd == 0x00 ) then

				subtree:add( p_kiss, buffer(2,buffer:len()-3), "KISS Payload " .. buffer:len()-3 .. " byte(s)" )
				if( kiss_settings.decode_ax25 and val_exists( Dissector.list(), "ax25" ) ) then
					Dissector.get("ax25"):call( buffer(2,buffer:len()-3):tvb(), pinfo, tree)
				end
				
			elseif( pk_cmd == 0x06 ) then
				pinfo.cols.info = "KISS, vendor specific command"
				subtree:add_expert_info( PI_PROTOCOL, PI_INFO, "Vendor specific, undecoded")
				
			else
				subtree:add_expert_info( PI_PROTOCOL, PI_WARN, "Undocumented command")
			end
		end
		subtree:add( p_kiss, buffer(buffer:len()-1,1), "Packet tail")
	end
end


-------------------------------------------------------------------------------
-- Register settings & dissectors
-------------------------------------------------------------------------------
p_kiss.prefs.enabled = Pref.bool("Dissector enabled", kiss_settings.enabled,
                                        "Whether the KISS over TCP dissector is enabled or not")

p_kiss.prefs.portnum = Pref.uint("Port Number", kiss_settings.port,
                                        "The default Winlink over TCP port")

p_kiss.prefs.decode_ax25 = Pref.bool("Decode payload as AX.25", kiss_settings.decode_ax25,
                                        "Whether the dissector should interpret its payload as AX.25")
-- Register the dissectors
local function regDissectors()
	DissectorTable.get("tcp.port"):add( kiss_settings.port, p_kiss)
end
-- call it now, because we're enabled by default
regDissectors()

-- Unregister the dissectors
local function unregDissectors()
	DissectorTable.get("tcp.port"):remove( kiss_settings.port, p_kiss)
end

-- Track the settings change
function p_kiss.prefs_changed()
	local must_change_port = kiss_settings.port ~= p_kiss.prefs.portnum
	local must_change_state = kiss_settings.enabled ~= p_kiss.prefs.enabled
	local must_change_decax25 = kiss_settings.decode_ax25 ~= p_kiss.prefs.decode_ax25
	local must_reload = must_change_port or must_change_state or must_change_decax25
	
	-- B2F decoding change
	kiss_settings.decode_ax25 = p_kiss.prefs.decode_ax25

	-- Port change
	if ( must_change_port ) then
		-- Disable dissectors if they were previously enabled
		if( kiss_settings.enabled ) then unregDissectors() end

		-- Update preferences
		kiss_settings.port = p_kiss.prefs.portnum
		kiss_settings.enabled = p_kiss.prefs.enabled

		-- Enable back the dissectors if they are enabled
		if( kiss_settings.enabled ) then regDissectors() end
	end

	-- Simple state change
	if( must_change_state and not must_change_port ) then
		kiss_settings.enabled = p_kiss.prefs.enabled

		if( kiss_settings.enabled ) then
			regDissectors()
		else
			unregDissectors()
		end
	end

	-- Reload the capture file
	if (must_reload) then reload() end
end

