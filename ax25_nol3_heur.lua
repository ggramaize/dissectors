-- ax25_nol3_heur.lua - Heuristic services for AX.25 No Layer 3

-- Some module-specific constants
local proto_shortname = "ax25_nol3_heur"
local proto_fullname  = "AX.25 No Layer 3"

-- Protocol Definition
p_ax25_nol3_heur = Proto ( proto_shortname, proto_fullname)

local f_ax25_ctl = Field.new("ax25.ctl")

local p_ax25_nol3_heur_aprs_types = {
	[0x1c]=1, [0x1d]=1, [0x21]=1, [0x23]=1, [0x24]=1, [0x25]=1, [0x27]=1, [0x28]=1,
	[0x29]=1, [0x2a]=1, [0x2b]=1, [0x2c]=1, [0x2d]=1, [0x2e]=1, [0x2f]=1, [0x3a]=1, 
	[0x3b]=1, [0x3c]=1, [0x3d]=1, [0x3e]=1, [0x3f]=1, [0x40]=1, [0x54]=1, [0x5b]=1, 
	[0x5c]=1, [0x5d]=1, [0x5e]=1, [0x5f]=1, [0x60]=1, [0x7b]=1, [0x7d]=1,
}

local function p_ax25_nol3_heur_is_aprs(buffer, pinfo, tree)
    -- Guard for length
    local length = buffer:len()
    if length < 6 then return false end
    
    -- Only for UI Frames
    local fi_ax25_ctl = f_ax25_ctl()
    if ( fi_ax25_ctl.value == nil or bit.band( fi_ax25_ctl.value, 0xEF) ~= 0x03 ) then return false end

	-- Only for supported types
    if ( p_ax25_nol3_heur_aprs_types[ buffer(0,1):uint() ] ~= nil ) then
        return true
	end
	
    return false 
end

-- Dissector
function p_ax25_nol3_heur.dissector(buffer, pinfo, tree)
	local length = buffer:len()
    
	tree:add( p_ax25_nol3_heur, buffer())
	
    -- Only invoke APRS dissector for UI frames
    if ( p_ax25_nol3_heur_is_aprs(buffer, pinfo, tree) ) then 
    	Dissector.get("aprs"):call( buffer, pinfo, tree)
    	return 0
    end
end

-- Register for PID 0xF0
DissectorTable.get("ax25.pid"):add( 0xF0, p_ax25_nol3_heur)
