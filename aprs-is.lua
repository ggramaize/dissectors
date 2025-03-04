-- aprs-is.lua - APRS Internet Service

-- Some module-specific constants
local proto_colname = "APRS-IS"
local proto_shortname = "aprsis"
local proto_fullname  = "APRS Internet Service"
local proto_default_port = 14580

-- Protocol Definition
p_aprsis = Proto ( proto_shortname, proto_fullname)

-- Direction info (shim for versions < 3.4.4)
if( P2P_DIR_RECV == nil ) then
	P2P_DIR_UNKNOWN = -1
	P2P_DIR_SENT    =  0
	P2P_DIR_RECV    =  1
end

local aprsis_srv_qconst = {
    ["qAC"]= "Verified login via bidirectional port",
    ["qAX"]= "Unverified login.",
    ["qAU"]= "Direct via UDP.",
    ["qAo"]= "Gated packet via client-only port.",
    ["qAO"]= "Non-gated packet via send-only port or indirect packet via client-only port.",
    ["qAS"]= "Packet via server without q construct.",
    ["qAr"]= "Gated packet using ,I construct from remote IGate.",
    ["qAR"]= "Gated packet using ,I construct with verified IGate login.",
}

local aprsis_clt_qconst = {
    ["qAR"]= "Gated packet from RF.",
    ["qAO"]= "Gated packet from RF without messaging.",
    ["qAZ"]= "Server-client command packet.",
    ["qAI"]= "Trace packet.",
}

local p_aprsis_aprs_types = {
	[0x1c]=1, [0x1d]=1, [0x21]=1, [0x23]=1, [0x24]=1, [0x25]=1, [0x27]=1, [0x28]=1,
	[0x29]=1, [0x2a]=1, [0x2b]=1, [0x2c]=1, [0x2d]=1, [0x2e]=1, [0x2f]=1, [0x3a]=1, 
	[0x3b]=1, [0x3c]=1, [0x3d]=1, [0x3e]=1, [0x3f]=1, [0x40]=1, [0x54]=1, [0x5b]=1, 
	[0x5c]=1, [0x5d]=1, [0x5e]=1, [0x5f]=1, [0x60]=1, [0x7b]=1, [0x7d]=1,
}
-------------------------------------------------------------------------------
-- Common utilities
-------------------------------------------------------------------------------
-- Ternary operator
local function fif(condition, if_true, if_false)
	if condition then return if_true else return if_false end
end

-- Find the next character
local function find_next( buffer, val, skip)
	local len = buffer:len()
	if ( skip == nil ) then skip = 0 end
	for i=skip , len-1 , 1 do
		if( buffer(i,1):uint() == val ) then return i end 
	end
	return len
end

local function find_header_commas( buffer, aprs_sep)
	local commas = {}
	local i = 0
	commas["count"] = 0
	while( i < aprs_sep ) do
		if ( buffer( i, 1):string() == "," ) then
			commas[commas["count"]] = i
			commas["count"] = commas["count"]  + 1
		end
		i = i + 1
	end
	
	return commas
end

local function tokenize_login( buffer)
	local spaces = {}	
	spaces["count"] = 0
	
	local i = 2
	while( i < buffer():len() ) do
		if ( buffer( i, 1):string() == " " ) then
			spaces[spaces["count"]] = i
			spaces["count"] = spaces["count"] + 1
		end
		i = i + 1
	end

	local tokens = {}
	tokens["count"] = 0
	
	if ( spaces["count"] < 1 ) then return tokens end
	
	i = 0
	while ( i < spaces["count"] ) do
		if ( i ~= 0 ) then
			tokens[tokens["count"]] = buffer( spaces[i-1]+1	,  spaces[i]-spaces[i-1]-1)
		else
			tokens[tokens["count"]] = buffer( 2, spaces[i]-2)
		end
		tokens["count"] = tokens["count"] + 1
		i = i + 1
	end
	tokens[tokens["count"]] = buffer( spaces[spaces["count"]-1]+1,  buffer():len()-spaces[spaces["count"]-1]-1)
	tokens["count"] = tokens["count"] + 1

	return tokens, spaces
end

local function tokenize_extras( buffer, commas, aprs_sep)
	local tokens = {}
	tokens["count"] = 0
	
	if ( commas == nil or commas["count"] == nil or commas["count"] < 1 ) then return tokens end
	
	i = 1
	while ( i < commas["count"] ) do
		tokens[tokens["count"]] = buffer( commas[i-1]+1	,  commas[i]-commas[i-1]-1)
		tokens["count"] = tokens["count"] + 1
		i = i + 1
	end
	tokens[tokens["count"]] = buffer( commas[commas["count"]-1]+1	,  aprs_sep-commas[commas["count"]-1]-1)
	tokens["count"] = tokens["count"] + 1

	return tokens
end

local function find_qconstruct( tokens)
	if ( tokens == nil or tokens["count"] == nil or tokens["count"] == 0 ) then return nil end
	
	local i = 0
	while ( i < tokens["count"] ) do
		if ( tokens[i]:len() == 3 and tokens[i](0,1):string() == "q" ) then return i end
		i = i + 1
	end
	
	return nil
end

-- Decode the Q Construct into a human-readable format
local function decode_qconstruct( qconst, is_s2c)
	if ( qconst == nil or qconst == "" ) then return "(not found)" end
	
	if ( is_s2c == true and aprsis_srv_qconst[ qconst] ~= nil ) then
		return aprsis_srv_qconst[ qconst]
	
	elseif ( is_s2c == false and aprsis_clt_qconst[ qconst] ~= nil ) then
		return aprsis_clt_qconst[ qconst]
	end
	
	return "Unknown Q Construct"
end

function p_aprsis.dissector( buffer, pinfo, tree)
	local len = buffer():len()
	local is_s2c = ( pinfo.src_port == proto_default_port )

	-- Update packet direction
	pinfo.cols.direction = fif( is_s2c, P2P_DIR_RECV, P2P_DIR_SENT)
	
	-- Set protocol name
	pinfo.cols.protocol = proto_colname
	
	local subtree = tree:add( p_aprsis, buffer(), proto_fullname)
	
	if( is_s2c == true and buffer( 0, 10):string() == "# logresp " ) then
		-- Login response
		pinfo.cols.info = "Login Result: "
		local login_args
		local login_spaces
		login_args, login_spaces = tokenize_login( buffer)
		local authres = login_args[2]:string():gsub(",", "")
		pinfo.cols.info:append( fif( authres == "verified", "Success", "Failure") )
		
		subtree:add( p_aprsis, login_args[1], "Username: " .. login_args[1]:string())
		subtree:add( p_aprsis, login_args[2]( 0, login_args[2]:len()), "Auth Result: " .. fif( authres == "verified", "Success", "Failure"))
		subtree:add( p_aprsis, login_args[4], "Server: " .. login_args[4]:string():gsub("\r", ""):gsub("\n", ""))
		pinfo.cols.info:append( ", User: " .. login_args[1]:string() .. ", Server:" .. login_args[4]:string():gsub("\r", ""):gsub("\n", ""))
		
	elseif( buffer( 0, 2):string() == "# " ) then
		-- Comment
		local description = "Comment: " .. buffer( 2):string():gsub("\r", ""):gsub("\n", "")
		subtree:add( p_aprsis, buffer( 2), description )
		pinfo.cols.info = description
			
	elseif( buffer( 0, 1):string() == "#" ) then
		-- Comment
		local description = "Comment: " .. buffer( 1):string():gsub("\r", ""):gsub("\n", "")
		subtree:add( p_aprsis, buffer( 1),  description) 
		pinfo.cols.info = description
		
	elseif ( is_s2c == false and buffer( 0, 5):string() == "user " ) then
		-- Login request
		local login_args
		local login_spaces
		login_args, login_spaces = tokenize_login( buffer)
		pinfo.cols.info = "Login Request"
		
		subtree:add( p_aprsis, login_args[1], "Username: " .. login_args[1]:string())
		pinfo.cols.info:append( " (User: " .. login_args[1]:string())
		subtree:add( p_aprsis, login_args[3], "Password: " .. fif( login_args[3]:string() ~= "-1" or login_args[3]:string() == "-1\r\n", login_args[3]:string(), "[No password, Rx only]"))
		if ( login_args[3]:string() == "-1" or login_args[3]:string() == "-1\r\n" ) then
			pinfo.cols.info:append( ", Rx Only")
		end

		local cmd_offset = 0
		if ( login_args[4]:string() == "vers" ) then
			subtree:add( p_aprsis, login_args[5], "Software name: " .. login_args[5]:string()) 
			subtree:add( p_aprsis, login_args[6], "Software version: " .. login_args[6]:string():gsub("\r", ""):gsub("\n", "")) 
			cmd_offset = 3
		end
		
		if ( login_args[4+cmd_offset]:string() == "UDP" ) then
			subtree:add( p_aprsis, login_args[5+cmd_offset], "UDP Port: " .. login_args[5+cmd_offset]:string():gsub("\r", ""):gsub("\n", ""))
			pinfo.cols.info:append( ", UDP port: " .. login_args[5+cmd_offset]:string():gsub("\r", ""):gsub("\n", ""))
			cmd_offset = cmd_offset + 2
		end
		
		if ( 4+cmd_offset < login_args["count"] ) then
			local filter = buffer(login_spaces[4+cmd_offset], len-login_spaces[4+cmd_offset]-2)
			pinfo.cols.info:append( ", Rx filter set")
			subtree:add( p_aprsis, filter, "Requested filter: " .. filter:string():gsub("\r", ""):gsub("\n", "")) 
		end
		
		pinfo.cols.info:append( ")")
	else
		local pf_src = ProtoField.new("Source Address", "aprsis.src", ftypes.STRING)
		-- TNC2 Data
		local src_sep = find_next( buffer, 0x3E, 0)
		local aprs_sep = find_next( buffer, 0x3A, 0)
		
		if ( aprs_sep == nil ) then
			subtree:add_expert_info( PI_DISSECTOR_BUG, PI_ERROR, "Didn't find field separator")
			return	
		end
		
		local commas = find_header_commas( buffer, aprs_sep)
		
		local source = buffer( 0, src_sep)
		local destination = buffer( src_sep+1, commas[0]-src_sep-1)
		local tokens = tokenize_extras( buffer, commas, aprs_sep)
		local qconst_idx = find_qconstruct( tokens)
		
		pinfo.cols.src = source:string()
		pinfo.cols.dl_src = source:string()
		pinfo.cols.dst = destination:string()
		pinfo.cols.dl_dst = destination:string()
		
		subtree:add( p_aprsis, source, "Source Address: " .. source:string())
		subtree:add( p_aprsis, destination, "Destination Address: " .. destination:string())
		
		local i = 0		
		if ( qconst_idx ~= nil ) then
			-- Print paths
			i = 0
			if ( qconst_idx > 0 ) then
				while ( i < qconst_idx ) do
					subtree:add( p_aprsis, tokens[i], "Path " .. i+1 .. ": " .. tokens[i]:string() )
					i = i + 1
				end
			end
		
			local q_const = tokens[ qconst_idx]
			subtree:add( p_aprsis, q_const, "Q Construct: " .. decode_qconstruct( q_const:string(), is_s2c) )
			
			-- Print vias
			if ( qconst_idx+1 < tokens["count"] ) then
				i=qconst_idx+1
				while ( i < tokens["count"] ) do
					subtree:add( p_aprsis, tokens[i], fif( i == qconst_idx+1, "Via: ", "Via " .. i+1 .. ": ") .. tokens[i]:string() )
					i = i + 1
				end
			end
		else
			for i=0, tokens["count"]-1, 1 do
				subtree:add( p_aprsis, tokens[i], "Path " .. i+1 .. ": " .. tokens[i]:string() )
			end
		end
		
		-- Check if valid APRS Packet
		if ( p_aprsis_aprs_types[ buffer( aprs_sep+1,1):uint()] ~= nil ) then
			-- Dissect APRS Packet
			Dissector.get("aprs"):call( buffer( aprs_sep+1):tvb(), pinfo, tree)

			-- Prepend source and destination Addresses
			pinfo.cols.info:prepend("Src: " .. string.format( "%09s", source:string()) .. " Dst: " .. string.format( "%09s", destination:string()) .. " - ")
		else
			pinfo.cols.info = "Src: " .. string.format( "%09s", source:string()) .. " Dst: " .. string.format( "%09s", destination:string()) .. " - [Malformed APRS Packet]"
			local errtree = tree:add( p_aprsis, buffer( aprs_sep+1), "[Malformed APRS Packet]")
			errtree:add_expert_info( PI_MALFORMED, PI_ERROR, "Invalid APRS Packet Format")
		end
		

	end
end

-- Register port
DissectorTable.get("tcp.port"):add( proto_default_port, p_aprsis)
