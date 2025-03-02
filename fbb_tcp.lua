-- fbb_tcp.lua - F6FBB Forwarding Protocol

-- Some module-specific constants
local proto_shortname = "FBB"
local proto_fullname  = "FBB over TCP"

-- Protocol Definition
p_fbb_tcp = Proto ( proto_shortname, proto_fullname)

-- Used to read the TCP stream
local f_tcp_stream = Field.new("tcp.stream")
local original_dissector

-- Frame number
local f_fnum       = Field.new("frame.number")

-- TCP Stream index
--local pf_fbb_tcp_stream = ProtoField.string( "fbb.stream", "FBB stream index")

-- Direction info (shim for versions < 3.4.4)
if( P2P_DIR_RECV == nil ) then
	P2P_DIR_UNKNOWN = -1
	P2P_DIR_SENT    =  0
	P2P_DIR_RECV    =  1
end

-- FBB next protocol
local fbb_next_protocol = {
	MBL_RLI=1,  -- Standard Forwarding Protocol
	ASCII=2,    -- ASCII Basic Protocol
	BCP_v0=3,   -- Binary Compressed Protocol version 0
	BCP_v1=4,   -- Binary Compressed Protocol version 1
	B2F=5,      -- B2 Forwarding / Winlink
}

local fbb_state = {
	INIT=1,     -- Initialization mode
	CMDS=2,     -- Command mode
	XFER=3,     -- Transfer mode
};


-- Stream info
local fbb_tcp_stream_infos = {}

-- Packet info
local fbb_pinfo = {}
-------------------------------------------------------------------------------
-- FBB SID Features Definition
-------------------------------------------------------------------------------

local fbb_feature_flagval = {
	F_PERS_MSG_ACK=1,         -- A
	F_COMP_XFER=2,            -- B
	F_DATE_DISTR=4,           -- C
	--F_=8,                   -- D
	--F_=16,                  -- E
	F_BASIC_XFER=32,          -- F
	F_GZIP=64,                -- G
	F_HLOC=128,               -- H
	F_IBSID=256,              -- I
	F_WL2K_CMS=512,           -- J
	--F_=1024,                -- K
	F_G1NNA_COMP=2048, 		  -- L
	F_MID=4096,               -- M
	--F_=8192,                -- N
	--F_=16384,               -- O
	--F_=32768,               -- P
	--F_=65536,               -- Q
	F_AA4RE_EXT_REJ=131072,   -- R
	F_AA4RE_EXT_S=262144,     -- S
	F_WL2K_T=524288,          -- T
	F_WL2K_U=1048576,         -- U
	--F_=2097152,             -- V
	F_WL2K=4194304,           -- W
	F_COMP_BATCH_FWD=8388608, -- X
	--F_=16777216,            -- Y
	--F_=33554432,            -- Z
	F_BID=67108864,           -- $
}



local fbb_feature_labels = {
	[fbb_feature_flagval.F_PERS_MSG_ACK]="Acknowledgement for personal messages",
	[fbb_feature_flagval.F_DATE_DISTR]="Automatic distribution of date / time",
	[fbb_feature_flagval.F_GZIP]="GZIP compression",
	[fbb_feature_flagval.F_HLOC]="Hierarchical Location designators",
	[fbb_feature_flagval.F_IBSID]="In-band Station Identification",
	[fbb_feature_flagval.F_WL2K_CMS]="Connected to Winlink Network (CMS or MPS)",
	[fbb_feature_flagval.F_G1NNA_COMP]="G1NNA Compression",
	[fbb_feature_flagval.F_MID]="Message identifiers (MID)",
	[fbb_feature_flagval.F_AA4RE_EXT_REJ]="AA4RE Extended reject responses",
	[fbb_feature_flagval.F_AA4RE_EXT_S]="AA4RE Extended S commands support",
	[fbb_feature_flagval.F_WL2K_T]="Winlink? (feature T)",
	[fbb_feature_flagval.F_WL2K_U]="Winlink? (feature U)",
	[fbb_feature_flagval.F_WL2K]="Winlink Network",
	[fbb_feature_flagval.F_COMP_BATCH_FWD]="Compressed batch forwarding",
	[fbb_feature_flagval.F_BID]="Basic message identification",
}

-- Flag lookup table
local fbb_feature_lut = {
	[0x41]=fbb_feature_flagval.F_PERS_MSG_ACK,  -- A
	[0x43]=fbb_feature_flagval.F_DATE_DISTR,    -- C
	[0x47]=fbb_feature_flagval.F_GZIP,          -- G
	[0x48]=fbb_feature_flagval.F_HLOC,          -- H
	[0x49]=fbb_feature_flagval.F_IBSID,         -- I
	[0x4A]=fbb_feature_flagval.F_WL2K_CMS,      -- J
	[0x4C]=fbb_feature_flagval.F_G1NNA_COMP,    -- L
	[0x4D]=fbb_feature_flagval.F_MID,           -- M
	[0x52]=fbb_feature_flagval.F_AA4RE_EXT_REJ, -- R
	[0x53]=fbb_feature_flagval.F_AA4RE_EXT_S,   -- S
	[0x54]=fbb_feature_flagval.F_WL2K_T,        -- T
	[0x55]=fbb_feature_flagval.F_WL2K_U,        -- U
	[0x57]=fbb_feature_flagval.F_WL2K,          -- W
	[0x58]=fbb_feature_flagval.F_COMP_BATCH_FWD,-- X
	[0x24]=fbb_feature_flagval.F_BID,           -- $
}

local fbb_nproto_label = {
	[fbb_next_protocol.MBL_RLI] = "Standard Forwarding Protocol",
	[fbb_next_protocol.ASCII]   = "ASCII Basic Protocol",
	[fbb_next_protocol.BCP_v0]  = "Binary Compressed Protocol version 0",
	[fbb_next_protocol.BCP_v1]  = "Binary Compressed Protocol version 1",
	[fbb_next_protocol.B2F]     = "B2 Forwarding",
}

local fbb_nproto_short_label = {
	[fbb_next_protocol.MBL_RLI] = ", MBL/RLI",
	[fbb_next_protocol.ASCII]   = ", ASCII",
	[fbb_next_protocol.BCP_v0]  = ", BCP version 0",
	[fbb_next_protocol.BCP_v1]  = ", BCP version 1",
	[fbb_next_protocol.B2F]     = ", B2 Forwarding",
}

-------------------------------------------------------------------------------
-- Common utilities
-------------------------------------------------------------------------------
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

-- Find the next character
local function find_next( buffer, val, skip)
	local len = buffer:len()
	if ( skip == nil ) then skip = 0 end
	for i=skip , len-1 , 1 do
		if( buffer(i,1):uint() == val ) then return i end 
	end
	return len
end

-- Find the next new line
local function find_next_cr( buffer)
	local len = buffer:len()
	for i=0 , len-1 , 1 do
		if( buffer(i,1):uint() == 0x0a or buffer(i,1):uint() == 0x0d ) then return i end 
	end
	return len
end

-- Set or concatenate info, according to the already reached level of severity.
local function set_or_concat_info ( pinfo, fnum_id, severity, main_info, concat_info )
	if( fbb_pinfo == nil or fbb_pinfo[fnum_id] == nil or fbb_pinfo[fnum_id]["loglevel"] == nil ) then error("set_or_concat_info(): nil value in arguments") end
	if ( severity < fbb_pinfo[fnum_id]["loglevel"] ) then
		pinfo.cols.info:append( concat_info)
	else
		pinfo.cols.info = main_info
		fbb_pinfo[fnum_id]["loglevel"] = severity
	end
end

-- Display SID Feature Tree
local function fbb_sid_list_features( subtree, pinfo, buffer, featflags, nproto)
	if( nproto == nil ) then error( "fbb_sid_list_features(): Next Proto is nil") end
	
	subtree:add( p_fbb_tcp, buffer(), fbb_nproto_label[nproto] )
	pinfo.cols.info:append( fbb_nproto_short_label[nproto])
	
	for key, value in pairs( fbb_feature_flagval ) do
		result = bit.band( value, featflags)
		if ( result ~= 0 and value ~= fbb_feature_flagval.F_COMP_XFER and value ~= fbb_feature_flagval.F_BASIC_XFER ) then
			subtree:add( p_fbb_tcp, buffer(), fbb_feature_labels[ result] )
		end
	end
end

-- Enumerate SID Features in string
local function fbb_sid_parse_features( subtree, software_features, fnum_id)
	local len = software_features:len()
	
	local features = 0;
	local cur_char = 0
	local found_b = false
	local cur_key
	local f_relpos = 1
	local next_proto = fbb_next_protocol.MBL_RLI
	local cur_flag
	
	for i=0 , len-1, 1 do
		cur_key = software_features(i,1):uint()
		
		-- Feature Flag 'B'
		if ( cur_key == 0x42 ) then
			if ( find_next( software_features(), 0x46 ) == len ) then
				subtree:add_expert_info( PI_PROTOCOL, PI_ERROR, "Ignored 'B', due to absence of ASCII Basic Protocol")
				goto sid_feat_continue -- continue
			end
			found_b = true
			
			if ( i < len and software_features(i+1,1):uint() == 0x31) then
				-- B1
				next_proto = fbb_next_protocol.BCP_v1
				f_relpos = 2
				
			elseif ( i < len and software_features(i+1,1):uint() == 0x32) then
				-- B2
				next_proto = fbb_next_protocol.B2F
				f_relpos = 2
				
			else
				-- BCFv0
				next_proto = fbb_next_protocol.BCP_v0
			end
			local comp_xfer = subtree:add( p_fbb_tcp, software_features(i,f_relpos), fbb_nproto_label[next_proto]) 
			if( i+f_relpos >= len or software_features(i+f_relpos,1):uint() ~= 0x46 ) then
				comp_xfer:add_expert_info( PI_PROTOCOL, PI_WARN, "Feature 'F', is not next to B, some clients may misbehave")
			end
			features = features + fbb_feature_flagval.F_COMP_XFER
			
		elseif ( cur_key == 0x31 or cur_key == 0x32 ) then
			-- Ignore 1 and 2
		
		-- Feature Flag 'F'
		elseif ( cur_key == 0x46 ) then
			local basic_xfer = subtree:add( p_fbb_tcp, software_features(i,1), fbb_nproto_label[fbb_next_protocol.ASCII])
			if ( find_next( software_features(), 0x42 ) ~= len ) then
				basic_xfer:add_expert_info( PI_PROTOCOL, PI_COMMENT, "Ignored, due to presence of a higher protocol")
			else
				-- Set Next Protocol to ASCII
				next_proto = fbb_next_protocol.ASCII
			end
			features = features + fbb_feature_flagval.F_BASIC_XFER
		
		-- Generic flags
		elseif ( fbb_feature_lut[ cur_key ] ~= nil ) then
			-- Add feature
			features = features + fbb_feature_lut[ cur_key ]
			local gen_feat = subtree:add( p_fbb_tcp, software_features(i,1), fbb_feature_labels[ fbb_feature_lut[ cur_key ]])
		else
			local unk_flag = subtree:add( p_fbb_tcp, software_features(i,1), "Unknown feature flag")
			unk_flag:add_expert_info( PI_PROTOCOL, PI_WARN, "Undocumented feature")
		end
		::sid_feat_continue::
	end
	
	if( features == 0 ) then
		subtree:add_expert_info( PI_PROTOCOL, PI_NOTE, "No known feature found")
	end
	return features , next_proto
end

-- Parse the bytes to append field, returns the append field value, and the offset to resume to on string
local function fbb_get_append_offset( buffer)
	if( buffer == nil ) then return nil, 0 end
	
	local len = buffer():len()
	
	if( len == 0 ) then return nil, 0 end
	local offset = 0
	local curchar
	local found = false
	
	for offset=0, len-1, 1 do
		curchar = buffer(offset,1):uint()
		if ( curchar >= 0x30 and curchar <= 0x39 ) then 
			found = true
			break 
		end
	end
	
	if ( found == true ) then
		return tonumber( buffer(0,i+1), 10), offset
	end
	
	return nil
end

-- Get the size of *ONE* compressed message, returns nil if invalid, and -1 if needs reassembly
local function fbb_binxfer_get_size( buffer)
	if ( buffer == nil ) then return nil end
	local len = buffer():len()
	
	if( buffer(0,1):uint() ~= 0x01 ) then return nil end
	local i = 0
	
	while ( i < len) do
		local cur_byte = buffer(i,1):uint()
		
		-- Invalid frame
		if ( i+1 >= len ) then return nil end
		
		if( cur_byte == 0x01 or cur_byte == 0x02 ) then
			i = i + 2 + buffer(i+1,1):uint() -- Two for the header, plus the payload
			
		elseif( cur_byte == 0x04 ) then
			return i + 2  -- One for the extra byte, and 1 for the fencepost
		else
			-- Invalid Frame
			return nil
		end
	end
	-- Too short, needs reassembly
	return -1
end

local function fbb_is_ibsid( buffer)
	if ( buffer == nil ) then return nil end
	local len = buffer():len()
	
	if ( buffer(0,2):string() ~= "; " ) then return false end
	
	local spaces = {}
	local i=2
	local j=0
	
	while ( i < len ) do
		next_space = find_next( buffer, 0x20, i)
		if ( i == len ) then break end
		spaces[j] = next_space
		
		j = j + 1
		i = next_space + 1
	end
	
	if ( spaces[0] == nil or spaces[1] == nil or buffer( spaces[0]+1, spaces[1]-spaces[0]-1):string() ~= "DE" ) then return false end

	return true
end

-------------------------------------------------------------------------------
-- Global settings
-------------------------------------------------------------------------------
local fbb_tcp_settings =
{
	enabled      = true, -- whether this dissector is enabled or not
	port         = 8772, -- default TCP port number
	decode       = true, -- should this dissector interpret the payload as FBB over TCP
}

-------------------------------------------------------------------------------
-- Specific dissectors
-------------------------------------------------------------------------------
-- Base Dissector : Displays preauth labels, then comments.
local function fbb_base_dissector ( buffer, pinfo, subtree, fbb_seq, fnum_id, is_s2c )
	local len = buffer:len()
	
	-- TODO: ;SQ:
	local title = fif( fbb_seq < 4, fif( is_s2c, "Challenge: \"", "Response: \""), "Comment: \"") .. buffer(0,len):string() .. "\""
	--pinfo.cols.info = title
	set_or_concat_info ( pinfo, fnum_id, PI_COMMENT, title, "" ) -- Log level COMMENT = 2
	subtree:add( p_fbb_tcp, buffer(0,len), title)

end

-- In-band Station ID Dissector : Displays caller, called station and caller's locator, if applicable
local function fbb_ibsid_dissector ( buffer, pinfo, tree, fbb_seq, stream_id, is_s2c )
	if ( buffer == nil ) then return nil end
	local len = buffer():len()
	
	if ( buffer(0,2):string() ~= "; " ) then return false end
	
	local subtree
	local spaces = {}
	local i=2
	local j=0
	
	while ( i < len ) do
		next_space = find_next( buffer, 0x20, i)
		if ( i == len ) then break end
		spaces[j] = next_space
		
		j = j + 1
		i = next_space + 1
	end
	
	if ( spaces[0] == nil or spaces[1] == nil or buffer( spaces[0]+1, spaces[1]-spaces[0]-1):string() ~= "DE" ) then return false end

	-- Skip in absence of feature 'I', after placing a warning in the dissection tree
	local server_feats = fbb_tcp_stream_infos[ stream_id ]["server_feats"]
	if ( server_feats == nil or bit.band( server_feats, fbb_feature_flagval.F_IBSID) == 0 ) then
		subtree = tree:add( p_fbb_tcp, buffer(0,len), "Comment: \"" .. buffer(0,len):string() .. "\"")
		subtree:add_expert_info( PI_PROTOCOL, PI_WARN, "Probable In-band Station ID ignored, due to missing feature 'I' in Server Hello")
		return
	end
	
	local called = buffer( 2, spaces[0]-2)
	local calling = nil
	local locator = nil
	
	if ( spaces[2] ~= nil ) then
		-- TODO: set locator
		calling = buffer( spaces[1]+1, spaces[2]-spaces[1]-1)
		locator = buffer( spaces[2]+2, len-spaces[2]-3)
	else
		calling = buffer( spaces[1]+1, len-spaces[1]-1)
	end
	
	subtree = tree:add( p_fbb_tcp, buffer(), "In-Band Station Identification")
	local caller_subtree = subtree:add( p_fbb_tcp, calling, "Calling Station ID: " .. calling:string())
	if ( locator ~= nil ) then
		caller_subtree:add( p_fbb_tcp, locator, "Caller's Location: " .. locator:string())
	end
	subtree:add( p_fbb_tcp, called, "Called Station ID: " .. called:string())
	
end

local function fbb_comment_dissector ( buffer, pinfo, subtree, stream_id, fnum_id, is_s2c )
	local len = buffer:len()	
	
	local fbb_seq            = fbb_pinfo[fnum_id]["seq"]
	local current_state      = fbb_pinfo[fnum_id]["state"]
	local next_proto         = fbb_pinfo[fnum_id]["next_proto"]
	local opts_xchg_done     = fbb_pinfo[fnum_id]["opts_xchg_done"]
	
	local main_info = "" -- Used for subtree entry
	
	
	if ( len == 13 and buffer(0,5):string() == ";PQ: " ) then
		main_info = "Winlink auth Nonce: " .. buffer(5,8):string()
		set_or_concat_info ( pinfo, fnum_id, PI_CHAT, main_info, ", auth Nonce" )
	elseif ( len == 13 and buffer(0,5):string() == ";PR: " ) then
		main_info = "Winlink auth reply: " .. buffer(5,8):string()
		set_or_concat_info ( pinfo, fnum_id, PI_CHAT, main_info, ", auth reply" )
	elseif ( len > 5 and buffer(0,5):string() == ";FW: " ) then
		main_info = "Winlink forward request: " .. buffer(5,len-5):string()
		set_or_concat_info ( pinfo, fnum_id, PI_CHAT, main_info, ", forward request" )
	-- TODO ;SR:
	-- TODO: CSID
	elseif ( fbb_is_ibsid( buffer) == true ) then
		main_info = "Station Identification"
		set_or_concat_info ( pinfo, fnum_id, PI_CHAT, main_info, ", station ident" )
		fbb_ibsid_dissector( buffer, pinfo, subtree, fbb_seq, stream_id, is_s2c )
		return
	else
		-- Base line, call appropriate dissector
		fbb_base_dissector ( buffer, pinfo, subtree, fbb_seq, fnum_id, is_s2c )
		return
	end
	
	subtree:add( p_fbb_tcp, buffer(0,len), main_info)
end

-- SID Banner Dissector
local function fbb_sid_dissector ( buffer, pinfo, subtree, stream_id, fnum_id, is_s2c)
	local len = buffer:len()
	local main_info = fif( is_s2c, "Server Hello", "Client Hello")
	local alt_info = fif( is_s2c, ", server hello", ", client hello")
	local first_sep = 0
	local second_sep = 0
	
	-- Add Element to tree
	set_or_concat_info ( pinfo, fnum_id, PI_NOTE, main_info, alt_info )
	local sid_elt = subtree:add( p_fbb_tcp, buffer(), main_info)
		
	-- Parse Fields

	first_sep = find_next( buffer(1,len-1), 0x2D )
	if ( first_sep == len ) then
		sid_elt:add_expert_info( PI_MALFORMED, PI_ERROR, "Mandatory field separator not found in field")
		return
	end
	
	local software_name = buffer( 1, first_sep);	
	sid_elt:add( p_fbb_tcp, software_name, "Software name: " .. software_name:string() )
	
	second_sep = find_next( buffer(1,len-1), 0x2D, first_sep+1 )
	
	-- 1 offset for initial bracket, 1 for the separator itself, remove trailing separator/bracket
	local software_ver = buffer( first_sep+2,fif( second_sep ~= len, second_sep-first_sep-1, second_sep-first_sep-2) )
	sid_elt:add( p_fbb_tcp, software_ver, "Software version: " .. software_ver:string() )
	
	local software_features = nil
	local featflags = 0
	local nextproto = fbb_next_protocol.MBL_RLI
	if ( second_sep ~= len ) then
		-- 1 offset for second bracket, 1 for the separator itself, remove trailing bracket
		software_features = buffer( second_sep+2, len-second_sep-3)
		local subtree_feats = sid_elt:add( p_fbb_tcp, software_features, "Software Feature List")
		featflags, nextproto = fbb_sid_parse_features( subtree_feats, software_features)
	else
		sid_elt:add_expert_info( PI_PROTOCOL, PI_NOTE, "No exposed features")
	end
	
	if ( is_s2c ) then
		-- The called party is the first to expose its banner, store flags for nego.
		fbb_tcp_stream_infos[ stream_id ]["server_feats"] = featflags
		fbb_tcp_stream_infos[ stream_id ]["server_proto"] = nextproto
	else
		-- The calling party exposes its flags.
		
		-- Perform state transition
		sid_elt:add_expert_info( PI_SEQUENCE, PI_NOTE, "FBB SID exchange completed")
		fbb_tcp_stream_infos[ stream_id ]["state"] = fbb_state.CMDS  -- For the whole stream
		fbb_pinfo[fnum_id]["cur_state"] = fbb_state.CMDS             -- For following commands in current segment
		
		-- Session features is the intersection of both server and client flags.
		fbb_tcp_stream_infos[ stream_id ]["session_feats"] = bit.band( featflags, fbb_tcp_stream_infos[ stream_id ]["server_feats"])
		
		-- Derive next proto's value
		nextproto = fif( nextproto > fbb_tcp_stream_infos[ stream_id ]["server_proto"], nextproto, fbb_tcp_stream_infos[ stream_id ]["server_proto"])
		fbb_tcp_stream_infos[ stream_id ]["next_proto"] = nextproto
		
		local neg_featlist = sid_elt:add( p_fbb_tcp, software_features, "[Common Session Features]")

		fbb_sid_list_features( neg_featlist, pinfo, software_features, fbb_tcp_stream_infos[ stream_id ]["session_feats"], nextproto)
	end

end
local function fbb_modern_proposal_dissector( frame, subtree, stream_id, fbb_seq_next )
	local len = frame():len()
	local buffer = frame(3,len-3)
	len = len-3 -- FIXME: reindex offsets instead of this dirty trick
	local spaces = {}
	--find_next( buffer, val, skip)
	spaces[0] = find_next( buffer(), 0x20)
	spaces[1] = find_next( buffer(), 0x20, spaces[0]+1)
	spaces[2] = find_next( buffer(), 0x20, spaces[1]+1)
	spaces[3] = find_next( buffer(), 0x20, spaces[2]+1)
	
	if( spaces[0] ~= 2 ) then
		subtree:add_expert_info( PI_MALFORMED, PI_ERROR, "Malformed Proposal")
		return
	end
	
	if ( buffer(0,2):string() == "EM" ) then
		subtree:add( p_fbb_tcp, buffer(0,2), "Message Type: Encapsulated Message" )
	elseif ( buffer(0,2):string() == "CM" ) then
		subtree:add( p_fbb_tcp, buffer(0,2), "Message Type: WinLink Control Message" )
	else
		local mt = subtree:add( p_fbb_tcp, buffer(0,2), "Message Type: Unknown" )
		mt:add_expert_info( PI_UNDECODED, PI_WARN, "Undocumented feature")
	end
	
	local mid   = buffer( spaces[0]+1, spaces[1]-spaces[0]-1)
	subtree:add( p_fbb_tcp, mid, "Message ID: " .. mid:string() )
	
	local usize = buffer( spaces[1]+1, spaces[2]-spaces[1]-1)
	subtree:add( p_fbb_tcp, usize, "Uncompressed size: " .. usize:string() )
	
	local csize
	if( spaces[3] ~= len ) then
		csize = buffer( spaces[2]+1, spaces[3]-spaces[2]-1)
		-- TODO: explain the meaning ot the next field
	else
		csize = buffer( spaces[2]+1, len-spaces[2]-1)
	end
	subtree:add( p_fbb_tcp, csize, "Compressed size: " .. csize:string() )
	
	subtree.text = subtree.text .. ( " (id: " .. mid:string() .. ", U-Size: " .. usize:string() .. ", C-Size: " .. csize:string() .. ")")
	
	-- Enqueue pending message metadata
	local mq_id = fbb_tcp_stream_infos[ stream_id ]["pending_msg"][fbb_seq_next]["count"]
	fbb_tcp_stream_infos[ stream_id ]["pending_msg"][fbb_seq_next]["count"] = mq_id + 1
	
	fbb_tcp_stream_infos[ stream_id ]["pending_msg"][fbb_seq_next][mq_id] = {}
	fbb_tcp_stream_infos[ stream_id ]["pending_msg"][fbb_seq_next][mq_id]["type"] = buffer(0,2):string()
	fbb_tcp_stream_infos[ stream_id ]["pending_msg"][fbb_seq_next][mq_id]["payload_type"] = "message"
	fbb_tcp_stream_infos[ stream_id ]["pending_msg"][fbb_seq_next][mq_id]["mid"] = mid:string()
	fbb_tcp_stream_infos[ stream_id ]["pending_msg"][fbb_seq_next][mq_id]["usize"] = tonumber(usize:string()) -- Uncompressed size
	fbb_tcp_stream_infos[ stream_id ]["pending_msg"][fbb_seq_next][mq_id]["csize"] = tonumber(csize:string()) -- Compressed size
	fbb_tcp_stream_infos[ stream_id ]["pending_msg"][fbb_seq_next][mq_id]["_tsize"] = tonumber(csize:string()) -- Real size to transfer
	fbb_tcp_stream_infos[ stream_id ]["pending_msg"][fbb_seq_next][mq_id]["comp_type"] = fif( frame(1,1):string() == "D", "gzip", "lzhuf")

end

local function fbb_proposal_dissector ( buffer, pinfo, subtree, stream_id, fnum_id, is_s2c, fbb_seq_next)
	local len = buffer():len()
	
	if( (len == 2 or len == 5) and buffer(1,1):uint() == 0x3E ) then
		-- 'F>' End of Proposal End of Proposals marker
		local eop_prop = subtree:add( p_fbb_tcp, buffer(), "End of Proposals marker")
		
		if( len > 2 ) then
			-- Checksum
			local rx_checksum = tonumber( buffer(3,2):string(), 16)
			eop_prop:add( p_fbb_tcp, buffer(3,2), "Proposals list checksum: " .. rx_checksum)
		else
		end

	elseif( len > 5 and buffer(1,1):uint() == 0x44 ) then
		-- 'FD' Proposal: GZIPed Pending Message Proposal
		local gzip_prop = subtree:add( p_fbb_tcp, buffer(), "GZIPed Pending Message Proposal")
		
		-- Is the required feature flag available?
		if( fbb_tcp_stream_infos[ stream_id ]["next_protocol"] < fbb_next_protocol.B2F ) then
			gzip_prop:add_expert_info( PI_PROTOCOL, PI_ERROR, "GZIP Proposal requires at least B2 Forwarding")
			return false
		end
		
		-- Is the required feature flag available?
		if( bit.band( fbb_tcp_stream_infos[ stream_id ]["session_feats"], fbb_feature_flagval.F_GZIP) == 0 ) then
			gzip_prop:add_expert_info( PI_PROTOCOL, PI_ERROR, "GZIP Proposal requested, but not available")
			return false
		end
		
		-- Dissect Proposal
		fbb_modern_proposal_dissector( buffer(), gzip_prop, stream_id, fbb_seq_next )
		
	elseif( len > 5 and buffer(1,1):uint() == 0x43 ) then
		-- 'FC' Proposal: Modern Pending Message Proposal
		local mdn_prop = subtree:add( p_fbb_tcp, buffer(), "Modern Pending Message Proposal")
		
		-- Is the required feature flag available?
		if( fbb_tcp_stream_infos[ stream_id ]["next_proto"] < fbb_next_protocol.B2F ) then
			mdn_prop:add_expert_info( PI_PROTOCOL, PI_ERROR, "Modern proposals requires at least B2 Forwarding")
			return false
		end
		
		-- Decode Proposal
		fbb_modern_proposal_dissector( buffer(), mdn_prop, stream_id, fbb_seq_next )
	end
	
	return true
end

local function fbb_fetch_mesg_dissector ( buffer, pinfo, subtree, stream_id, fnum_id, is_s2c, fbb_seq )
	local nopm_info = "Fetch messages"
	local fetch_subtree = subtree:add( p_fbb_tcp, buffer(), nopm_info)
	set_or_concat_info ( pinfo, fnum_id, PI_CHAT, nopm_info, ", fetch messages" )
	
	local protocol_ver = fbb_pinfo[fnum_id]["next_proto"]
	local commands = buffer( 3, buffer():len()-3) -- Strip the command header
	local len = commands():len()
	local cur_char
	local cur_message = 0
	local pending_messages = fbb_tcp_stream_infos[ stream_id ]["pending_msg"][fbb_seq]["count"];
	local pending_bytes = 0;
	
	if( pending_messages == 0 ) then
		fetch_subtree:add_expert_info( PI_PROTOCOL, PI_ERROR, "No pending message related to this command")
		return 0
	end
	
	for i=0, len-1, 1 do
		cur_char = commands( i, 1)
		local action_prop
		local mid = fbb_tcp_stream_infos[ stream_id ]["pending_msg"][fbb_seq][cur_message]["mid"]
		if( cur_char:string() == "+" or ( protocol_ver >= fbb_next_protocol.BCP_v1 and cur_char:string() == "Y" ) ) then
			action_prop = fetch_subtree:add( p_fbb_tcp, cur_char(), "Accept Message (id: " .. mid .. ")")
			pending_bytes = pending_bytes + fbb_tcp_stream_infos[ stream_id ]["pending_msg"][fbb_seq][i]["_tsize"]
			
		elseif( cur_char:string() == "-" or ( protocol_ver >= fbb_next_protocol.BCP_v1 and cur_char:string() == "N" ) ) then
			action_prop = fetch_subtree:add( p_fbb_tcp, cur_char(), "Drop Message (id: " .. mid .. ")")
			
		elseif( cur_char:string() == "=" or ( protocol_ver >= fbb_next_protocol.BCP_v1 and cur_char:string() == "L" ) ) then
			action_prop = fetch_subtree:add( p_fbb_tcp, cur_char(), "Defer Message (id: " .. mid .. ")")
			
		elseif( protocol_ver >= fbb_next_protocol.BCP_v1 and cur_char:string() == "H" ) then
			action_prop = fetch_subtree:add( p_fbb_tcp, cur_char(), "Hold Message (id: " .. mid .. ")")
			
		elseif( protocol_ver >= fbb_next_protocol.BCP_v1 and cur_char:string() == "R" ) then
			action_prop = fetch_subtree:add( p_fbb_tcp, cur_char(), "Reject Message (id: " .. mid .. ")")
			
		elseif( protocol_ver >= fbb_next_protocol.BCP_v1 and cur_char:string() == "E" ) then
			action_prop = fetch_subtree:add( p_fbb_tcp, cur_char(), "Error in proposal")
			
		elseif( protocol_ver >= fbb_next_protocol.BCP_v1 and ( cur_char:string() == "!" or cur_char:uint() == "A" ) ) then
			local append_sz
			local offset
			
			append, offset = fbb_get_append_offset( buffer(i+1) )
			i = i + offset
			
			if ( append ~= nil ) then
				action_prop = fetch_subtree:add( p_fbb_tcp, cur_char(), "Accept Message (id: " .. mid .. "), start from " .. append .. " byte(s).")
				if ( append <= 6 ) then
					action_prop:add_expert_info( PI_PROTOCOL, PI_WARN, "Append action will result in larger transmission size than an Accept action")
				end
			else
				action_prop = fetch_subtree:add( p_fbb_tcp, cur_char(), "Accept Message (id: " .. mid .. "), start from an undefined offset [malformed]")
				action_prop:add_expert_info( PI_PROTOCOL, PI_ERROR, "Malformed header, ASCII decimal 'offset' value expected")
			end
			
		else
			action_prop = fetch_subtree:add( p_fbb_tcp, cur_char(), "Unknown action")
			action_prop:add_expert_info( PI_PROTOCOL, PI_ERROR, "Unknown action, check if handshaked version is sufficient")
		end
		cur_message = cur_message + 1
	end
	if( pending_messages ~= cur_message ) then
		fetch_subtree:add_expert_info( PI_PROTOCOL, PI_WARN, "Some pending message(s) not covered (got: " .. cur_message .. ", expected: " .. pending_messages .. ")")
		return cur_message
	end
	
	if ( pending_bytes ~= 0 ) then
		pinfo.cols.info:append( ", " .. pending_bytes .. " byte(s) to transfer (excl. overhead)")
	end
	
	return pending_messages
end

-------------------------------------------------------------------------------
-- Main dissector
-------------------------------------------------------------------------------
function p_fbb_tcp.dissector ( buffer, pinfo, tree)
	local len = buffer:len()
	-- Validate packet length
	if ( len < 1 ) then return end

	-- Set protocol name
	pinfo.cols.protocol = "FBB"
	
	-- Call the original dissector & check the direction
	pcall( function() original_dissector:call( buffer, pinfo, tree) end )
	local is_s2c = ( pinfo.src_port == fbb_tcp_settings.port )
	
	local stream_id = "tcp_" .. f_tcp_stream().value
	local fnum_id = f_fnum().value
	
	-- Update packet direction
	pinfo.cols.direction = fif( is_s2c, P2P_DIR_RECV, P2P_DIR_SENT)
	
	-- Update the info column
	pinfo.cols.info = proto_fullname
	
	-- Build Stream metadata table if it doesn't exist
	if ( fbb_tcp_stream_infos[ stream_id ] == nil ) then
		fbb_tcp_stream_infos[ stream_id ]= {}
		fbb_tcp_stream_infos[ stream_id ]["server_feats"] = 0
		fbb_tcp_stream_infos[ stream_id ]["session_feats"] = 0
		fbb_tcp_stream_infos[ stream_id ]["opts_xchg_done"] = false
		fbb_tcp_stream_infos[ stream_id ]["dndecode"]= {}
		fbb_tcp_stream_infos[ stream_id ]["state"] = fbb_state.INIT
		fbb_tcp_stream_infos[ stream_id ]["server_proto"] = fbb_next_protocol.MBL_RLI
		fbb_tcp_stream_infos[ stream_id ]["next_proto"] = fbb_next_protocol.MBL_RLI
		fbb_tcp_stream_infos[ stream_id ]["seq_next"] = 0
		fbb_tcp_stream_infos[ stream_id ]["seq"] = {} -- 
		fbb_tcp_stream_infos[ stream_id ]["pending_msg"] = {}
	end
	
	-- Assign a sequence ID in FBB exchange
	if ( fbb_pinfo[fnum_id] == nil ) then
		fbb_pinfo[fnum_id] = {}
		
		fbb_pinfo[fnum_id]["loglevel"] = 0 -- Null
		
		-- Packet state
		fbb_pinfo[fnum_id]["seq"] = fbb_tcp_stream_infos[ stream_id ]["seq_next"]
		fbb_tcp_stream_infos[ stream_id ]["seq_next"] = fbb_tcp_stream_infos[ stream_id ]["seq_next"]+1
		
		-- Packet state
		fbb_pinfo[fnum_id]["state"] = fbb_tcp_stream_infos[ stream_id ]["state"]
		
		-- Next protocol (Upper Layer Protocol)
		fbb_pinfo[fnum_id]["next_proto"] = fbb_tcp_stream_infos[ stream_id ]["next_proto"]
		
		-- FBB SID Options exchange done
		fbb_pinfo[fnum_id]["opts_xchg_done"] = fbb_tcp_stream_infos[ stream_id ]["opts_xchg_done"];
	end
	
	fbb_pinfo[fnum_id]["cur_state"] = fbb_pinfo[fnum_id]["state"]
	
	-- FBB Sequence number
	local fbb_seq            = fbb_pinfo[fnum_id]["seq"]
	local current_state      = fbb_pinfo[fnum_id]["state"]
	local next_proto         = fbb_pinfo[fnum_id]["next_proto"]
	local opts_xchg_done     = fbb_pinfo[fnum_id]["opts_xchg_done"]
	
	-- Reset next pending message list
	fbb_tcp_stream_infos[ stream_id ]["pending_msg"][fbb_seq+1] = {}
	fbb_tcp_stream_infos[ stream_id ]["pending_msg"][fbb_seq+1]["count"] = 0
	
	-- Update the subtree with basic metadata
	local subtree = tree:add( p_fbb_tcp, buffer(), proto_fullname)
	
	local seq_str = "[FBB Sequence: " .. fbb_seq .. "]"
	subtree:add( p_fbb_tcp, buffer(0,0), seq_str)
	
	local direct_str = "[Direction: " .. fif( is_s2c, "Incoming", "Outgoing") .. "]"
	subtree:add( p_fbb_tcp, buffer(0,0), direct_str)

	-- TODO: When in XFER, detect unexpected direction reversal

	if ( next_proto < fbb_next_protocol.BCP_v0 or fbb_pinfo[fnum_id]["cur_state"] ~= fbb_state.XFER ) then
		-- Line-aligned protocol, find and split lines prior to interpretation
		local cur_line = 0
		local len_line = 0
		local actual_len_line = 0
		local pending_xfer = false
		local ascii_lines = nil
		local pending_mesgs = 0
		
		-- TODO: detect if reassembly is required (should happen if a Segment doesn't end with a '\r'
		
		local fbb_subtree = subtree:add( p_fbb_tcp, buffer(), fif( fbb_pinfo[fnum_id]["cur_state"] ~= fbb_state.XFER, "FBB Commands", "ASCII Data" ))
		
		-- Yell if we're using MBL/RLI
		if ( fbb_pinfo[fnum_id]["cur_state"] ~= fbb_state.INIT and fbb_tcp_stream_infos[ stream_id ]["next_proto"] == fbb_next_protocol.MBL_RLI ) then
			subtree:add_expert_info( PI_UNDECODED, PI_WARN, "Session is using the undocumented MBL/RLI protocol")
			--return
		end
		
		repeat
			::next_line::
			-- Parse the next line
			cur_line = cur_line + len_line
			actual_len_line = find_next_cr( buffer( cur_line))
			len_line = actual_len_line + 1
			
			-- Skip blank lines
			if( buffer(cur_line):len() < 1 or buffer( cur_line, 1):uint() == 0x0a or buffer( cur_line, 1):uint() == 0x0d ) then
				if ( cur_line+len_line >= len ) then break end
				goto next_line
			end
			
			-- Initial state: we're before SID exchange			
			if ( fbb_pinfo[fnum_id]["cur_state"] == fbb_state.INIT ) then
								
				if ( buffer(cur_line,1):uint() == 0x5B and buffer(cur_line+actual_len_line-1,1):uint() == 0x5D ) then
					-- SID string
					fbb_sid_dissector ( buffer(cur_line,actual_len_line), pinfo, fbb_subtree, stream_id, fnum_id, is_s2c )
					
				elseif ( buffer(cur_line,1):uint() == 0x3B ) then
					-- Special purpose comment, depending on the situation
					fbb_comment_dissector ( buffer(cur_line,actual_len_line), pinfo, fbb_subtree, stream_id, fnum_id, is_s2c )
					
				else
					-- Basic Dissector
					fbb_base_dissector ( buffer(cur_line,actual_len_line), pinfo, fbb_subtree, fbb_seq, fnum_id, is_s2c )	
				end
				
			-- Commands mode
			elseif ( fbb_pinfo[fnum_id]["cur_state"] == fbb_state.CMDS ) then 
				local proposal_code = buffer(cur_line,3):string()
				if ( proposal_code == "FS " ) then
					local pending_xfers = 0
					-- Message Transfer Query
					pending_xfers = fbb_fetch_mesg_dissector ( buffer(cur_line,actual_len_line), pinfo, fbb_subtree, stream_id, fnum_id, is_s2c, fbb_seq )
		
					-- Mark the next message for flow reversal
					if ( pending_xfers ~= 0 ) then pending_xfer = true end

				elseif ( proposal_code == "FA " or proposal_code == "FB " or proposal_code == "FC " or proposal_code == "FD " or proposal_code == "F> ") then
					-- Message Proposal
					fbb_proposal_dissector ( buffer(cur_line,actual_len_line), pinfo, fbb_subtree, stream_id, fnum_id, is_s2c, fbb_seq+1 )
					
					if( buffer(cur_line,2):string() ~= "F>" ) then 
						pending_mesgs = pending_mesgs+1 
					end
					
				elseif ( buffer(cur_line,1):uint() == 0x3B ) then
					-- Special purpose comment, depending on the situation
					fbb_comment_dissector ( buffer(cur_line,actual_len_line), pinfo, fbb_subtree, stream_id, fnum_id, is_s2c )
					
				elseif( buffer(cur_line,2):string() == "FF" ) then
					-- 'FF' Proposal: No Pending Message
					local nopm_info = "No Pending Message"
					fbb_subtree:add( p_fbb_tcp, buffer(cur_line,2), nopm_info)
					set_or_concat_info ( pinfo, fnum_id, PI_CHAT, nopm_info, ", no pending mesg" )
		
				elseif( buffer(cur_line,2):string() == "FQ" ) then
					-- 'FQ' Proposal: Disconnection Request
					local disc_info = "Disconnection Request"
					fbb_subtree:add( p_fbb_tcp, buffer(cur_line,2), disc_info)
					set_or_concat_info ( pinfo, fnum_id, PI_NOTE, disc_info, ", disc. req." )
					
				else
					-- Basic Dissector
					fbb_base_dissector ( buffer(cur_line,actual_len_line), pinfo, fbb_subtree, fbb_seq, fnum_id, is_s2c )
				end
			else
				-- ASCII Data Transfer
				
				-- TODO: Handle mode change
				if ( ascii_lines == nil ) then
					ascii_lines = fbb_subtree:add( p_fbb_tcp, nil, "ASCII Basic Payload")
				end
				-- TODO: Properly detect title and text
				ascii_lines:add( p_fbb_tcp, buffer(cur_line,actual_len_line), "Payload Line")
			end
			
			if ( cur_line+len_line >= len ) then break end
		until ( false )
		
		if ( pending_mesgs > 0 ) then
			pinfo.cols.info:append( ", " .. pending_mesgs .. " pending message" .. fif( pending_mesgs ~= 1, "s", ""))
		end
		
		if ( pending_xfer ) then
			-- Handle state transition to data transfer, happens at modem reversal.
			fbb_tcp_stream_infos[ stream_id ]["state"] = fbb_state.XFER
		end
	else
		-- Binary transfer
		local fbb_subtree = subtree:add( p_fbb_tcp, buffer(), "Binary data transfer")
		
		-- Adjust FBB sequence number
		fbb_tcp_stream_infos[ stream_id ]["seq_next"] = fbb_tcp_stream_infos[ stream_id ]["seq_next"] - 1
		
		-- Encaspulated message size
		local message_size = fbb_binxfer_get_size( buffer())
		
		if ( message_size == nil ) then
			-- Error handling
			fbb_subtree:add_expert_info( PI_MALFORMED, PI_ERROR, "Invalid payload format (expected YAPP-U)")
			
			-- Return to commands for the next message
			fbb_tcp_stream_infos[ stream_id ]["state"] = fbb_state.CMDS
		end

		-- Check if we need reassembly
		if ( message_size == -1 ) then
			pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
			pinfo.desegment_offset = 0
			return
		end
		
		-- Desegment for the next message.
		if ( message_size < len ) then
			-- Specify the desegmentation instructions
			pinfo.desegment_offset = message_size
			-- Will we need an extra reassembly
			if( fbb_binxfer_get_size( buffer( message_size, len-message_size) ) == -1 ) then
				pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
			end
		end
		
		if ( fbb_tcp_stream_infos[ stream_id ]["mesg_ctr"] == nil ) then
			fbb_tcp_stream_infos[ stream_id ]["mesg_ctr"] = 0
		end
		
		if ( fbb_pinfo[fnum_id]["mesg_ctr"] == nil ) then
			fbb_pinfo[fnum_id]["mesg_ctr"] = fbb_tcp_stream_infos[ stream_id ]["mesg_ctr"]
			fbb_tcp_stream_infos[ stream_id ]["mesg_ctr"] = fbb_tcp_stream_infos[ stream_id ]["mesg_ctr"] + 1
		end
		
		local mesg_id = fbb_pinfo[fnum_id]["mesg_ctr"]

		local mid = fbb_tcp_stream_infos[ stream_id ]["pending_msg"][fbb_seq-1][mesg_id]["mid"]
		local comp_type = fbb_tcp_stream_infos[ stream_id ]["pending_msg"][fbb_seq-1][mesg_id]["comp_type"]
		
		pinfo.cols.info = "Message transfer, MID: " .. mid .. ", comp alg: " .. comp_type -- TODO: add MID
		local expects_newmsg = true
		
		-- Pass the message to YAPP-U dissector
		local yapp_u = Dissector.get("yapp_u")
		if ( yapp_u ~= nil ) then
			pinfo.private["yapp_u_payload_format"] = comp_type
			pinfo.private["lzhuf_next_dissector"] = fif( next_proto >= fbb_next_protocol.B2F, "b2f_mail", nil )
			pinfo.private["fbb_mid"] = mid
			-- TODO: add csize and usize if applicable
			yapp_u:call( buffer(0,message_size):tvb(), pinfo, tree)
		end
		
		-- Return to Commands mode once our message Tx queue is processed.
		-- Data transfer ends with immediate modem reversal
		if ( mesg_id+1 == fbb_tcp_stream_infos[ stream_id ]["pending_msg"][fbb_seq-1]["count"] ) then
			fbb_tcp_stream_infos[ stream_id ]["state"] = fbb_state.CMDS
		end
	end
end

-------------------------------------------------------------------------------
-- Plugin preferences and management
-------------------------------------------------------------------------------

p_fbb_tcp.prefs.enabled = Pref.bool("Dissector enabled", fbb_tcp_settings.enabled,
                                        "Whether the Winlink over TCP dissector is enabled or not")

p_fbb_tcp.prefs.portnum = Pref.uint("Port Number", fbb_tcp_settings.port,
                                        "The default Winlink over TCP port")

p_fbb_tcp.prefs.decode = Pref.bool("Decode payload", fbb_tcp_settings.decode,
                                        "Whether the dissector should interpret and unpack its payload")
										
-- Register the dissector
local function regDissectors()
	DissectorTable.get("tcp.port"):add( fbb_tcp_settings.port, p_fbb_tcp)
	fbb_tcp_stream_infos = {}
	fbb_pinfo = {}
end
-- call it now, because we're enabled by default
regDissectors()

-- Unregister the dissectors
local function unregDissectors()
	DissectorTable.get("tcp.port"):remove( fbb_tcp_settings.port, p_fbb_tcp)
	fbb_tcp_stream_infos = {}
	fbb_pinfo = {}
end

-- Track the settings change
function p_fbb_tcp.prefs_changed()
	local must_change_port  = fbb_tcp_settings.port    ~= p_fbb_tcp.prefs.portnum
	local must_change_state = fbb_tcp_settings.enabled ~= p_fbb_tcp.prefs.enabled
	local must_change_dec   = fbb_tcp_settings.decode  ~= p_fbb_tcp.prefs.decode
	local must_reload = must_change_port or must_change_state or must_change_dec
	
	-- Payload decoding change
	fbb_tcp_settings.decode = p_fbb_tcp.prefs.decode

	-- Port change
	if ( must_change_port ) then
		-- Disable dissectors if they were previously enabled
		if( fbb_tcp_settings.enabled ) then unregDissectors() end

		-- Update preferences
		fbb_tcp_settings.port = p_fbb_tcp.prefs.portnum
		fbb_tcp_settings.enabled = p_fbb_tcp.prefs.enabled

		-- Enable back the dissectors if they are enabled
		if( fbb_tcp_settings.enabled ) then regDissectors() end
	end

	-- Simple state change
	if( must_change_state and not must_change_port ) then
		fbb_tcp_settings.enabled = p_fbb_tcp.prefs.enabled

		if( fbb_tcp_settings.enabled ) then
			regDissectors()
		else
			unregDissectors()
		end
	end

	-- Reload the capture file
	if (must_reload) then reload() end
end
