-- b2f.lua
-- B2F Dissector
p_b2f = Proto ( "B2F", "B2F Message forwarding protocol")

-------------------------------------------------------------------------------
-- Connection metadata
-------------------------------------------------------------------------------
-- The purpose of this table is to make some metadata (features, version...)
-- persist along a tcp stream. We'll need to find a way to broaden the tag beyond
-- tcp later, to support AX.25 connected mode for instance
local b2f_con_meta = {}

-------------------------------------------------------------------------------
-- Fields
-------------------------------------------------------------------------------
local pf_b2f_stream = ProtoField.string( "b2f.stream", "B2F stream index")

-------------------------------------------------------------------------------
-- Common utilities
-------------------------------------------------------------------------------
-- Find the next new line
local function find_next_cr( buffer)
	local len = buffer:len()
	for i=0 , len-1 , 1 do
		if( buffer(i,1):uint() == 0x0a or buffer(i,1):uint() == 0x0d ) then return i end 
	end
	return len
end

-------------------------------------------------------------------------------
-- Software identification
-------------------------------------------------------------------------------
local b2f_features = {
	F_PERS_MSG_ACK=1, 		-- A
	F_COMP_XFER=2, 			-- B
	F_DATE_DISTR=4, 		-- C
	--F_=8, 				-- D
	F_BASIC_XFER=16, 		-- F
	F_GZIP=32, 				-- G
	F_HLOC=64, 				-- H
	F_NULLCMD=128, 			-- I
	--F_=256, 				-- J
	F_G1NNA_COMP=512, 		-- L
	F_MID=1024, 			-- M
	F_AA4RE_EXT_REJ=2048, 	-- R
	F_AA4RE_EXT_S=4096, 	-- S
	F_WL2K_T=8192, 			-- T
	F_WL2K_U=16384, 		-- U
	F_WL2K=32768, 			-- W
	F_COMP_BATCH_FWD=65536,	-- X
	F_BID=131072, 			-- $
}

-- Find the next new line
local function sid_find_separators( buffer)
	local len = buffer:len()
	local first_sep = nil
	local scnd_sep = nil

	for i=0 , len-1 , 1 do
		if( buffer(i,1):uint() == 0x2D ) then
			if( first_sep == nil ) then
				first_sep = i
			else
				scnd_sep = i
				break
			end
		end
	end

	return first_sep, scnd_sep
end

-- Process the Software Identification
local function process_sid( buffer, pinfo, tree)
	local buf_len = buffer:len()	-- SID length
	local first_sep 				-- Position of the first '-' separator
	local scnd_sep					-- Position of the second '-' separator
	local sid_author				-- Software author
	local sid_version				-- Version number or author data
	local sid_features = nil		-- Optional features
	local sess_ver = 0				-- Session version (can be 0 to 2)
	local sess_feats = 0			-- Session optional features
	
	-- Ignore anything smaller than the smallest frame
	if ( buf_len < 5 ) then return end
	
	-- Ignore anything that begins and ends by anything else than '[' and ']' respectively
	if ( buffer(0,1):uint() ~= 0x5B or buffer(buf_len-1,1):uint() ~= 0x5D ) then return end
	first_sep, scnd_sep = sid_find_separators( buffer)
	
	-- Ignore SIDs without at least one separator
	if ( first_sep == nil ) then return end
	
	-- Ignore SIDs with malformed parameters
	if ( first_sep == 1 or ( scnd_sep ~= nil and ( scnd_sep-first_sep == 1 or buf_len-scnd_sep == 2 ))) then return end
	
	-- Populate fields
	sid_author = buffer( 1, first_sep-1)
	tree:set_text( "Software Identification")	
	tree:add( p_b2f, sid_author, "Author: " .. sid_author:string())
	
	if( scnd_sep ~= nil ) then
		-- We have a feature field
		sid_version = buffer( first_sep+1, scnd_sep-first_sep-1)
		tree:add( p_b2f, sid_version, "Version: " .. sid_version:string())
		
		sid_features = buffer( scnd_sep+1, buf_len-scnd_sep-2)
		local feat_tree = tree:add( p_b2f, sid_features, "Supported feature(s) list" )
		
		-- Parse the feature field
		local feat_pos = scnd_sep+1
		local feat_last = buf_len-2
		
		for i=feat_pos, feat_last, 1 do
			if ( buffer(i,1):string() == "A" ) then
				feat_tree:add( p_b2f, buffer(i,1), "Acknowledgement for personal messages")
				sess_feats=sess_feats+b2f_features.F_PERS_MSG_ACK
				
			elseif ( buffer(i,1):string() == "B" ) then
				if ( i+1 <= feat_last and buffer(i+1,1):uint() >= 0x30 and buffer(i+1,1):uint() <= 0x32 ) then
					-- Version specified
					feat_tree:add( p_b2f, buffer(i,2), "Binary compressed protocol version " .. buffer(i+1,1):string())
					sess_ver=buffer(i+1,1):uint()-0x30
				else
					-- Default version
					feat_tree:add( p_b2f, buffer(i,1), "Binary compressed protocol version 0")
				end
				sess_feats=sess_feats+b2f_features.F_COMP_XFER
				
			elseif ( buffer(i,1):string() == "C" ) then
				local time_tree = feat_tree:add( p_b2f, buffer(i,1), "Automatic distribution of date / time")
				time_tree:add_expert_info( PI_PROTOCOL, PI_INFO, "Obsolete feature")
				sess_feats=sess_feats+b2f_features.F_DATE_DISTR
				
			elseif ( buffer(i,1):string() == "F" ) then
				feat_tree:add( p_b2f, buffer(i,1), "ASCII basic protocol")
				sess_feats=sess_feats+b2f_features.F_BASIC_XFER
				
			elseif ( buffer(i,1):string() == "G" ) then
				feat_tree:add( p_b2f, buffer(i,1), "GZIP compression")
				sess_feats=sess_feats+b2f_features.F_GZIP
							
			elseif ( buffer(i,1):string() == "H" ) then
				feat_tree:add( p_b2f, buffer(i,1), "Hierarchical Location designators")
				sess_feats=sess_feats+b2f_features.F_HLOC

			elseif ( buffer(i,1):string() == "I" ) then
				feat_tree:add( p_b2f, buffer(i,1), "Calling station Identification")
				sess_feats=sess_feats+b2f_features.F_NULLCMD

			elseif ( buffer(i,1):string() == "L" ) then
				feat_tree:add( p_b2f, buffer(i,1), "G1NNA Compression")
				sess_feats=sess_feats+b2f_features.F_G1NNA_COMP

			elseif ( buffer(i,1):string() == "M" ) then
				feat_tree:add( p_b2f, buffer(i,1), "Message identifiers (MID)")
				sess_feats=sess_feats+b2f_features.F_MID

			elseif ( buffer(i,1):string() == "R" ) then
				feat_tree:add( p_b2f, buffer(i,1), "AA4RE Extended reject responses")
				sess_feats=sess_feats+b2f_features.F_AA4RE_EXT_REJ

			elseif ( buffer(i,1):string() == "S" ) then
				feat_tree:add( p_b2f, buffer(i,1), "AA4RE Extended S commands support")
				sess_feats=sess_feats+b2f_features.F_AA4RE_EXT_S

			elseif ( buffer(i,1):string() == "T" ) then
				local t_tree = feat_tree:add( p_b2f, buffer(i,1), "Winlink? (feature T)")
				t_tree:add_expert_info( PI_PROTOCOL, PI_INFO, "Undocumented feature, referenced by W0RLI")
				sess_feats=sess_feats+b2f_features.F_WL2K_T

			elseif ( buffer(i,1):string() == "U" ) then
				local u_tree = feat_tree:add( p_b2f, buffer(i,1), "Winlink? (feature U)")
				u_tree:add_expert_info( PI_PROTOCOL, PI_INFO, "Undocumented feature, referenced by W0RLI")
				sess_feats=sess_feats+b2f_features.F_WL2K_U

			elseif ( buffer(i,1):string() == "W" ) then
				feat_tree:add( p_b2f, buffer(i,1), "Winlink")
				sess_feats=sess_feats+b2f_features.F_WL2K

			elseif ( buffer(i,1):string() == "X" ) then
				feat_tree:add( p_b2f, buffer(i,1), "Compressed batch forwarding")
				sess_feats=sess_feats+b2f_features.F_COMP_BATCH_FWD

			elseif ( buffer(i,1):string() == "$" ) then
				local bid_tree = feat_tree:add( p_b2f, buffer(i,1), "Basic message identification")
				sess_feats=sess_feats+b2f_features.F_BID
				if ( i ~= feat_last ) then
					bid_tree:add_expert_info( PI_PROTOCOL, PI_ERROR, "Support for BID must be the last reported feature")
				end
			elseif ( buffer(i,1):uint() >= 0x30 and buffer(i,1):uint() <= 0x39 ) then
			else
				local und_tree = feat_tree:add( p_b2f, buffer(i,1), "Unrecognized feature")
				und_tree:add_expert_info( PI_PROTOCOL, PI_WARN, "Feature not seen in the various documentations")
			end
		end
		
	else
		-- No feature field
		sid_version = buffer( first_sep+1, buf_len-first_sep-2)
		tree:add( p_b2f, sid_version, "Version: " .. sid_version:string())
		
		-- Absence of a feature field implies the peer will fall back to MBL/RLI
		tree:add( p_b2f, buffer( buf_len-1,1), "Feature: MBL/RLI protocol supported" )
	end	
end

-------------------------------------------------------------------------------
-- Main Dissector
-------------------------------------------------------------------------------
function p_b2f.dissector( buffer, pinfo, tree)
	if ( buffer:len() < 1 ) then return end

	local pk_size = buffer():len()

	-- Set protocol name
	pinfo.cols.protocol = "B2F"

	-- Binary transfer frame
	if( buffer(0,1):uint() < 0x20 ) then return end
	
	local cur_line = 0
	local len_line = 0

	local subtree = tree:add( p_b2f, buffer(), "Open B2F Commands")	

	repeat
		::next_line::
		-- Check for the next line
		cur_line = cur_line + len_line
		len_line = find_next_cr( buffer( cur_line))+1
		
		-- Skip new lines
		if( buffer(cur_line):len() >= 1 and buffer( cur_line, 1):uint() == 0x0a or buffer( cur_line, 1):uint() == 0x0d ) then
			if ( cur_line+len_line >= pk_size ) then
				break
			else
				goto next_line
			end
		end
		
		-- Process the line
		local cmdtree = subtree:add( buffer( cur_line, len_line-1), "B2F Command: " .. buffer( cur_line, len_line-1 ):string() )
		process_sid( buffer( cur_line, len_line-1 ):tvb(), pinfo, cmdtree)
		print( "   " .. buffer( cur_line, len_line-1 ):string() )

		-- Break the loop once we reach the end of the buffer
		if ( cur_line+len_line >= pk_size ) then break end
	until ( false )
end


