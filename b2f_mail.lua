-- b2f_mail.lua - B2F E-mail

-- Some module-specific constants
local proto_shortname = "b2f_mail"
local proto_fullname  = "B2F E-mail"


local b2f_mail_state = {
	HEADERS=1,     -- Initialization mode
	BODY=2,     -- Command mode
	ATTACHMENTS=3,     -- Transfer mode
};

-------------------------------------------------------------------------------
-- Common utilities
-------------------------------------------------------------------------------
-- Find the next new line
local function find_next_val( buffer, val)
	local len = buffer:len()
	local i=0
	while ( i < len ) do
		if( buffer(i,1):uint() == val ) then return i end 
		i = i+1
	end
	return len
end

-- Find the next new line
local function find_header_end( buffer)
	local len = buffer:len()
	local i=0
	while ( i < len-1 ) do
		if( buffer(i,1):uint() == 0x0A and buffer(i+1,1):uint() == 0x0D  ) then return i+1 end 
		i = i+1
	end
	return len
end

-------------------------------------------------------------------------------
-- Dissector
-------------------------------------------------------------------------------
p_b2f_mail = Proto ( proto_shortname, proto_fullname)

function p_b2f_mail.dissector ( buffer, pinfo, tree)
	local len = buffer():len()
	
	local subtree = tree:add( p_b2f_mail, buffer, "")
	local headers_subtree = subtree:add( p_b2f_mail, buffer(0, find_header_end(buffer)), "Headers")
	
	local cur_line = 0
	local cur_len = 0
	local next_line = 0
	local state = b2f_mail_state.HEADERS
	local body_sz = nil
	local attachments = {}
	attachments.count = 0
	attachments.current = 0
	
	local attr_type, attr_value, colon_pos
	
	while ( next_line < len ) do
		if ( state == b2f_mail_state.HEADERS ) then
			next_line = find_next_val( buffer( cur_line), 0x0A) +1
			cur_len = next_line - 2
			if ( cur_len <= 0 ) then
				if ( body_sz == nil ) then
					headers_subtree:add_expert_info( PI_MALFORMED, PI_ERROR, "Message headers didn't specify a body size")
					return
				end
				state = b2f_mail_state.BODY
				goto next_line
			end
			
			-- Decode the current header
			colon_pos = find_next_val( buffer( cur_line), 0x3A)
			attr_type = buffer(cur_line, colon_pos):string()
			attr_value = buffer(cur_line+colon_pos+2, cur_len-colon_pos-2):string()
			
			if ( string.upper(attr_type) == "MID" ) then
				-- Message ID
				local mid_subtree = headers_subtree:add( p_b2f_mail, buffer( cur_line, cur_len), "Message ID: " .. attr_value)
				if ( pinfo.private["fbb_mid"] ~= nil and pinfo.private["fbb_mid"] ~= attr_value ) then
					mid_subtree:add_expert_info( PI_MALFORMED, PI_WARN, "Message ID in message doesn't match with B2F transaction MID (got '" .. pinfo.private["fbb_mid"] .. "')")
				end
				
			elseif ( string.upper(attr_type) == "BODY" ) then
				-- Body length
				headers_subtree:add( p_b2f_mail, buffer( cur_line, cur_len), "Body length: " .. attr_value .. " byte(s)")
				body_sz = tonumber( attr_value, 10)
				
			elseif ( string.upper(attr_type) == "FILE" ) then
				-- Attachment
				local separator = find_next_val( buffer( cur_line+colon_pos+2, cur_len-colon_pos-2), 0x20)
				
				local fsize = tonumber( string.sub( attr_value, 0, separator), 10)
				local fname = string.sub( attr_value, separator+2)
				headers_subtree:add( p_b2f_mail, buffer( cur_line, cur_len), "Attached file: " .. fname .. ", " .. fsize .. " byte(s)")
				attachments[attachments.count] = { ["size"]=fsize, ["name"]=fname }
				attachments.count = attachments.count + 1
				
			else
				headers_subtree:add( p_b2f_mail, buffer( cur_line, cur_len), attr_type .. ": " .. attr_value )
			end
			
			if ( cur_line == 0 and string.upper(attr_type) ~= "MID" ) then
				headers_subtree:add_expert_info( PI_MALFORMED, PI_WARN, "Message ID not set as first attribute, as required by the Open B2F Specification")
			end
			
			::next_line::
			cur_line = cur_line + next_line 
			
		elseif ( state == b2f_mail_state.BODY ) then
			subtree:add( p_b2f_mail, buffer( cur_line, body_sz), "Body")
			cur_line = cur_line + body_sz
			state = b2f_mail_state.ATTACHMENTS
			
		elseif ( state == b2f_mail_state.ATTACHMENTS ) then
			while ( attachments.current < attachments.count ) do
				cur_line = cur_line + 2
				local attach_sz = attachments[attachments.current].size
				local attach_name = attachments[attachments.current].name
				
				-- Display file content in a dedicated tab
				local ba_attach = ByteArray.new()
				ba_attach:append( buffer( cur_line, attach_sz ):bytes())
				local attach_tvb = ba_attach:tvb( "File " .. attach_name )
				
				subtree:add( p_b2f_mail, attach_tvb(), "Attached file: " .. attach_name .. ", " .. attach_sz .. " byte(s)")
				
				cur_line = cur_line + attach_sz
				attachments.current = attachments.current + 1
			end
			break
		else
			break
		end
	end
	pinfo.cols.protocol = "B2F MAIL"
end
