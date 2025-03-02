-- lzhuf.lua - LZHUF Lua decoder (tuned for Ham radio)

-- Some module-specific constants
local proto_shortname = "lzhuf"
local proto_fullname  = "LZHUF Compressed Payload"

-- Protocol Definition
p_lzhuf = Proto ( proto_shortname, proto_fullname)


-------------------------------------------------------------------------------
-- Well-known values
-------------------------------------------------------------------------------
local LZHUF_BUFFER_SZ    = 2048          -- buffer size                  #define N
local LZHUF_LA_BUFFER_SZ = 60            -- lookahead buffer size        #define F
local LZHUF_THRESHOLD    = 2
local LZHUF_TREE_NIL     = BUFFER_SZ     -- leaf of tree                 #define NIL

local LZHUF_ALPHABET_SZ  = 256 - LZHUF_THRESHOLD + LZHUF_LA_BUFFER_SZ -- #define N_CHAR
local LZHUF_TABLE_SZ     = LZHUF_ALPHABET_SZ * 2 - 1                  -- #define T
local LZHUF_ROOT_POS     = LZHUF_TABLE_SZ - 1                         -- #define R

-- Update tree when the root freq reaches this value.
local LZHUF_MAX_FREQ     = 0x8000        

-------------------------------------------------------------------------------
-- Common utilities
-------------------------------------------------------------------------------
-- Ternary operator
local function fif(condition, if_true, if_false)
	if condition then return if_true else return if_false end
end

-------------------------------------------------------------------------------
-- Lookup tables
-------------------------------------------------------------------------------

-- CRC lookup table
local lzhuf_crc_lut = {
    0x0000,  0x1021,  0x2042,  0x3063,  0x4084,  0x50a5,  0x60c6,  0x70e7,
    0x8108,  0x9129,  0xa14a,  0xb16b,  0xc18c,  0xd1ad,  0xe1ce,  0xf1ef,
    0x1231,  0x0210,  0x3273,  0x2252,  0x52b5,  0x4294,  0x72f7,  0x62d6,
    0x9339,  0x8318,  0xb37b,  0xa35a,  0xd3bd,  0xc39c,  0xf3ff,  0xe3de,
    0x2462,  0x3443,  0x0420,  0x1401,  0x64e6,  0x74c7,  0x44a4,  0x5485,
    0xa56a,  0xb54b,  0x8528,  0x9509,  0xe5ee,  0xf5cf,  0xc5ac,  0xd58d,
    0x3653,  0x2672,  0x1611,  0x0630,  0x76d7,  0x66f6,  0x5695,  0x46b4,
    0xb75b,  0xa77a,  0x9719,  0x8738,  0xf7df,  0xe7fe,  0xd79d,  0xc7bc,
    0x48c4,  0x58e5,  0x6886,  0x78a7,  0x0840,  0x1861,  0x2802,  0x3823,
    0xc9cc,  0xd9ed,  0xe98e,  0xf9af,  0x8948,  0x9969,  0xa90a,  0xb92b,
    0x5af5,  0x4ad4,  0x7ab7,  0x6a96,  0x1a71,  0x0a50,  0x3a33,  0x2a12,
    0xdbfd,  0xcbdc,  0xfbbf,  0xeb9e,  0x9b79,  0x8b58,  0xbb3b,  0xab1a,
    0x6ca6,  0x7c87,  0x4ce4,  0x5cc5,  0x2c22,  0x3c03,  0x0c60,  0x1c41,
    0xedae,  0xfd8f,  0xcdec,  0xddcd,  0xad2a,  0xbd0b,  0x8d68,  0x9d49,
    0x7e97,  0x6eb6,  0x5ed5,  0x4ef4,  0x3e13,  0x2e32,  0x1e51,  0x0e70,
    0xff9f,  0xefbe,  0xdfdd,  0xcffc,  0xbf1b,  0xaf3a,  0x9f59,  0x8f78,
    0x9188,  0x81a9,  0xb1ca,  0xa1eb,  0xd10c,  0xc12d,  0xf14e,  0xe16f,
    0x1080,  0x00a1,  0x30c2,  0x20e3,  0x5004,  0x4025,  0x7046,  0x6067,
    0x83b9,  0x9398,  0xa3fb,  0xb3da,  0xc33d,  0xd31c,  0xe37f,  0xf35e,
    0x02b1,  0x1290,  0x22f3,  0x32d2,  0x4235,  0x5214,  0x6277,  0x7256,
    0xb5ea,  0xa5cb,  0x95a8,  0x8589,  0xf56e,  0xe54f,  0xd52c,  0xc50d,
    0x34e2,  0x24c3,  0x14a0,  0x0481,  0x7466,  0x6447,  0x5424,  0x4405,
    0xa7db,  0xb7fa,  0x8799,  0x97b8,  0xe75f,  0xf77e,  0xc71d,  0xd73c,
    0x26d3,  0x36f2,  0x0691,  0x16b0,  0x6657,  0x7676,  0x4615,  0x5634,
    0xd94c,  0xc96d,  0xf90e,  0xe92f,  0x99c8,  0x89e9,  0xb98a,  0xa9ab,
    0x5844,  0x4865,  0x7806,  0x6827,  0x18c0,  0x08e1,  0x3882,  0x28a3,
    0xcb7d,  0xdb5c,  0xeb3f,  0xfb1e,  0x8bf9,  0x9bd8,  0xabbb,  0xbb9a,
    0x4a75,  0x5a54,  0x6a37,  0x7a16,  0x0af1,  0x1ad0,  0x2ab3,  0x3a92,
    0xfd2e,  0xed0f,  0xdd6c,  0xcd4d,  0xbdaa,  0xad8b,  0x9de8,  0x8dc9,
    0x7c26,  0x6c07,  0x5c64,  0x4c45,  0x3ca2,  0x2c83,  0x1ce0,  0x0cc1,
    0xef1f,  0xff3e,  0xcf5d,  0xdf7c,  0xaf9b,  0xbfba,  0x8fd9,  0x9ff8,
    0x6e17,  0x7e36,  0x4e55,  0x5e74,  0x2e93,  0x3eb2,  0x0ed1,  0x1ef0
}

-- Look-up tables to decode upper 6 bits of position
local lzhuf_d_code = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
	0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
	0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
	0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
	0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
	0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
	0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
	0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
	0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
	0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
	0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A,
	0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
	0x0C, 0x0C, 0x0C, 0x0C, 0x0D, 0x0D, 0x0D, 0x0D,
	0x0E, 0x0E, 0x0E, 0x0E, 0x0F, 0x0F, 0x0F, 0x0F,
	0x10, 0x10, 0x10, 0x10, 0x11, 0x11, 0x11, 0x11,
	0x12, 0x12, 0x12, 0x12, 0x13, 0x13, 0x13, 0x13,
	0x14, 0x14, 0x14, 0x14, 0x15, 0x15, 0x15, 0x15,
	0x16, 0x16, 0x16, 0x16, 0x17, 0x17, 0x17, 0x17,
	0x18, 0x18, 0x19, 0x19, 0x1A, 0x1A, 0x1B, 0x1B,
	0x1C, 0x1C, 0x1D, 0x1D, 0x1E, 0x1E, 0x1F, 0x1F,
	0x20, 0x20, 0x21, 0x21, 0x22, 0x22, 0x23, 0x23,
	0x24, 0x24, 0x25, 0x25, 0x26, 0x26, 0x27, 0x27,
	0x28, 0x28, 0x29, 0x29, 0x2A, 0x2A, 0x2B, 0x2B,
	0x2C, 0x2C, 0x2D, 0x2D, 0x2E, 0x2E, 0x2F, 0x2F,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
}

local lzhuf_d_len = {
	0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
	0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
	0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
	0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
	0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
	0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
	0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
	0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
	0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
	0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
	0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
	0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
	0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
	0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
	0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
	0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
	0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
	0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
	0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
	0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
	0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
	0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
	0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
	0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
	0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
	0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
	0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
	0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
	0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
	0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
	0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
	0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
}

-------------------------------------------------------------------------------
-- Internal Functions
-------------------------------------------------------------------------------

-- Checksum update function
local function lzhuf_crc_update ( checksum, val)
	if ( val == nil ) then return nil end
	if ( checksum == nil ) then return nil end
	-- ((checksum << 8) ^ lzhuf_crc_lut[ (val & 0xFF) ^ (checksum >> 8)])
	-- +1 because of initialized lua array indexing offset
	local result = bit.bxor( bit.lshift( checksum, 8), lzhuf_crc_lut[ bit.bxor( bit.band( val, 0xFF), bit.rshift( checksum, 8))+1])
	return bit.band( result, 0xFFFF) -- Constrain result as a 16 bit integer
end

local function lzhuf_crc16 ( buffer)
	if ( buffer == nil ) then return nil end
	local len = buffer():len()
	local checksum = 0;
	local i = 0
	
	while( i < len ) do
		checksum = lzhuf_crc_update( checksum, buffer( i, 1):uint())
		i = i + 1
	end
	
	return checksum
end

-- Get one bit from the input buffer
local function lzhuf_get_bit( buffer, reader_ctx)
	local result = 0
	
	while ( reader_ctx.cur_bit_count <= 8 ) do
		if ( reader_ctx.rbuff_offset < buffer():len() ) then
			result = buffer( reader_ctx.rbuff_offset, 1):uint()
			reader_ctx.rbuff_offset = reader_ctx.rbuff_offset + 1
		end
		reader_ctx.char_buff = bit.bor( reader_ctx.char_buff, bit.lshift( result, 8 - reader_ctx.cur_bit_count) )
		reader_ctx.cur_bit_count = reader_ctx.cur_bit_count + 8
	end
	
	result = reader_ctx.char_buff
	reader_ctx.char_buff = bit.lshift( reader_ctx.char_buff, 1) -- char_buff <<= 1
	reader_ctx.cur_bit_count = reader_ctx.cur_bit_count - 1

	return fif( bit.band( result, 0x8000) ~= 0, 1, 0 ) -- return the 15th bit value
end

-- Get one byte from the input buffer
local function lzhuf_get_byte( buffer, reader_ctx)
	local result = 0
	
	while ( reader_ctx.cur_bit_count <= 8 ) do
		if ( reader_ctx.rbuff_offset < buffer():len() ) then
			result = buffer( reader_ctx.rbuff_offset, 1):uint()
			reader_ctx.rbuff_offset = reader_ctx.rbuff_offset + 1
		end
		reader_ctx.char_buff = bit.bor( reader_ctx.char_buff, bit.lshift( result, 8 - reader_ctx.cur_bit_count) )
		reader_ctx.cur_bit_count = reader_ctx.cur_bit_count + 8
	end
	
	result = reader_ctx.char_buff
	reader_ctx.char_buff = bit.lshift( reader_ctx.char_buff, 8)
	reader_ctx.cur_bit_count = reader_ctx.cur_bit_count - 8

	return bit.band( bit.rshift( result, 8), 0xFF)
end

-- Initialize Huffman frequency tree
local function lzhuf_start_huff( reader_ctx)
	local i
	local j
	
	i=0
	while ( i < LZHUF_ALPHABET_SZ ) do
		reader_ctx.freq[i] = 1;
		reader_ctx.son[i] = i + LZHUF_TABLE_SZ
		reader_ctx.prnt[i + LZHUF_TABLE_SZ ] = i
		i = i + 1
	end
	
	i = 0
	j = LZHUF_ALPHABET_SZ
	while ( j <= LZHUF_ROOT_POS ) do
		reader_ctx.freq[j] = reader_ctx.freq[i] + reader_ctx.freq[i+1]
		reader_ctx.son[j] = i
		reader_ctx.prnt[i+1] = j
		reader_ctx.prnt[i] = reader_ctx.prnt[i+1]
		i = i+2
		j = j+1
	end
	reader_ctx.freq[LZHUF_TABLE_SZ] = 0xFFFF
	reader_ctx.prnt[LZHUF_ROOT_POS] = 0
end

-- Reconstruct Huffman frequency tree
local function lzhuf_reconst( reader_ctx)
	local i
	local j
	local k
	local l -- memmove emulation
	local first
	
	-- Collect leaf nodes in the first half of the table,
	-- then replace the freq by (freq +1) /2
	j = 0
	i = 0
	while ( i < LZHUF_TABLE_SZ ) do
		if( reader_ctx.son[i] >= LZHUF_TABLE_SZ ) then
			reader_ctx.freq[j] = (reader_ctx.freq[i] + 1) / 2
			reader_ctx.son[j] = reader_ctx.son[i]
			j = j + 1
			i = i + 1 -- for iteration
		end
	end
	
	-- Begin constructing tree by connecting sons
	i = 0
	j = LZHUF_ALPHABET_SZ
	while ( j < LZHUF_TABLE_SZ ) do
		k = i+1
		reader_ctx.freq[j] = reader_ctx.freq[i] + reader_ctx.freq[k]
		first = reader_ctx.freq[j]
		
		k = j - 1
		while( first < reader_ctx.freq[k] ) do
			k = k - 1
		end
		
		k = k + 1
		
		-- last = j-k; // unused in this implementation.		
		-- memmove( &lzhuf->freq[ k+1], &lzhuf->freq[ k], last)
		l = j-1
		while ( l >= k ) do
			reader_ctx.freq[l+1] = reader_ctx.freq[l]
			l = l-1
		end
		reader_ctx.freq[k] = first
		
		-- memmove( &lzhuf->son[ k+1], &lzhuf->son[ k], last)
		l = j-1
		while ( l >= k ) do
			reader_ctx.son[l+1] = reader_ctx.son[l]
			l = l-1
		end
		reader_ctx.son[k] = i
		
		i = i+2 -- for iteration
		j = j+1 -- for iteration
	end
	
	-- Connect prnt
	i = 0
	while ( i < LZHUF_TABLE_SZ ) do
		k = reader_ctx.son[i]
		if ( k >= LZHUF_TABLE_SZ ) then
			reader_ctx.prnt[k] = i
		else
			reader_ctx.prnt[k+1] = i
			reader_ctx.prnt[k] = reader_ctx.prnt[k+1]
		end
		
		i = i + 1 -- for iteration
	end
end

-- Update the frequency tree
local function lzhuf_update( reader_ctx, c)
	local i=0
	local j=0
	local k=0
	local l=0
	
	if ( reader_ctx.freq[LZHUF_ROOT_POS] == LZHUF_MAX_FREQ ) then
		lzhuf_reconst( reader_ctx)
	end
	
	c = reader_ctx.prnt[ c + LZHUF_TABLE_SZ ]
	repeat
		-- k = ++lzhuf->freq[c]
		reader_ctx.freq[c] = reader_ctx.freq[c] + 1
		k = reader_ctx.freq[c]
		
		-- If the order is disturbed, exchange nodes
		l = c + 1 -- if( k > reader_ctx.freq[l = c + 1] )
		if( k > reader_ctx.freq[l] ) then
		
			-- while( k > reader_ctx.freq[++l]);
			l = l + 1
			while ( k > reader_ctx.freq[l] ) do l = l + 1 end
			
			l = l - 1
			reader_ctx.freq[c] = reader_ctx.freq[l]
			reader_ctx.freq[l] = k
			
			i = reader_ctx.son[c]
			reader_ctx.prnt[i] = l
			if ( i < LZHUF_TABLE_SZ ) then  reader_ctx.prnt[i+1] = l  end
			
			j = reader_ctx.son[l]
			reader_ctx.son[l] = i
			
			reader_ctx.prnt[j] = c
			if( j < LZHUF_TABLE_SZ ) then  reader_ctx.prnt[j+1] = c  end
			reader_ctx.son[c] = j
			
			c = l
		end
		c = reader_ctx.prnt[c]
	until( c == 0 ) -- logic negated for equivalence a do while () condition
end

-- Decode a character
local function lzhuf_decode_char( buffer, reader_ctx)
	local c
	
	c = reader_ctx.son[ LZHUF_ROOT_POS ];
	
	while ( c < LZHUF_TABLE_SZ ) do
		c = c + lzhuf_get_bit( buffer, reader_ctx)
		c = reader_ctx.son[ c ]
	end
	
	c = c - LZHUF_TABLE_SZ
	lzhuf_update( reader_ctx, c)
	return c
end

local function lzhuf_decode_position( buffer, reader_ctx)


	local i = lzhuf_get_byte( buffer, reader_ctx)
	local c = bit.lshift( lzhuf_d_code[ i+1 ], 6 ) -- +1, cause constructor indexes start from 1 instead of 0
	local j = lzhuf_d_len[ i+1 ] -- +1, cause constructor indexes start from 1 instead of 0
	
	j = j - 2
	while ( j ~= 0 ) do
		j = j-1
		i = bit.lshift( i, 1) + lzhuf_get_bit( buffer, reader_ctx)
	end
	return bit.bor( c, bit.band( i, 0x3F))
end

-------------------------------------------------------------------------------
-- Dissector
-------------------------------------------------------------------------------
function p_lzhuf.dissector ( buffer, pinfo, tree, payload_format)
	local len = buffer():len()
	local payload_format = pinfo.private["lzhuf_next_dissector"]
	local stored_checksum = buffer(0,2):le_uint()
	local decompressed_len = buffer(2,4):le_uint()
	
	local decompressed_payload = ByteArray.new()
	
	local decompressed_tvb
	
    -- TODO: Use cached results
    if ( false ) then
    	--decompressed_payload:append( lzhuf_cache[fnum])
    	decompressed_tvb = decompressed_payload:tvb("Decompressed Payload")
    	return 0 	-- Normal return condition
    end
    
    -- Add metadata to dissection tree
	local subtree = tree:add( p_lzhuf, buffer, "")
	
	local checksum_tree = subtree:add( p_lzhuf, buffer(0,2), "Checksum: " .. string.format( "%04X", stored_checksum) )
	local size_tree = subtree:add( p_lzhuf, buffer(2,4), "Uncompressed length: " .. decompressed_len .. " byte(s)")
	local pload_tree = subtree:add( p_lzhuf, buffer(6, len-6), "Compressed Payload")
	
	-- Checksum verification
	local actual_checksum = lzhuf_crc16( buffer(2, len-2))
	
	if ( actual_checksum == stored_checksum ) then
		checksum_tree.text = checksum_tree.text .. " [valid]"
	else
		checksum_tree:add_expert_info( PI_MALFORMED, PI_ERROR, "Checksum validation failed (got " .. actual_checksum .. ", expected " .. stored_checksum .. ")" )
		return nil
	end

	-- Create data reader context, to make lzhuf_get_bit() and lzhuf_get_byte() reentrant.
	local reader_ctx = { 	 
		-- Input buffer variables
		["rbuff_offset"] = 6,  -- Read buffer offset, used to emulate internal file pointer
		["char_buff"] = 0,     -- Current bit buffer
		["cur_bit_count"] = 0, -- Current number of bits in bit buffer

		-- Huffman tree variables
		["text_buf"] = {},	   -- Text buffer
		["son"] = {},	   -- Text buffer
		["freq"] = {},	   -- Text buffer
		["prnt"] = {},	   -- Text buffer
	}
	
	local r = LZHUF_BUFFER_SZ - LZHUF_LA_BUFFER_SZ
	
	-- Initialize Huffman context
	lzhuf_start_huff( reader_ctx);
	
	local i
	i = 0
	while ( i < LZHUF_BUFFER_SZ - LZHUF_LA_BUFFER_SZ ) do
		reader_ctx.text_buf[i] = 0x20    -- ' '
		i = i+1
	end
	
	local j
	local char
	local k
	local out
	
	local count = 0
	while( count < decompressed_len ) do
		val = lzhuf_decode_char( buffer, reader_ctx)
		if ( val < 256 ) then
			-- Direct value
			decompressed_payload:append( ByteArray.new( string.format("%02X", val ) ))   -- add byte to output buffer
			reader_ctx.text_buf[ r ] = val 
			r = r + 1
			r = bit.band( r, LZHUF_BUFFER_SZ-1)
			count = count + 1
		else
			-- Backreference recall
			i = bit.band( r - lzhuf_decode_position( buffer, reader_ctx) - 1, LZHUF_BUFFER_SZ-1)
			j = val - 255 + LZHUF_THRESHOLD
			k = 0
			while ( k < j ) do
				val = reader_ctx.text_buf[ bit.band( i + k, LZHUF_BUFFER_SZ-1 ) ]
				decompressed_payload:append( ByteArray.new( string.format("%02X", val ) ))    -- add byte to output buffer
				reader_ctx.text_buf[ r ] = val 
				r = r + 1
				r = bit.band( r, LZHUF_BUFFER_SZ-1)
				count = count + 1
				k = k+1
			end
		end
	end
	
	-- Add TVB
	decompressed_tvb = decompressed_payload:tvb("Decompressed Payload")

	-- Call next dissector, if applicable
	if ( payload_format ~= nil ) then
		Dissector.get(payload_format):call( decompressed_tvb, pinfo, tree)
	end
	
	-- TODO: Cache result data
end

-- No protocol registration
