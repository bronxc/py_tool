# \x31\xc9\xb9\x57  ==>> escape('%uc931%u57b9')

def byte2escape(dst_file, src_file):
	dst = open(dst_file,'w+')
	src = open(src_file,'r')
	content = src.read()
	rlt = 'unescape(\"'
	while len(content)%4:
		content += '\\xcc'
	for i in range(0,len(content)/8):
		rlt += "%u"
		rlt += content[i*8+6]
		rlt += content[i*8+7]
		rlt += content[i*8+2]
		rlt += content[i*8+3]
	rlt += '\")'
	dst.write(rlt)
	dst.close
	src.close

if __name__ == '__main__':
	from sys import argv
	if len(argv) < 3:
		print "\nUsage : python byte2escape.py fileName\n"
	else:
		byte2escape(argv[2],argv[1])


