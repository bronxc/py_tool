import struct
import binascii
import string

'''
@convert_b2x 
	convet binary file to hex bytes
	text  => \x74\x65\x78\x74
@param 
	src: source binary file
	dst: hex bytes file
'''
def convert_b2x(src, dst):
	file_in = open(src, "rb")
	file_out = open(dst, "wb")

	file_buff = file_in.read()

	file_buff_dec = "\""
	line_len = 0

	for byte in file_buff:
		line_len = line_len + 1
		file_buff_dec = file_buff_dec + '\\x' + binascii.hexlify(byte)
		if line_len == 0x10:
			line_len = 0
			file_buff_dec = file_buff_dec + '\"\x0d\"'

	file_out.write(file_buff_dec)
	file_in.close()
	file_out.close()

'''
@convert_b2t
	convert binary file to hex byte string
	text  => 74657874
@param
	src: source binary file
	dst: hex byte string file
'''
def convert_b2t(src, dst):
	file_in = open(src, "rb")
	file_out = open(dst, "wb")

	file_buff = file_in.read()

	file_buff_dec = ""
	line_len = 0

	for byte in file_buff:
		file_buff_dec = file_buff_dec + binascii.hexlify(byte)

	file_out.write(file_buff_dec)
	file_in.close()
	file_out.close()

'''
@convert_b2d
	convert binary file to dword number
	text  => 0x74786574  => 1954047348
@param
	src: source binary file
	dst: dword numbers file
'''
def convert_b2d(src,dst):
	file_in = open(src, "rb")
	file_out = open(dst, "wb")

	file_buff = file_in.read()
	while len(file_buff)%4:
		file_buff += '\xcc'
	dword_num = len(file_buff)/4

	dword_vec = struct.unpack('I'*dword_num,file_buff)
	

	for x in dword_vec:
		file_out.write(str(x)+'\n')

	file_in.close()
	file_out.close()

'''
@convert_b2w
	convert binary file to dword number
	text  => 0x74786574  => 1954047348
@param
	src: source binary file
	dst: dword numbers file
'''
def convert_t2dw(src):

	while len(src)%4:
		src += '\x00'
	dword_num = len(src)/4
	dword_vec = struct.unpack('@'+'I'*dword_num,src);

	for x in dword_vec:
		print '0x%0.8x' % x

def convert_t2b(src, dst):
        file_in = open(src, "rb")
	file_out = open(dst, "wb")
        while len()
        file_in.close()
	file_out.close()

def main():
	#src = input("src file path:")
	#dst = input("dst file path:")
	src = 'aa.txt'
	dst = 'aaa.txt' 
	text = 'FlsGetValue'
	convert_b2t(src,dst)



if __name__ == '__main__':
	main()
