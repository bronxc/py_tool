import pefile

'''
@ror
@param
	val: val to be rotate right
	n: rotate right bit
	N: max bit of val 
@output
	rotate right value
'''
def ror(val,n,N):
	return ((val << (N - n))& 0xffffffff) | ((val >> n)& 0xffffffff)

'''
@get_hash
	get function's hash name by accumulate the value and ror 13 per character
@param 
	func_name: function name
@output 
	hash value
'''
def get_hash(func_name):
	digest = 0
	for x in func_name:
		digest = ror(digest, 7, 32) + ord(x)
	return digest

def get_pe_export_tbl(pe_path):
	pe = pefile.PE(pe_path)
	pe_out = open("pe_exp_tbl","w")
	for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
		pe_out.write(export.name+": "+hex(get_hash(export.name))+"\x0a\x0d") 
	pe_out.close()

def main():
	pe_path = "C:\\Windows\\System32\\kernel32.dll"
	get_pe_export_tbl(pe_path)

if __name__ == '__main__':
	main()
