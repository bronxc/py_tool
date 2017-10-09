import re
import idaapi

start = SelStart()
end = SelEnd()

if start != BADADDR:
    #print "%x, %x" % (start, end)
    
    print 'struct __declspec(uuid("00000000-0000-0000-0000-000000000000")) Interface : IUnknown {'
    
    while start < end:
        ofs = Qword(start)
        print "    // 0x%x" % ofs
        name = Demangle(Name(ofs), GetLongPrm(INF_LONG_DN))
        name = re.sub(r'[A-Za-z0-9_]+::', r'', name)
        name = re.sub(r'^public: ', r'', name)
        name = re.sub(r'^virtual long', r'virtual HRESULT', name)
        name = re.sub(r'unsigned short const \*', r'const wchar_t *', name)
        name = re.sub(r'unsigned short \*', r'wchar_t *', name)
        print "    %s = 0;" % name
        
        start += 8
        
    print '};'
else:
    print "Please select vtable range to export"
            

