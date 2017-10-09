# Anlysis WASM File
#

import os
import sys

SUCCESS = True
FAILED = False
PLACEHOLDER = 0xffffffff
LastKnownSection = 0xB

LanguageTypes ={ '\x7f':'I32', '\x7e':'I64', '\x7d':'F32', '\x7c':'F64','\x40':'Empty','\x70':'anyfunc','\x60':'fun'}

SectionInfoAll = ["custom","type","import","function","table","memory","global","export","start","element","code","data","name"]

OpCodeMap = {'\x00':'Unreachable',\
'\x01':'Nop',\
'\x02':'Block',\
'\x03':'Loop',\
'\x04':'If',\
'\x05':'Else',\
'\x0b':'End',\
'\x0c':'Br',\
'\x0d':'BrIf',\
'\x0e':'BrTable',\
'\x0f':'Return',\
'\x10':'Call',\
'\x11':'CallIndirect',\
'\x1a':'Drop',\
'\x1b':'Select',\
'\x20':'GetLocal',\
'\x21':'SetLocal',\
'\x22':'TeeLocal',\
'\x23':'GetGlobal',\
'\x24':'SetGlobal',\
'\x28':'I32LoadMem',\
'\x29':'I64LoadMem',\
'\x2a':'F32LoadMem',\
'\x2b':'F64LoadMem',\
'\x2c':'I32LoadMem8S',\
'\x2d':'I32LoadMem8U',\
'\x2e':'I32LoadMem16S',\
'\x2f':'I32LoadMem16U',\
'\x30':'I64LoadMem8S',\
'\x31':'I64LoadMem8U',\
'\x32':'I64LoadMem16S',\
'\x33':'I64LoadMem16U',\
'\x34':'I64LoadMem32S',\
'\x35':'I64LoadMem32U',\
'\x36':'I32StoreMem',\
'\x37':'I64StoreMem',\
'\x38':'F32StoreMem',\
'\x39':'F64StoreMem',\
'\x3a':'I32StoreMem8',\
'\x3b':'I32StoreMem16',\
'\x3c':'I64StoreMem8',\
'\x3d':'I64StoreMem16',\
'\x3e':'I64StoreMem32',\
'\x3f':'CurrentMemory',\
'\x40':'GrowMemory',\
'\x41':'I32Const',\
'\x42':'I64Const',\
'\x43':'F32Const',\
'\x44':'F64Const',\
'\x45':'I32Eqz',\
'\x46':'I32Eq',\
'\x47':'I32Ne',\
'\x48':'I32LtS',\
'\x49':'I32LtU',\
'\x4a':'I32GtS',\
'\x4b':'I32GtU',\
'\x4c':'I32LeS',\
'\x4d':'I32LeU',\
'\x4e':'I32GeS',\
'\x4f':'I32GeU',\
'\x50':'I64Eqz',\
'\x51':'I64Eq',\
'\x52':'I64Ne',\
'\x53':'I64LtS',\
'\x54':'I64LtU',\
'\x55':'I64GtS',\
'\x56':'I64GtU',\
'\x57':'I64LeS',\
'\x58':'I64LeU',\
'\x59':'I64GeS',\
'\x5a':'I64GeU',\
'\x5b':'F32Eq',\
'\x5c':'F32Ne',\
'\x5d':'F32Lt',\
'\x5f':'F32Le',\
'\x5e':'F32Gt',\
'\x60':'F32Ge',\
'\x61':'F64Eq',\
'\x62':'F64Ne',\
'\x63':'F64Lt',\
'\x65':'F64Le',\
'\x64':'F64Gt',\
'\x66':'F64Ge',\
'\x67':'I32Clz',\
'\x68':'I32Ctz',\
'\x69':'I32Popcnt',\
'\x6a':'I32Add',\
'\x6b':'I32Sub',\
'\x6c':'I32Mul',\
'\x6d':'I32DivS',\
'\x6e':'I32DivU',\
'\x6f':'I32RemS',\
'\x70':'I32RemU',\
'\x71':'I32And',\
'\x72':'I32Or',\
'\x73':'I32Xor',\
'\x74':'I32Shl',\
'\x75':'I32ShrS',\
'\x76':'I32ShrU',\
'\x77':'I32Rol',\
'\x78':'I32Ror',\
'\x79':'I64Clz',\
'\x7a':'I64Ctz',\
'\x7b':'I64Popcnt',\
'\x7c':'I64Add',\
'\x7d':'I64Sub',\
'\x7e':'I64Mul',\
'\x7f':'I64DivS',\
'\x80':'I64DivU',\
'\x81':'I64RemS',\
'\x82':'I64RemU',\
'\x83':'I64And',\
'\x84':'I64Or',\
'\x85':'I64Xor',\
'\x86':'I64Shl',\
'\x87':'I64ShrS',\
'\x88':'I64ShrU',\
'\x89':'I64Rol',\
'\x8a':'I64Ror',\
'\x8b':'F32Abs',\
'\x8c':'F32Neg',\
'\x8d':'F32Ceil',\
'\x8e':'F32Floor',\
'\x8f':'F32Trunc',\
'\x90':'F32NearestInt',\
'\x91':'F32Sqrt',\
'\x92':'F32Add',\
'\x93':'F32Sub',\
'\x94':'F32Mul',\
'\x95':'F32Div',\
'\x96':'F32Min',\
'\x97':'F32Max',\
'\x98':'F32CopySign',\
'\x99':'F64Abs',\
'\x9a':'F64Neg',\
'\x9b':'F64Ceil',\
'\x9c':'F64Floor',\
'\x9d':'F64Trunc',\
'\x9e':'F64NearestInt',\
'\x9f':'F64Sqrt',\
'\xa0':'F64Add',\
'\xa1':'F64Sub',\
'\xa2':'F64Mul',\
'\xa3':'F64Div',\
'\xa4':'F64Min',\
'\xa5':'F64Max',\
'\xa6':'F64CopySign',\
'\xa7':'I32Wrap_I64',\
'\xa8':'I32TruncS_F32',\
'\xa9':'I32TruncU_F32',\
'\xaa':'I32TruncS_F64',\
'\xab':'I32TruncU_F64',\
'\xac':'I64ExtendS_I32',\
'\xad':'I64ExtendU_I32',\
'\xae':'I64TruncS_F32',\
'\xaf':'I64TruncU_F32',\
'\xb0':'I64TruncS_F64',\
'\xb1':'I64TruncU_F64',\
'\xb2':'F32SConvertI32',\
'\xb3':'F32UConvertI32',\
'\xb4':'F32SConvertI64',\
'\xb5':'F32UConvertI64',\
'\xb6':'F32DemoteF64',\
'\xb7':'F64SConvertI32',\
'\xb8':'F64UConvertI32',\
'\xb9':'F64SConvertI64',\
'\xba':'F64UConvertI64',\
'\xbb':'F64PromoteF32',\
'\xbc':'I32ReinterpretF32',\
'\xbd':'I64ReinterpretF64',\
'\xbe':'F32ReinterpretI32',\
'\xbf':'F64ReinterpretI64',\
'\xf0':'PrintFuncName',\
'\xf1':'PrintArgSeparator',\
'\xf2':'PrintBeginCall',\
'\xf3':'PrintNewLine',\
'\xf4':'PrintEndCall',\
'\xfc':'PrintI32',\
'\xfd':'PrintI64',\
'\xfe':'PrintF32',\
'\xff':'PrintF64',}

class Header:
    def __init__(self):
        self.m_section_id = PLACEHOLDER
        self.m_section_size = PLACEHOLDER
        self.m_section_name = ''
        self.m_start = PLACEHOLDER
        self.m_end = PLACEHOLDER

class Limit:
    def __init__(self):
        self.m_flag = PLACEHOLDER
        self.m_initial = PLACEHOLDER
        self.m_maxmium = PLACEHOLDER

class Signature:
    def __init__(self):
        self.m_form = PLACEHOLDER
        self.m_param_count = PLACEHOLDER
        self.m_params = [] 

def print_section_header(header):
    print header.m_section_id.encode('hex') + '  ' + header.m_section_name
    print hex(header.m_section_size) + '  ' + ' Section Size'  

class Reader:

    def __init__(self, file, size):
        self.m_file = file
        self.m_start = 0
        self.m_end = self.m_start + size
        self.m_pc = self.m_start
        self.m_current_section = 0

    def end_of_module(self):
        return (self.m_pc >= self.m_end)

    def read_next(self):
        byte = self.m_file.read(1)
        self.m_pc += 1
        if not byte:
            print "some thing error at read_next!!"
            sys.exit()
        return byte

    def read_bytes(self, byte_len):
        bytes_ = self.m_file.read(byte_len)
        self.m_pc += byte_len
        if not bytes_:
            print "some thing error at read_bytes!!"
            sys.exit()
        return bytes_

    def read_uint7(self):
        byte_ =  self.read_next()
        return ord(byte_) & 0x7f

    def read_float(self):
        self.m_pc+=4
        return self.m_file.read(4)

    def read_double(self):
        self.m_pc +=8
        return self.m_file.read(8)

    def read_len128(self):
        len_  = 0
        shamt = 0
        for i in range(0,5):
            b = self.read_next()
            byte = ord(b)
            len_ = len_ | ((byte&0x7f) << shamt)
            if (byte&0x80) == 0:
                break
            shamt+=7
        if byte & 0x80 :
            print "some thing error at read_len128 !!"
            sys.exit()
        return len_

    def read_len128_64(self):
        len_  = 0
        shamt = 0
        for i in range(0,10):
            byte = ord(self.read_next())
            len_ = len_ | ((byte&0x7f) << shamt)
            if (byte&0x80) == 0:
                break
            shamt+=7
        if byte & 0x80 :
            print "some thing error at read_len128_64!!" 
            sys.exit()
        return len_

    def read_type(self):
        byte = self.read_next()

    def read_string(self):
        name_length = self.read_len128()
        name = ''
        if name_length > 100000:
            print "some thing error at read_string!!"
            sys.exit()
        for i in range(0,name_length):
            byte = self.read_next()
            name += byte
        # print 
        print hex(self.m_pc) + "  " + hex(name_length) + '  ' + 'string length'
        print hex(self.m_pc) + "  " + name.encode('hex') + '   ' + name
        return name 

    def read_section_header(self):
        header = Header() 
        section_id = self.read_uint7()
        header.m_section_id = chr(section_id)
        if section_id > LastKnownSection:
            print "some thing error at read_section_header!!"
            sys.exit()
        header.m_section_size = self.read_len128()
        header.m_section_name = SectionInfoAll[section_id]
        # print
        print_section_header(header)
        return header

    def read_next_section(self):
        if self.end_of_module():
            return False
        self.m_current_section = self.read_section_header()
        section_id = self.m_current_section.m_section_id
        if section_id == '\x01':
            self.read_type_section()
        elif section_id == '\x02':
            self.read_import_section()
        elif section_id == '\x03':
            self.read_function_signature_section()
        elif section_id == '\x04':
            self.read_table_section(False)
        elif section_id == '\x05':
            self.read_memory_section(False)
        elif section_id == '\x06':
            self.read_global_section()
        elif section_id == '\x07':
            self.read_export_section()
        elif section_id == '\x08':
            self.read_start_function()
        elif section_id == '\x09':
            self.read_element_section()
        elif section_id == '\x0a':
            self.read_function_section()
        elif section_id == '\x0b':
            self.read_data_section()
        elif section_id == '\x0c':
            self.read_name_section()
        elif section_id == '\x00':
            self.read_custom_section()
        return True


    def read_wasm_header(self):
        file_magic = self.read_bytes(4);
        file_version = self.read_bytes(4);
        if file_magic != '\x00\x61\x73\x6d' or file_version != '\x01\x00\x00\x00':
            print "some thing error!!"
            return FAILED
        #print 
        print hex(self.m_pc) + "  " + file_magic.encode('hex') + '    ' + "File Magic 'asm'"
        print hex(self.m_pc) + "  " + file_version.encode('hex') + '    ' + 'File Version 1'
        return SUCCESS 

    def read_type_section(self):
        #print
        print "; section 'Type' (1)"
        num = self.read_len128()
        if num > 1000000:
            print "some thing error at read_type_section!!"
            sys.exit()
        #print
        print hex(self.m_pc) + "  " + hex(num) + '   ' + "number of type"
        for i in range(0, num):
            print ";type  " + str(i)
            form = self.read_next()
            param_count = self.read_len128()
            params = []
            for j in range(0, param_count):
                param_type = self.read_next()
                wasm_type = LanguageTypes.get(param_type)
                params.append([param_type, wasm_type])
            result_count = self.read_len128()
            if result_count > 1:
                print "some thing error at read_type_section!!"
                sys.exit()
            if result_count == 1:
                result_type = self.read_next()
                result_wasm_type = LanguageTypes.get(result_type)
            ## print
            print hex(self.m_pc) + "  " + form.encode('hex') + '   ' +  'func'
            print hex(self.m_pc) + "  " + hex(param_count) + '   ' + 'params number'
            for p in params:
                print hex(self.m_pc) + "  " + p[0].encode('hex') + '   ' + p[1]
            print hex(self.m_pc) + "  " + str(result_count) + '    ' + "result number"
            if result_count == 1:
                print hex(self.m_pc) + "  " + result_type.encode('hex')  + '   ' #+ result_wasm_type

    def read_import_section(self):
        # print
        print "; section 'Import' (2)"
        num = self.read_len128()
        if num > 1000000:
            print "some thing error at read_import_section!!"
            sys.exit()
        #print 
        print hex(self.m_pc) + "  " + hex(num) + '  ' + "number of import"
        for i in range(0, num):
            print ";Import item  " + str(i)
            mod_name = self.read_string()
            func_name = self.read_string()
            kind = self.read_next()
            if kind == '\x00':  # Function
                sigId = self.read_len128()
                #print 
                print hex(self.m_pc) + "  " + str(sigId) + '  ' + "signature ID"
            elif kind == '\x03': # Global
                global_type = self.read_next()
                global_wasm_type = LanguageTypes.get(global_type)
                global_mutable = self.read_next()
                # print 
                print hex(self.m_pc) + "  " + hex(global_type) + '  ' + global_wasm_type
                print hex(self.m_pc) + "  " + global_mutable.encode('hex') + '  ' + 'mutable'
            elif kind == '\x01':  #Table
                self.read_table_section(True)
            elif kind == '\x02':  # Memory
                self.read_memory_section(True)
            else:
                print  "some thing error!!"

    def read_function_signature_section(self):
        # print
        print "; section 'Function' (3)"
        num = self.read_len128()
        if num > 1000000:
            print "some thing error at read_function_signature_section!!"
            sys.exit()
        function_siges = []
        for i in range(0, num):
            sig_index = self.read_len128()
            function_siges.append(sig_index)
        #print
        print  hex(self.m_pc) + "  " + hex(num) + '   ' + 'Function signature number'
        for f in function_siges:
            print hex(self.m_pc) + "  " + str(f) + '  ' + 'signature index'

    def read_function_section(self):
        # print
        print "; section 'Code' (10)"
        num = self.read_len128()
        # print 
        print  hex(self.m_pc) + "  " + hex(num) + '   ' + 'Function number'
        if num > 1000000:
            print "some thing error at read_function_section!!"
            sys.exit()
        function_sizes = []
        for i in range(0, num):
            print "; function body " + str(i)
            func_size = self.read_len128()
            # print 
            print hex(self.m_pc) + "  " + str(func_size) + '  ' + 'function body size'
            if func_size > 128 * 1024:
                print "some thing error at read_function_section!!"
                sys.exit()
            function_sizes.append(func_size)
            self.read_function_body()

    def read_export_section(self):
        # print
        print "; section \"Export\" (7)"
        num = self.read_len128()
        #print 
        print hex(self.m_pc) + "  " + str(num) + '  ' + "export number "
        if num > 1000000:
            print "some thing error at read_export_section!!"
            sys.exit()
        exports = []
        for i in range(0, num):
            print "; export item" + str(i)
            export_name = self.read_string()
            kind = self.read_next()
            index = self.read_len128()
            if kind == '\x00':
                type_ = 'Function'
            elif kind == '\x02':
                type_ = 'Memory'
            elif kind == '\x01':
                type_ = 'Table'
            elif kind == '\x03':
                type_ = 'Global'
            else:
                print "some thing error at read_export_section!!"
                sys.exit()
            #print 
            print hex(self.m_pc) + "  " + kind.encode('hex')+ '   ' + "export kind : " + type_
            print hex(self.m_pc) + "  " + str(index) + '   ' + 'export ' + type_ + ' index'
            #exports.append([kind,type_,index])

        

    def read_start_function(self):
        # print
        print "; section \"Start\" (8)"
        id_ = self.read_len128()
        #print
        print hex(self.m_pc) + "  " + id_ + '   ' + "Start Function index"

    def read_memory_section(self, is_import):
        # print
        print "; section \"Memory\" (5)"
        if is_import:
            count =1
        else:
            count = self.read_len128()
        if count >1 :
            print "some thing error at read_memory_section!!"
            sys.exit()
        if count == 1:
            mem_limit = self.read_section_limits(100000,100000)
        # print
        print hex(self.m_pc) + "  " + str(count) + '    ' + 'memory count' 
        print "; memory 0"
        print hex(self.m_pc) + "  " + str(mem_limit.m_flag) + "  " + "memory flag"
        print hex(self.m_pc) + "  " + str(mem_limit.m_initial) + '  ' + "memory limit inital size"
        if mem_limit.m_maxmium != PLACEHOLDER:
            print hex(self.m_pc) + "  " + str(mem_limit.m_maxmium) + '  ' + 'memory limit maximum size'

    def read_table_section(self, is_import):
        # print
        print "; section \"Table\" (4)"
        if is_import:
            entries =1
        else:
            entries = self.read_len128()
        if entries >1 :
            print "some thing error at read_table_section!!"
            sys.exit()
        if entries == 1:
            ele_type = self.read_next()
            if ele_type != '\x70':
                print "some thing error at read_table_section!!"
                sys.exit()
            table_limit = self.read_section_limits(100000,100000)
        # print 
        print hex(self.m_pc) + "  " + str(entries) + '    ' + 'table entries num' 
        print "; table 0"
        print hex(self.m_pc) + "  " + ele_type.encode('hex') + '   ' + 'anyfunc'
        print hex(self.m_pc) + "  " + str(table_limit.m_flag) + "  " + "table flag"
        print hex(self.m_pc) + "  " + str(table_limit.m_initial) + '  ' + "table limit inital size"
        if table_limit.m_maxmium != PLACEHOLDER:
            print hex(self.m_pc) + "  " + str(table_limit.m_maxmium) + '  ' + 'table limit maximum size'

        # ??????
    def read_data_section(self):
        # print
        print "; section \"Data\" (11)"
        num = self.read_len128()
        # print
        print hex(self.m_pc) + "  " + str(num) + '    ' + "segments number"
        if num > 1000000:
            print "some thing error at read_data_section!!"
            sys.exit()
        for i in range(0, num):
            index = self.read_len128()
            # print
            print hex(self.m_pc) + "  " + str(index) + '    ' + "index "
            self.read_init_expr()
            data_byte_len = self.read_len128()
            data = self.read_bytes(data_byte_len)
            # print
            print hex(self.m_pc) + "  " + str(data_byte_len) + '    ' + "data byte len"
            print hex(self.m_pc) + "  " + data.encode('hex') + '    ' + 'data'

    # ?????????
    def read_element_section(self):
        print "; section 'Elem' (9)"
        num = self.read_len128()
        # print
        print hex(self.m_pc) + "  " + str(num) + '    ' + "segments number"
        if num > 1000000:
            print "some thing error at read_element_section!!"
            sys.exit()
        elements = []
        for i in range(0, num):
            print "; elem segment header  " + str(i)
            table_index =self.read_len128()
            # print
            print hex(self.m_pc) + "  " + str(table_index) + '    ' + "Table index "
            self.read_init_expr()
            function_num = self.read_len128()
            print hex(self.m_pc) + "  " + str(function_num) + '    ' + "num function indices"
            for j in range(0, function_num):
                function_index = self.read_len128()
                # print
                print hex(self.m_pc) + "  " + str(function_index) + '    ' + "Function index"

    def read_name_section(self):
        # print
        print "; section \"Name\" (12)"
        num_func_names = self.read_len128()
        # print
        print hex(self.m_pc) + "  " + str(num_func_names) + '    ' + "function name number"
        if num_func_names > 1000000:
            print "some thing error at read_name_section!!"
            sys.exit()
        for i in range(0, num_func_names):
            name = self.read_string()
            local_name_num = self.read_len128()
            # print
            print hex(self.m_pc) + "  " + str(local_name_num) + '    ' + 'local name number'
            for j in range(0, local_name_num):
                local_name = self.read_string()

    # ????????
    def read_global_section(self):
        #print
        print "; section 'Global' (6)" 
        num_global = self.read_len128()
        # print
        print hex(self.m_pc) + "  " + str(num_global) + '    ' + "global varible number"
        if num_global > 1000000:
            print "some thing error at read_global_section!!"
            sys.exit()
        for i in range(0, num_global):
            print "; Global varibale  " + str(i)
            global_type = self.read_next()
            global_mutable = self.read_next()
            # print 
            print hex(self.m_pc) + "  " + global_type.encode('hex') + '    ' + 'global variable type'
            print hex(self.m_pc) + "  " + global_mutable.encode('hex') + '   ' + 'global variable mutability'
            self.read_init_expr()

    # Reserved
    def read_custom_section(self):
        custom_data = self.m_file.read()

    def read_function_body(self):
        local_entries = self.read_len128()
        entries = []
        for i in range(0, local_entries):
            local_type_count = self.read_len128()
            local_type = self.read_next()
            entries.append([local_type_count, local_type])
        # print 
        print hex(self.m_pc) + "  " + str(local_entries) + '    ' + "local decl count"
        for e in entries:
            print hex(self.m_pc) + "  " + str(e[0]) + '   ' + "local type count"
            print hex(self.m_pc) + "  " + e[1].encode('hex') + '    ' + "type"
        self.read_block()
        #while True:
            #op = self.read_expr()
            #if op == '\x0b':
                #break;

    def read_block(self):
        while True:
            op = self.read_expr()
            if op == '\x0b':
                break
            self.emit_expr(op)

    def emit_expr(self, op):
        if op in ['\x02','\x03','\x04']:  # if loop block 
            self.read_block()

    def read_expr(self):
        op = self.read_next()
        #print 
        print hex(self.m_pc) + "  " + op.encode('hex') + '   ' + OpCodeMap.get(op)
        if op in ['\x02','\x03','\x04']:
            self.block_node()
        elif op in ['\x10']:
            self.call_node()
        elif op in ['\x11']:
            self.call_indirect_node()
        elif op in ['\x0c','\x0d']:
            self.br_node()
        elif op in ['\x0e']:
            self.br_table_node()
        elif op in ['\x41']:
            self.const_node('I32')
        elif op in ['\x42']:
            self.const_node('I64')
        elif op in ['\x43']:
            self.const_node('F32')
        elif op in ['\x44']:
            self.const_node('F64')
        elif op in ['\x20','\x21','\x22','\x23','\x24']:
            self.var_node()
        elif op in ['\x28','\x29','\x2a','\x2b','\x2c','\x2d','\x2e','\x2f','\x30','\x31','\x32','\x33','\x34','\x35','\x36','\x37','\x38','\x39','\x3a','\x3b','\x3c','\x3d','\x3e']:
            self.mem_node()
        elif op in ['\x3f','\x40']:
            reserve = self.read_next()
            #print 
            print  hex(self.m_pc) + "  " + reserve.encode('hex') + '  ' + "Reserved"
        return op

    def read_init_expr(self):
        node_op = self.read_expr()
        op = self.read_expr()
        if op != '\x0b':
            print "some thing error at read_init_expr!!"
            sys.exit()

    def block_node(self):
        block_type = self.read_next()
        #print 
        print hex(self.m_pc) + "  " + block_type.encode('hex') + '   ' + "Block type " + LanguageTypes.get(block_type)

    def br_node(self):
        len_ = self.read_len128()
        #print 
        print hex(self.m_pc) + "  " + str(len_) + '    ' + 'len '

    def call_node(self):
        func_num = self.read_len128()
        #print 
        print hex(self.m_pc) + "  " + str(func_num) + '   ' + "call index"

    def call_indirect_node(self):
        func_num = self.read_len128()
        reserve = self.read_next()
        #print
        print hex(self.m_pc) + "  " + str(func_num) + '   ' + 'indirect call index'
        print hex(self.m_pc) + "  " + reserve.encode('hex') + '   ' + 'Reserved Value'

    #???????
    def br_table_node(self):
        num_targets = self.read_len128()
        target_table = []
        for i in range(0, num_targets):
            target = self.read_len128()
            target_table.append(target)
        default_target = self.read_len128()
        #print 
        print hex(self.m_pc) + "  " + str(num_targets) + '    ' + " number of target"
        for t in target_table:
            print hex(self.m_pc) + "  " + str(t) + '    ' + 'target'
        print hex(self.m_pc) + "  " + str(default_target) + '   ' + 'default target'

    def mem_node(self):
        flags = self.read_len128()
        offset = self.read_len128()
        #print 
        print hex(self.m_pc) + "  " + str(flags) + '    ' + "memory flags"
        print hex(self.m_pc) + "  " + str(offset) + '   '  + "memory offset"  

    def var_node(self):
        num = self.read_len128()
        print hex(self.m_pc) + "  " + str(num) + '   ' + "var index"

    def const_node(self, localType):
        if localType == 'I32':
            const_value = self.read_len128()
        elif localType == 'I64':
            const_value = self.read_len128_64()
        elif local_value == 'F32':
            const_value = self.read_float()
        elif local_value == 'F64':
            const_value = self.read_double()
        #print
        print hex(self.m_pc) + "  " + str(const_value) + '   ' + "Const value"


    def read_section_limits(self, max_initial, max_maxmium):
        limit = Limit()
        flag = self.read_len128()
        limit.m_flag = flag
        limit.m_initial = self.read_len128()
        limit.m_maximum = max_maxmium
        if (flag & 0x01) > 0:
            limit.m_maxmium = self.read_len128()
            if limit.m_maxmium > max_maxmium:
                print "some thing error!!"
        if limit.m_initial > max_initial:
            print "some thing error!!"
        return limit

def Usage():
    print "Usage:"
    print "\t parser.py file.wasm"

def main(argc,argv):
    if argc <1:
        file_size = os.path.getsize("test.wasm")
        file_handle = open("test.wasm","rb")
    else:
        file_size = os.path.getsize(argv[0])
        file_handle = open(argv[0],"rb")

    wasm_reader = Reader(file_handle, file_size)
    wasm_reader.read_wasm_header()

    while True:
       if not wasm_reader.read_next_section():
            break

    print hex(file_size)


if __name__ == "__main__":
    main(len(sys.argv)-1,sys.argv[1:])

