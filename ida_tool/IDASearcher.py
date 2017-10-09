#-*-coding:utf-8-*-

import idaapi
import idc
import sys,time,IDAResolve
import re



class Searcher:

    def __init__(self):
        '''
            初始化类
        '''
        pass


    def get_seg_range_by_name(self,seg_name):
        '''
            获取指定名字的seg的范围
        '''
        start_addr = idc.FirstSeg()
        while start_addr != idaapi.BADADDR:
            end_addr = idc.SegEnd(start_addr)
            name = idc.SegName(start_addr)
            #print '%s : 0x%08x - 0x%08x'%(seg_name, start_addr, seg_end_addr)
            if name.lower() == seg_name.lower():
                return [start_addr,end_addr]
            start_addr = idc.NextSeg(start_addr)
        return None
    
    # potential function has only one or two Block
    # left side of assignment must be one of [r8,r9,rdx]
    # right side of assignment must be [reg+offset]
    def is_LOAD_64_G(self,function):
        if len(function.block_addr_list) > 2:
            return False
        
        pattern = re.compile(r'(mov|lea|movzx).*(r8d|r9d|rdx),.*\[r.*\+.*\]')
        for block_addr in function.block_addr_list:
            block = function.block_dict[block_addr] 
            is_load = False
            for i in range(0,len(block.disasm_list)):
                sasm_line = block.disasm_list[i]
                if sasm_line.mnemonics == 'call':
                    return False
                if pattern.match(sasm_line.disasm):
                    is_load = True
        return is_load
        
    # potential function has only one or two Block
    # call [this+offset]
    # indirect call indepent of [this]
    def is_INV_G(self,function):
        if len(function.block_addr_list) > 2:
            return False

        pattern = re.compile(r'(call|jmp).*cs:(__guard_check_icall_fptr|__guard_dispatch_icall_fptr)')
        for block_addr in function.block_addr_list:
            block = function.block_dict[block_addr] 
            for i in range(0,len(block.disasm_list)):
                sasm_line = block.disasm_list[i]
                #print sasm_line.disasm
                if sasm_line.mnemonics == 'call':
                    if pattern.match(sasm_line.disasm):
                        this_disam_list = block.disasm_list[:i]
                        this_disam_list = this_disam_list[::-1]
                        for this_sasm in this_disam_list:
                            if len(this_sasm.operands):
                                if this_sasm.operands[0] != 'rax':
                                    continue
                                elif 'rcx' in this_sasm.operands[1]:
                                    return True
                                else:
                                    return False
                    else:
                        return False
        return False
    
    def find_path_to(self,frm_node,to_node):
        def find_path_to_(frm_node,to_node, Visited):
          if frm_node in Visited:
            return None
          Visited.add(frm_node)
          if frm_node == to_node:
            return [frm_node]
          for addr in frm_node.sub_block_addr_list:
            node = frm_node.sub_block_dict[addr]
            l = find_path_to_(node,to_node, Visited)
            if l:
              l.append(frm_node)
              return l
          return None
        return find_path_to_(frm_node,to_node, set())
    
    
    # For every block check is there a closure path 
    def find_loop_blocks(self,function):
        loops_arr = []
        for block_addr in function.block_addr_list:
            block = function.block_dict[block_addr]
            for sub_block_addr in block.sub_block_addr_list:
                sub_block = block.sub_block_dict[sub_block_addr]
                loop_blocks = self.find_path_to(sub_block,block)
                if loop_blocks:
                    loops_arr.append(loop_blocks)
        loops_arr = set(tuple(sorted(x)) for x in loops_arr)
        return loops_arr  
    
    # potential function has blocks no more than 20
    # Looped basic block with an indirect call dependent on [this]
    # Use an conservative algrithm to find out all potential ML-G function 
    def is_ML_G(self,function):
        # Could decrease the threshold to reduce the potential function num
        if len(function.block_addr_list) > 20:
            return False
        
        pattern = re.compile(r'(call|jmp).*cs:(__guard_check_icall_fptr|__guard_dispatch_icall_fptr)')
        pattern_vt = re.compile(r'mov.*rax, \[rax\+.*\]')
        lp_arr = self.find_loop_blocks(function)
        for lp in lp_arr:
            if lp == None:
                return False
            # Could reduce the potential function num by enable this check
            # This check aimed to filter those have complicate loop blocks
            #elif len(lp) > 5:
            #    return False
            else:
                for block in lp:
                    is_only_call = False
                    #print "Block :",hex(block.start_ea),"->",hex(block.end_ea)
                    for i in range(0,len(block.disasm_list)):
                        sasm_line = block.disasm_list[i]
                        #print hex(head),":",GetDisasm(head)
                        if sasm_line.mnemonics == 'call':
                            is_only_call = False
                        if pattern.match(sasm_line.disasm):
                            this_disam_list = block.disasm_list[:i]
                            this_disam_list = this_disam_list[::-1]
                            for this_sasm in this_disam_list:
                                if len(this_sasm.operands):
                                    if this_sasm.operands[0] != 'rax':
                                        continue
                                    elif 'rax' in this_sasm.operands[1]:
                                        is_only_call = True
                if  is_only_call:
                    return True
        return False
    # potential function has only one or twoBlock
    # left side of assignment must be [this+offset]
    def is_ARITH_G(self,function):
        if len(function.block_addr_list) > 2:
            return False
            
        pattern = re.compile(r'(and|or|add|sub).*\[(rcx|rbx)\+.*\],.*')
        for block_addr in function.block_addr_list:
            block = function.block_dict[block_addr] 
            is_arith = False
            for i in range(0,len(block.disasm_list)):
                sasm_line = block.disasm_list[i]
                if sasm_line.mnemonics == 'call':
                    return False
                if pattern.match(sasm_line.disasm):
                    is_arith = True
        return is_arith 

    def is_function_ptr_G(self,function):
        if len(function.block_addr_list) > 20:
            return False
        pattern = re.compile(r'(call|jmp).*cs:(__guard_check_icall_fptr|__guard_dispatch_icall_fptr)')
        pattern2 = re.compile(r'(mov|lea).*rax, \[r.*\+.*\]')
        pattern3 = re.compile(r'mov.*r.*, \[r.{1,2}(\+0)?\]')
        for block_addr in function.block_addr_list:
            block = function.block_dict[block_addr] 
            for i in range(0,len(block.disasm_list)):
                sasm_line = block.disasm_list[i]
                #print sasm_line.disasm
                if sasm_line.mnemonics == 'call':
                    if sasm_line.operands[0] == 'rax':
                        return True
                    if pattern.match(sasm_line.disasm):
                        this_disam_list = block.disasm_list[:i]
                        this_disam_list = this_disam_list[::-1]
                        for j in range(0,len(this_disam_list)):
                            if pattern2.match(this_disam_list[j].disasm):
                                if 'rax' not in this_disam_list[j].operands[1]:
                                    for k in range(j,len(this_disam_list)):
                                        if pattern3.match(this_disam_list[k].disasm):
                                            return False
                                    return True
                                else:
                                    return False
                        return False
        return False
    
    def Find_ML_G(self, function):
        fp_mlg = open("ML_G.txt",'a+')
        if self.is_ML_G(function):
            fp_mlg.write(hex(function.start_address)+":"+function.function_name+"\n")
        fp_mlg.close()
        pass
    
    def Find_INV_G(self, function):
        fp_invg = open("INV_G.txt",'a+')
        if self.is_INV_G(function):
            fp_invg.write(hex(function.start_address)+":"+function.function_name+"\n")
        fp_invg.close()
        pass
        
    def Find_LOAD_64_G(self, function):
        fp_load64g = open("LOAD_R64_G.txt",'a+')
        if self.is_LOAD_64_G(function):
            fp_load64g.write(hex(function.start_address)+":"+function.function_name+"\n")
        fp_load64g.close()
        pass
        
    def Find_ARITH_G(self, function):
        fp_arithg = open("ARITH_G.txt",'a+')
        if self.is_ARITH_G(function):
            fp_arithg.write(hex(function.start_address)+":"+function.function_name+"\n")
        fp_arithg.close()
        pass
    
    def Find_function_ptr_G(self, function):
        fp_fptrg = open("fptr_G.txt",'a+')
        if self.is_function_ptr_G(function):
            print hex(function.start_address)+":"+function.function_name+"\n"
            fp_fptrg.write(hex(function.start_address)+":"+function.function_name+"\n")
        fp_fptrg.close()
        
    
    # Search all function 
    def Search_without_cfguard(self):
        
        
        print 'begin'
        seg_range = self.get_seg_range_by_name('.text')
        if seg_range == None:
            print 'seg name not exist'
            return
        
        seg_start_addr = seg_range[0]
        seg_end_addr = seg_range[1]
        function_address_list = []
        functions = Functions(seg_start_addr,seg_end_addr)
        
        for function_addr in functions:
            function_address_list.append(function_addr)
        
        for function_address in function_address_list:
            #解析function
            disasm_function = IDAResolve.DisasmFunction(function_address)
            disasm_function.resolve()

            #print 'function address: 0x%08x'%(function_address)
            
            self.Find_function_ptr_G(disasm_function)
            #print 'block address:'
            #self.Find_ML_G(disasm_function)
            #Find_INV_G(disasm_function)
            #Find_LOAD_64_G(disasm_function)
                
        print 'Done'
        
        
    # Only Search function that can bypass cfg check    
    def Search_with_cfguard(self,cfg_valid_file):
        print 'begin'
        function_address_list = []    
        fp = open(cfg_valid_file,'r')
        for line in fp.readlines():
            function_addr = int(line.slice(': ')[1][:-1],16)
            function_address_list.append(function_addr)
        
        for function_address in function_address_list:

            #解析function
            disasm_function = IDAResolve.DisasmFunction(function_address)
            disasm_function.resolve()

            print 'function address: 0x%08x'%(function_address)
            #print 'block address:'
            self.Find_ML_G(disasm_function)
            #Find_INV_G(disasm_function)
            #Find_LOAD_64_G(disasm_function)
                
        print 'Done'

    def testFunc(self):
        disasm_function = IDAResolve.DisasmFunction(ScreenEA())
        disasm_function.resolve()
        print disasm_function.function_name
        return self.is_function_ptr_G(disasm_function)
        
    
    def start(self):
        '''
            开始测试类
        '''
        self.Search_without_cfguard()
        #self.testFunc();



if __name__ == '__main__':
    '''
        start function
    '''
    ser = Searcher()
    ser.start()

