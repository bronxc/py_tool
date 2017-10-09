#-*-coding:utf-8-*-

import idaapi
import idc
import sys,time




class DisasmLine:
    '''
        表示一条disasm的对象
    '''
    def __init__(self,address):
        #整条汇编指令
        self.disasm = idc.GetDisasm(address)
        #当前汇编指令的地址
        self.address = address
        #汇编代码的二进制长度
        self.size = idc.ItemSize(address)
        #汇编代码的助记符
        self.mnemonics = idc.GetMnem(address)
        #操作数数量
        self.operands_size = 0
        #操作数列表
        self.operands = []
        #操作数类型
        self.operands_type = []
        #立即操作数的值
        self.operands_value = []
        #初始化操作数相关的信息
        self.get_all_operand_info()



    def get_all_operand_info(self):
        '''
            初始化前地址的汇编语句中所有的操作数相关的信息
        '''
        for i in range(0,3):
            opend = idc.GetOpnd(self.address,i)
            if len(opend)>0:
                self.operands.append(opend)
                self.operands_type.append(idc.GetOpType(self.address,i))
                self.operands_value.append(idc.GetOperandValue(self.address,i))
        self.operands_size = len(self.operands)



    def print_info(self,leve=0):
        '''
            格式化输出汇编语句信息
            leve : 0 | 1  为0则表示为最小化输出，为1则表示为最大化输出
        '''
        print_string  = '  |- %s\n'%(self.disasm)
        print_string += '  |- address        : 0x%08x\n'%(self.address)
        if leve >= 1:
            print_string += '  |- size           : %d\n'%(self.size)
            print_string += '  |- mnemonics      : %s\n'%(self.mnemonics)
            print_string += '  |- operands_size  : %d\n'%(self.operands_size)
            print_string += '  |- operands       : %s\n'%(','.join(self.operands))
            print_string += '  |- operands_type  : '
            test_string = ''
            for item in self.operands_type:
                test_string += str(item) + ','
            print_string += test_string[:-1]
            print_string += '\n'
            print_string += '  |- operands_value : '
            test_string = ''
            for item in self.operands_value:
                test_string += '0x%08x,'%(item)
            print_string += test_string[:-1]
            print_string += '\n'
        print print_string





class DisasmBlock:
    '''
        多条汇编语句形成一个Block
    '''
    def __init__(self):
        '''
            初始化
        '''
        #当前块的汇编语句对象列表
        self.disasm_list = []
        #当前块的开始地址
        self.start_address = 0
        #当前块的结束地址
        self.end_address = 0
        #当前块的汇编语句数量
        self.disasm_len = 0
        #当前块的二进制长度
        self.size = 0
        #表示当前块后分支的左子块和右子块
        self.left_child_block = None
        self.right_child_block = None



    def add_disasm(self,disasm_line):
        '''
            在当前块中增加汇编指令
        '''
        self.disasm_list.append(disasm_line)



    def del_disasm(self,disasm_line):
        '''
            在当前块中删除汇编指令
        '''
        if disasm_line in self.disasm_list:
            self.disasm_list.remove(disasm_line)



    def update(self):
        '''
            刷新当前块的属性
        '''
        min_addr = 0xffffffff
        max_addr = 0
        for disasm_line in self.disasm_list:
            if min_addr>disasm_line.address:
                min_addr = disasm_line.address
            if max_addr<disasm_line.address:
                max_addr = disasm_line.address
            self.size += disasm_line.size
        self.start_address = min_addr
        self.end_address = max_addr + self.disasm_list[-1].size
        self.disasm_len = len(self.disasm_list)





class DisasmFunction:
    '''
        用来描述反汇编块形成的树结构,表示函数体内部的不同流程
    '''
    def __init__(self,address):
        '''
            初始化代码树，从指定地址处开始将代码组织为block形成的树
        '''
        self.block_dict = {}
        self.block_addr_list = []
        self.start_address = address
        self.end_address = 0
        self.root_block = None
        self.function_name = idaapi.get_func_name(address)

        #保存函数参数大小的值
        self.function_parameter_size = 0



    def get_all_disasm_line(self):
        '''
            获取当前函数的所有汇编行
        '''
        disasm_list = []
        for block in self.block_dict.values():
            disasm_list += block.disasm_list
        return disasm_list



    def get_all_block_list(self):
        '''
            获取当前函数的所有代码块
        '''
        return self.block_dict.values()



    def get_block(self,address):
        '''
            根据指定的地址返回一个汇编块
        '''
        block = DisasmBlock()
        while True:
            disasm_line = DisasmLine(address)
            if len(disasm_line.mnemonics) <= 0:
                return None
            if (disasm_line.mnemonics[0] == 'j') or \
               (disasm_line.mnemonics == 'retn') or \
               (disasm_line.mnemonics == 'retf') or \
               (disasm_line.mnemonics == 'int'):
                #跳转代码
                block.add_disasm(disasm_line)
                break
            else:
                #为块内代码
                block.add_disasm(disasm_line)
            address += disasm_line.size
        block.update()
        return block



    def resolve_all_block_by_function(self):
        '''
            获取当前函数所有的block
        '''
        resolve_address_list = [self.start_address]
        while len(resolve_address_list)>0:
            resolve_address = resolve_address_list[0]
            del resolve_address_list[0]

            if resolve_address in self.block_addr_list:
                continue

            block = self.get_block(resolve_address)
            if block != None:
                self.block_dict[resolve_address] = block
                self.block_addr_list.append(resolve_address)

                #需要解析跳转地址
                if block.disasm_list[-1].mnemonics == 'jmp':
                    jmp_to_address = block.disasm_list[-1].operands_value[0]
                    resolve_address_list.append(jmp_to_address)
                #需要解析跳转地址和block之后的地址
                elif block.disasm_list[-1].mnemonics[0] == 'j':
                    jmp_to_address = block.disasm_list[-1].operands_value[0]
                    not_jmp_address = resolve_address + block.size
                    resolve_address_list.append(jmp_to_address)
                    resolve_address_list.append(not_jmp_address)
                #不需要继续解析
                elif (block.disasm_list[-1].mnemonics == 'int') or (block.disasm_list[-1].mnemonics == 'retn') or (block.disasm_list[-1].mnemonics == 'retf'):
                    continue



    def resolve(self):
        '''
            解析汇编指令并构造树
        '''
        address = self.start_address
        #解析出所有代码块
        block_dict = self.block_dict
        block_addr_list = self.block_addr_list
        self.resolve_all_block_by_function()

        #根节点
        if self.start_address not in block_dict:
            #发现无法判定函数块结束的代码块
            return

        self.root_block = block_dict[self.start_address]

        #设置他们的父子关系
        for block_addr in block_addr_list:
            block = block_dict[block_addr]

            #以retn结尾的块不用添加子块
            if (block.disasm_list[-1].mnemonics == 'retn') or \
               (block.disasm_list[-1].mnemonics == 'retf'):
                if (self.function_parameter_size == 0) and (len(block.disasm_list[-1].operands_value) > 0):
                    self.function_parameter_size = block.disasm_list[-1].operands_value[0]
                continue

            if (block.disasm_list[-1].mnemonics == 'int'):
                continue

            #添加左子节点
            if block.disasm_list[-1].mnemonics != 'jmp':
                next_block_addr = block.start_address+block.size
                if next_block_addr in block_addr_list:
                    block.left_child_block = block_dict[next_block_addr]

            #添加右子节点
            if block.disasm_list[-1].operands_value[0] in block_addr_list:
                block.right_child_block = block_dict[block.disasm_list[-1].operands_value[0]]
            else:
                right_block_addr = block.disasm_list[-1].operands_value[0]
                if right_block_addr in block_addr_list:
                    block.right_child_block = block_dict[right_block_addr]
        #设置function中最后代码的地址
        self.end_address = self.block_dict[max(self.block_addr_list)].end_address



    def print_block(self):
        print 'function:0x%08x %s {'%(self.start_addres,self.function_name)
        for block_address in self.block_dict:
            print 'block[0x%08x:0x%08x]'%(block_address,self.block_dict[block_address].end_address)
        print '}'



















