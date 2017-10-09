from idautils import *
from idaapi import *

import re

class BlockNode:
    # A Node has two refs at most 
    def __init__(self, (start_ea,end_ea)):
        self.start_ea = start_ea
        self.end_ea = end_ea+1
        self.next_nodes = set()

        
def find_node(ea, nodes):
    for n in nodes:
      if n.start_ea <= ea < n.end_ea:
        return n
    return None
    
# This code is from OpenRCE : http://www.openrce.org/articles/full_view/11
def enumerate_blocks(function_ea):
    '''
    Calculate the cyclomatic complexity measure for a function.
    
    Given the starting address of a function, it will find all
    the basic block's boundaries and edges between them
    '''
    
    f_start = function_ea
    f_end = FindFuncEnd(function_ea)
    
    edges = set()
    boundaries = set((f_start,))
    
    # For each defined element in the function.
    for head in Heads(f_start, f_end):
    
        # If the element is an instruction
        if isCode(GetFlags(head)):
        
            # Get the references made from the current instruction
            # and keep only the ones local to the function.
            refs = CodeRefsFrom(head, 0)
            refs = set(filter(lambda x: x>=f_start and x<=f_end, refs))
            
            if refs:
                # If the flow continues also to the next (address-wise)
                # instruction, we add a reference to it.
                # For instance, a conditional jump will not branch
                # if the condition is not met, so we save that
                # reference as well.
                next_head = NextHead(head, f_end)
                if isFlow(GetFlags(next_head)):
                    refs.add(next_head)
                
                # Update the boundaries found so far.
                boundaries.update(refs)
                            
                # For each of the references found, and edge is
                # created.
                for r in refs:
                    # If the flow could also come from the address
                    # previous to the destination of the branching
                    # an edge is created.
                    if isFlow(GetFlags(r)):
                        edges.add((PrevHead(r, f_start), r))
                    edges.add((head, r))

    sorted_boundaries = sorted(boundaries, reverse = True)
    end_addr = PrevHead(f_end, f_start)

    block_nodes = []
    for begin_addr in sorted_boundaries:
        block_nodes.append(BlockNode((begin_addr, end_addr)))
        # search the next end_addr which could be
        # farther than just the previous head
        # if data are interlaced in the code
        # WARNING: it assumes it won't epicly fail ;)
        end_addr = PrevHead(begin_addr, f_start)
        #if end_addr == BADADDR:
        #    break
        #while not isCode(GetFlags(end_addr)):
        #    end_addr = PrevHead(end_addr, f_start)
        # And finally return the result
    block_nodes.reverse()
    
    # Build a graph from edges and blocks
    for (src_ea, dest_ea) in edges:
        src_node = find_node(src_ea, block_nodes)
        dest_node = find_node(dest_ea, block_nodes)
        if src_node != None and dest_node != None:
            src_node.next_nodes.add(dest_node)
            
    return block_nodes
             

# This is an agressive algrithm, to find the first find path          
def find_path_to(frm_node,to_node):
    def find_path_to_(frm_node,to_node, Visited):
      if frm_node in Visited:
        return None
      Visited.add(frm_node)
      if frm_node == to_node:
        return [frm_node]
      for node in frm_node.next_nodes:
        l = find_path_to_(node,to_node, Visited)
        if l:
          l.append(frm_node)
          return l
      return None
    return find_path_to_(frm_node,to_node, set())

# For every block check is there a closure path 
def find_loop_blocks(func_ea):
    blocks = enumerate_blocks(func_ea)
    blocks_arr = []
    if len(blocks) > 20:
        return None
    for block in blocks:
        for node in block.next_nodes:
            loop_blocks = find_path_to(node,block)
            if loop_blocks:
                blocks_arr.append(loop_blocks)
    blocks_arr = set(tuple(sorted(x)) for x in blocks_arr)
    return blocks_arr  

# Generally,COOP do not concious about that big functions,
# functions with one or three basic blocks are potential vfgadgets
# the only exception being  ML-G and ML-ARG-G
def verify_blocks(func,threshold):
    blocks = enumerate_blocks(func)
    if len(blocks) > threshold:
        return False
    else:
        return True
        
# Looped basic block with an indirect call dependent on [this]
# and a non-constant write to [esp-4]
def is_ML_ARG_G(func):
    return False

# Looped basic block with an indirect call dependent on [this]
# Use an conservative algrithm to find out all potential ML-G function 
def is_ML_G(func):
    # Could decrease the threshold to reduce the potential function num
    if not verify_blocks(func,20):
        return False
    pattern = re.compile(r'(call|jmp).*cs:(__guard_check_icall_fptr|__guard_dispatch_icall_fptr)')
    pattern_vt = re.compile(r'mov.*rax, \[rax+.*\]')
    lp_arr = find_loop_blocks(func)
    for lp in lp_arr:
        if lp == None:
            print hex(BADADDR)
            return False
        # Could reduce the potential function num by enable this check
        # This check aimed to filter those have complicate loop blocks
        #elif len(lp) > 5:
        #    return False
        else:
            for block in lp:
                is_only_call = False
                #print "Block :",hex(block.start_ea),"->",hex(block.end_ea)
                for head in Heads(block.start_ea,block.end_ea): 
                    #print hex(head),":",GetDisasm(head)
                    if isCode(GetFlags(head)):
                        if GetMnem(head) == 'call':
                            is_only_call = False
                        if pattern.match(GetDisasm(head)):
                            while head != BADADDR and GetOpnd(head,0) != 'rax':
                                head = PrevHead(head,block.start_ea)
                            if GetOpnd(head,1).find('rax') != -1:
                                is_only_call = True
            if  is_only_call:
                return True
    return False

# potential function has only one Block
# left side of assignment must be one of [r8,r9,rdx]
# right side of assignment must be [reg+offset]
def is_LOAD_64_G(func_ea):
    pattern = re.compile(r'(mov|lea|movzx).*(r8d|r9d|rdx),.*\[r.*\+.*\]')
    f_start =func_ea
    f_end = FindFuncEnd(func_ea)
    is_load = False
    for head in Heads(f_start,f_end):
        if isCode(GetFlags(head)):
            if GetMnem(head) == 'call':
                return False
            if pattern.match(GetDisasm(head)):
                is_load = True
    return is_load
    
# potential function has only one Block
# call [this+offset]
# indirect call indepent of [this]
def is_INV_G(func_ea):
    pattern = re.compile(r'(call|jmp).*cs:(__guard_check_icall_fptr|__guard_dispatch_icall_fptr)')
    f_start =func_ea
    f_end = FindFuncEnd(func_ea)
    for head in Heads(f_start,f_end):
        if isCode(GetFlags(head)):
            if GetMnem(head) == 'call':
                if pattern.match(GetDisasm(head)):
                    while GetOpnd(head,0) != 'rax':
                        head = PrevHead(head,f_start)
                    if GetOpnd(head,1).find('rcx') != -1:
                        return True
                    else:
                        return False
                else:
                    return False
    return False

# potential function has only one Block
# left side of assignment must be [this+offset]
def is_ARITH_G(func):
    pattern = re.compile(r'(and|or|add|sub).*\[(rcx|rbx)+.*\],.*')
    f_start =func_ea
    f_end = FindFuncEnd(func_ea)
    for head in Heads(f_start,f_end):
        if isCode(GetFlags(head)):
            if pattern.match(GetDisasm(head)):
                return True
    return False


def is_R_G(func):
    return False

def is_W_G(func):
    return False
    
def is_W_SA_G(func):
    return False

def is_MOVE_SP_G(func):
    return False
    
    

print("Begin")
ea = BeginEA()
start_addr = SegStart(ea)
end_addr = SegEnd(ea)
ftable = Functions( start_addr, end_addr )

f_invg = open("is_INV_G.txt","w")
f_load64 = open('is_LOAD_64_G.txt',"w")
for func in ftable:
    functionName = GetFunctionName(func)
    print hex(func)+":"+functionName+"\n"
    if verify_blocks(func,2):
        if is_INV_G(func):
            f_invg.write(hex(func)+":"+functionName+"\n")
        if is_LOAD_64_G(func):
            f_load64.write(hex(func)+":"+functionName+"\n")
        #print hex(func)+":"+functionName
    #if is_LOAD_R64_G(func):
    #    print hex(func)+":"+functionName
    
f_invg.close()
f_load64.close()

print("Done ")
