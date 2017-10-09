# V2.0 Raw
# Use recursion to find loop 
# disregard the functions whose blocks larger than 20 
#
from idautils import *
from idaapi import *

import re

class BlockNode:
    # A Node has two refs at most 
    def __init__(self, (start_ea,end_ea)):
        self.start_ea = start_ea
        self.end_ea = end_ea
        self.next_nodes = set()

        
def find_node(ea, nodes):
    for n in nodes:
      if n.start_ea <= ea <= n.end_ea:
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
        src_node.next_nodes.add(dest_node)
            
    return block_nodes,edges
             

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
    
def find_loop_blocks(func_ea):
    blocks,edges = enumerate_blocks(func_ea)
    if len(blocks) > 20:
        return None
    for block in blocks:
        for node in block.next_nodes:
            loop_blocks = find_path_to(node,block)
            if loop_blocks:
                return loop_blocks
         

# Generally,COOP do not concious about that big functions,
# functions with one or three basic blocks are potential vfgadgets
def verify_blocks(func):
    blocks = cyclomatic_complexity(func)
    if len(blocks) > 3 :
        retrun False
    else :
        retrun True
        

def is_ML_ARG_G(func):
    return False

def is_ML_G(func):
    return False


# left side of assignment must be one of [r8,r9,rdx]
# right side of assignment must be [reg+offset]
def is_LOAD_64_G(func_ea):
    pattern = re.compile(r'(mov|lea|movzx).*(r8d|r9d|rdx),.*\[r.*\+.*\]')
    f_start =func_ea
    f_end = FindFuncEnd(func_ea)
    for head in Heads(f_start,f_end):
        if isCode(GetFlags(head)):
            if pattern.match(GetDisasm(head)):
                return True
    return False
    

# call [this+offset]
# indirect call indepent of [this]
def is_INV_G(func_ea):
    pattern = re.compile(r'(call|jmp).*cs:(__guard_check_icall_fptr|__guard_dispatch_icall_fptr)')
    f_start =func_ea
    f_end = FindFuncEnd(func_ea)
    for head in Heads(f_start,f_end):
        if isCode(GetFlags(head)):
            if pattern.match(GetDisasm(head)):
                while GetOpnd(head,0) != 'rax':
                    head = PrevHead(head,f_start)
                if GetOpnd(head,1).find('rcx') != -1:
                    return True
    return False
    
def is_ARITH_G(func):
    return False

def is_R_G(func):
    return False

def is_W_G(func):
    return False
    
def is_W_SA_G(func):
    return False

def is_MOVE_SP_G(func):
    return False