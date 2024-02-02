import r2pipe
import json
import copy
import sys
import uuid

class program_slice:
    end_addr = 0
    avoid_list = []
    top_addr = 0
    basic_block_list = []
    funcs = []
    id = None

    def __init__(self, end_addr):
        self.end_addr = end_addr
        self.top_addr = end_addr
        self.avoid_list = []
        self.basic_block_list = []
        self.funcs = []
        self.id = uuid.uuid4().hex
    
    def __repr__(self) -> str:
        ret = "[{} - {}]\n".format(hex(self.top_addr), hex(self.end_addr))
        for bb in self.basic_block_list:
            ret += "\t{}\n".format(hex(bb["addr"]) )
        return ret
    
    def get_basic_block_addrs(self):
        return [x["addr"] for x in self.basic_block_list]
    
def get_r2_instance(filename):
    r = r2pipe.open(filename ,['-2'])
    r.cmd('aaaa')
    return r

def get_xrefs_to_func(r2,addr):
    '''
    Expected JSON/Dict coming out
    [
        {"from":4197904,"type":
        "CALL","perm":"--x",
        "opcode":"jal sym.mtd_write_firmware",
        "fcn_addr":4196848,
        "fcn_name":"main",
        "refname":"sym.mtd_write_firmware"}
    ]
    '''
    print('axtj @ {}'.format(addr))
    json_text = r2.cmd('axtj @ {}'.format(addr))
    xrefs = json.loads(json_text)
    print(xrefs)
    return xrefs

def get_basic_block_from_addr(r2,addr):
    '''
    [
     {
    "addr": 4199216,
    "size": 8,
    "jump": 4199200,
    "opaddr": 18446744073709552000,
    "inputs": 1,
    "outputs": 1,
    "ninstr": 3,
    "instrs": [
      4199216,
      4199220,
      4199216
    ],
    "traced": true
    }
    ]
    '''
    r2.cmd('s {}'.format(addr))
    json_text = r2.cmd('afbij')
    bbs = json.loads(json_text)
    return bbs

def get_func_basic_blocks(r2, func_addr):
    json_text = r2.cmd('afbj {}'.format(func_addr))
    bbs = json.loads(json_text)
    return bbs

def get_predecessor_blocks(func_blocks, target_block):
    ret_block_list = []
    avoid_list = []

    bb_tuples = []

    if target_block.get("addr",None) is None:
        return []

    for block in func_blocks:
        found_block = False

        # Can this basic block jump to us?
        jump_addr = block.get("jump",None)
        if jump_addr and jump_addr== target_block["addr"]:
            found_block = True
            ret_block_list.append(block)

            # Check for fails
            fail_addr = block.get("fail",None)
            if fail_addr and fail_addr != target_block["addr"]:
                avoid_list.append(fail_addr)

        # Does this basic block have a fail?
        fail_addr = block.get("fail",None)
        if fail_addr and fail_addr == target_block["addr"]:
            found_block = True
            ret_block_list.append(block)

            # Check for jumps not to us
            jump_addr = block.get("jump",None)
            if jump_addr and jump_addr != target_block["addr"]:
                avoid_list.append(jump_addr)

        # Does this basic block execute us next without jumps?
        fall_in_range = target_block["addr"] - 0x4
        block_size = block.get("size", None)
        if block_size:
            if block['addr'] < target_block["addr"] and (block['addr'] + block_size) > fall_in_range:
                found_block = True
                ret_block_list.append(block)
            # If we get here there is no other branch we want to avoid.
            # No need to add to the avoid list
        
        if found_block:
            bb_tuples.append((ret_block_list[0], avoid_list))

        ret_block_list = []
        avoid_list = []
    
    return bb_tuples

def get_one_predecessor_block_slice_xref(r2, p_slice):

    program_slices = []

    xrefs = get_xrefs_to_func(r2, p_slice.top_addr)
    for xref in xrefs:
        xref_addr = xref.get('from',None) # Exact calling address
        xref_func = xref.get('fcn_addr',None) # Function containing address

        func_blocks = get_func_basic_blocks(r2, xref_func)
        xref_block = get_basic_block_from_addr(r2, xref_addr)

        basic_block_tuples = get_predecessor_blocks(func_blocks, xref_block)

        for ref_block,avoid_block_addrs in basic_block_tuples:
            p_slice_copy = copy.copy(p_slice)

            p_slice_copy.funcs.append(xref)
            p_slice_copy.avoid_list.extend(avoid_block_addrs)
            p_slice_copy.basic_block_list.append(ref_block)
            p_slice_copy.top_addr = ref_block.get("addr",None)

            program_slices.append(p_slice_copy)
    
    return program_slices
    
def get_one_predecessor_block_slice_block(r2, p_slice):

    program_slices = []

    xref = p_slice.funcs[0]

    # xref_addr = xref.get('from',None) # Exact calling address
    xref_func = xref.get('fcn_addr',None) # Function containing address

    func_blocks = get_func_basic_blocks(r2, xref_func)
    xref_block = get_basic_block_from_addr(r2, p_slice.top_addr)

    basic_block_tuples = get_predecessor_blocks(func_blocks, xref_block)

    for ref_block,avoid_block_addrs in basic_block_tuples:
        p_slice_copy = copy.copy(p_slice)

        p_slice_copy.avoid_list.extend(avoid_block_addrs)
        p_slice_copy.basic_block_list.append(ref_block)
        p_slice_copy.top_addr = ref_block.get("addr",None)
        
        program_slices.append(p_slice_copy)
    
    return program_slices

def top_block_has_xrefs(r2, p_slice):
    return len(get_xrefs_to_func(r2, p_slice.top_addr)) > 0

def top_block_has_bb_refs(r2, p_slice):
    if p_slice.top_addr == p_slice.end_addr:
        return False
    if len (p_slice.funcs) == 0: # Haven't done initial xref
        return False
    xref = p_slice.funcs[0]
    xref_block = get_basic_block_from_addr(r2, p_slice.top_addr)
    xref_func = xref.get('fcn_addr',None) # Function containing address

    func_blocks = get_func_basic_blocks(r2, xref_func)
    basic_block_tuples = get_predecessor_blocks(func_blocks, xref_block)

    return len(basic_block_tuples) > 0

'''
    Provide the address from bcheck and we'll start creating
    backward program slice to see how far into the program we can
    go while still getting an exploitable program state.
'''
def create_initial_program_slice(vuln_addr):
    p_slice = program_slice(vuln_addr)
    return p_slice

def get_next_predecessor_path(r2, p_slice):
    if top_block_has_xrefs(r2, p_slice):
        return get_one_predecessor_block_slice_xref(r2, p_slice)
    if top_block_has_bb_refs(r2, p_slice):
        return get_one_predecessor_block_slice_block(r2, p_slice)
    print("Error no basic block or xrefs found for slice : {}".format(p_slice))
    return None
