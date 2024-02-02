import angr
from angr import sim_options as so
from bin_check.function_models import *


# function name and format arg position
printf_list = {"printf", "fprintf", "sprintf", "snprintf", "vsnprinf"}

'''
    # Stdio based ones
    p.hook_symbol("printf", printFormat(0))
    p.hook_symbol("fprintf", printFormat(1))
    p.hook_symbol("dprintf", printFormat(1))
    p.hook_symbol("sprintf", printFormat(1))
    p.hook_symbol("snprintf", printFormat(2))

    # Stdarg base ones
    p.hook_symbol("vprintf", printFormat(0))
    p.hook_symbol("vfprintf", printFormat(1))
    p.hook_symbol("vdprintf", printFormat(1))
    p.hook_symbol("vsprintf", printFormat(1))
    p.hook_symbol("vsnprintf", printFormat(2))
    '''

# Best effort system hooks
def hook_list(p, hooks):
    for sys_type in hooks:
        try:
            p.hook_symbol(sys_type.name, SystemLibc())
        except Exception as e:
            print(e)
            pass


def hook_printf_list(p, hooks):
    # Stdio based ones
    p.hook_symbol("printf", printFormat(0))
    p.hook_symbol("fprintf", printFormat(1))
    p.hook_symbol("dprintf", printFormat(1))
    p.hook_symbol("sprintf", printFormat(1))
    p.hook_symbol("snprintf", printFormat(2))

    # Stdarg base ones
    p.hook_symbol("vprintf", printFormat(0))
    p.hook_symbol("vfprintf", printFormat(1))
    p.hook_symbol("vdprintf", printFormat(1))
    p.hook_symbol("vsprintf", printFormat(1))
    p.hook_symbol("vsnprintf", printFormat(2))


def get_funcs_and_prj(filename, system_check=False, printf_check=False, use_angr=False, r2=None):

    # Give us tracing information
    my_extras = {
        so.REVERSE_MEMORY_NAME_MAP,
        so.TRACK_ACTION_HISTORY,
        so.TRACK_MEMORY_ACTIONS,
        so.ACTION_DEPS,
        so.UNDER_CONSTRAINED_SYMEXEC,
    }

    # Don't fail at first issue
    my_extra = angr.options.resilience.union(my_extras)
    # Run faster
    my_extra = angr.options.unicorn.union(my_extra)

    if not use_angr:
        import r2pipe
        import json
        if r2 == None:
            r = r2pipe.open(filename, ['-2'])
            r.cmd('aaaa')
        else:
            r = r2
        bin_info = r.cmd("ij")
        bin_info = json.loads(bin_info)
        base_addr = bin_info["bin"]["baddr"]

        p = angr.Project(filename, auto_load_libs=False, main_opts={"base_addr": base_addr})
    else:
        p = angr.Project(filename, auto_load_libs=False)

    binary_system_list = [x for x in p.loader.symbols if x.name in system_list]
    binary_printf_list = [x for x in p.loader.symbols if x.name in printf_list]

    xrefs = set()

    check_list = []

    if system_check:
        hook_list(p, binary_system_list)
        check_list.extend(binary_system_list)
    if printf_check:
        hook_printf_list(p, binary_printf_list)
        check_list.extend(binary_printf_list)

    if not use_angr:
        check_list = []
        funcs = r.cmd("aflj")
        funcs = json.loads(funcs)
        binary_system_list = []
        binary_printf_list = []
        for func in funcs:
            func_name = func.get("name", None)
            if func_name:
                if any([x in func_name for x in system_list]):
                    binary_system_list.append(func["offset"])
                if any([x in func_name for x in printf_list]):
                    binary_printf_list.append(func["offset"])
    
        if system_check:
            check_list.extend(binary_system_list)
        if printf_check:
            check_list.extend(binary_printf_list)

    if use_angr:
        print("[~] Building CFG")
        import os
        import pickle
        if os.path.exists('bin.cfg'):
            with open('bin.cfg', 'rb') as f:
                print("loading cfg")
                cfg = pickle.load(f)
        else:
            cfg = p.analyses.CFG(cross_references=True, show_progressbar=True)
            with open('bin.cfg', 'wb') as f:
                pickle.dump(cfg, f)

        # Get all functions that have a system call
        # reference
        for func in check_list:
            if isinstance(func,int):
                addr = func
            else:
                addr = func.rebased_addr
            func_node = cfg.model.get_any_node(addr)
            if not func_node:
                continue
            func_callers = func_node.predecessors
            for func_caller in func_callers:
                xrefs.add(func_caller.function_address)

        xrefs = list(xrefs)

        del cfg

    else:

        # Get all functions that have a system call
        # reference
        for func in check_list:
            if isinstance(func,int):
                addr = func
            else:
                addr = func.rebased_addr
            
            xref_list = r.cmd('axtj @ {}'.format(addr))
            xref_list = json.loads(xref_list)
            for caller in xref_list:
                if caller["type"] == "NULL":
                    continue
                fcn_addr = caller.get('fcn_addr',None)
                if fcn_addr:
                    xrefs.add(fcn_addr)

        xrefs = list(xrefs)

    print("Found {} test sites in binary".format(len(xrefs)))

    return xrefs, p