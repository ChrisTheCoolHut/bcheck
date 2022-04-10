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


def get_funcs_and_prj(filename, system_check=False, printf_check=False):

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

    p = angr.Project(filename, auto_load_libs=False)

    binary_system_list = [x for x in p.loader.symbols if x.name in system_list]

    binary_printf_list = [x for x in p.loader.symbols if x.name in printf_list]

    print("[~] Building CFG")
    cfg = p.analyses.CFG(cross_references=True, show_progressbar=True)

    xrefs = set()

    if system_check:
        hook_list(p, binary_system_list)

        # Get all functions that have a system call
        # reference
        for func in binary_system_list:
            func_node = cfg.model.get_any_node(func.rebased_addr)
            func_callers = func_node.predecessors
            for func_caller in func_callers:
                xrefs.add(func_caller.function_address)

    if printf_check:
        hook_printf_list(p, binary_printf_list)

        # Get all functions that have a system call
        # reference
        for func in binary_printf_list:
            func_node = cfg.model.get_any_node(func.rebased_addr)
            if not func_node:
                continue
            func_callers = func_node.predecessors
            for func_caller in func_callers:
                xrefs.add(func_caller.function_address)

    xrefs = list(xrefs)

    print("Found {} test sites in binary".format(len(xrefs)))

    return xrefs, p
