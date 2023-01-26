import angr
import logging

log = logging.getLogger(__name__)

system_list = [
    "system",
    "execv",
    "execve",
    "popen",
    "execl",
    "execle",
    "execlp",
    "do_system",
    "doSystembk",
]

MAX_READ_LEN = 1024

# Better symbolic strlen
def get_max_strlen(state, value):
    i = 0
    for c in value.chop(8):  # Chop by byte
        i += 1
        if not state.solver.satisfiable([c != 0x00]):
            return i - 1
    return i


def get_largest_symbolic_buffer(symbolic_list):

    """
    Iterate over the characters in the string
    Checking for where our symbolic values are
    This helps in weird cases like:
    char myVal[100] = "I\'m cool ";
    strcat(myVal,STDIN);
    printf(myVal);
    """
    position = 0
    count = 0
    greatest_count = 0
    for i in range(1, len(symbolic_list)):
        if symbolic_list[i] and symbolic_list[i] == symbolic_list[i - 1]:
            count = count + 1
            if count > greatest_count:
                greatest_count = count
                position = i - count
        else:
            if count > greatest_count:
                greatest_count = count
                position = i - 1 - count
                # previous position minus greatest count
            count = 0

    return position, greatest_count


# Better symbolic strlen
def get_max_strlen(state, value):
    i = 0
    for c in value.chop(8): # Chop by byte
        i += 1
        if not state.solver.satisfiable([c != 0x00]):
            log.info("Found the null at offset : {}".format(i))
            return i-1
    return i


"""
Model either printf("User input") or printf("%s","Userinput")
"""


class printFormat(angr.procedures.libc.printf.printf):
    IS_FUNCTION = True
    input_index = 0
    """
    Checks userinput arg
    """

    def __init__(self, input_index):
        # Set user input index for different
        # printf types
        self.input_index = input_index
        angr.procedures.libc.printf.printf.__init__(self)

    def checkExploitable(self, fmt):

        bits = self.state.arch.bits
        load_len = int(bits / 8)
        max_read_len = 1024
        """
        For each value passed to printf
        Check to see if there are any symbolic bytes
        Passed in that we control
        """
        i = self.input_index
        state = self.state
        solv = state.solver.eval

        if len(self.arguments) <= i:
            #print("{} vs {}".format(len(self.arguments),i))
            #print(hex(state.globals["func_addr"]))
            return False
        printf_arg = self.arguments[i]

        var_loc = solv(printf_arg)

        # Parts of this argument could be symbolic, so we need
        # to check every byte
        var_data = state.memory.load(var_loc, max_read_len)
        var_len = get_max_strlen(state, var_data)

        fmt_len = self._sim_strlen(fmt)

        # Reload with just our max len
        var_data = state.memory.load(var_loc, var_len)

        log.info("Building list of symbolic bytes")
        symbolic_list = [
            state.memory.load(var_loc + x, 1).symbolic for x in range(var_len)
        ]
        log.info("Done Building list of symbolic bytes")

        """
        Iterate over the characters in the string
        Checking for where our symbolic values are
        This helps in weird cases like:

        char myVal[100] = "I\'m cool ";
        strcat(myVal,STDIN);
        printf(myVal);
        """
        position = 0
        count = 0
        greatest_count = 0
        prev_item = symbolic_list[0]
        for i in range(1, len(symbolic_list)):
            if symbolic_list[i] and symbolic_list[i] == symbolic_list[i - 1]:
                count = count + 1
                if count > greatest_count:
                    greatest_count = count
                    position = i - count
            else:
                if count > greatest_count:
                    greatest_count = count
                    position = i - 1 - count
                    # previous position minus greatest count
                count = 0
        log.info(
            "[+] Found symbolic buffer at position {} of length {}".format(
                position, greatest_count
            )
        )

        if greatest_count > 0:
            command_string = state.solver.eval(var_data, cast_to=bytes)
            print_formated = "{}\t->\t{}".format(hex(var_loc), command_string)
            log.info(
                "Format String bug in function at {}".format(
                    hex(state.globals["func_addr"])
                )
            )
            log.info(print_formated)

            state.globals["exploitable"] = True
            state.globals["cmd"] = print_formated
            return True
        return False

    def run(self, _, fmt):
        if not self.checkExploitable(fmt):
            return super(type(self), self).run(fmt)
"""
Basic check to see if symbolic input makes it's way into
an argument for a system call
"""


class SystemLibc(angr.procedures.libc.system.system):
    def check_exploitable(self, cmd):

        state = self.state

        # If you're not using the latest angr you'll get errors here. Uncomment
        # if "claripy.ast.bv.BV" in str(type(cmd)):
        #     print("raw bit vector")
        #     return False

        clarip = cmd.to_claripy()
        location = self.state.solver.eval(clarip)

        # Parts of this argument could be symbolic, so we need
        # to check every byte
        var_data = state.memory.load(location, MAX_READ_LEN)
        var_len = get_max_strlen(state, var_data)

        # Reload with just our max len
        var_data = state.memory.load(location, var_len)

        symbolic_list = [
            state.memory.load(location + x, 1).symbolic for x in range(var_len)
        ]

        symbolic_list = [
            state.memory.load(location + x, 1).symbolic for x in range(var_len)
        ]

        position, greatest_count = get_largest_symbolic_buffer(symbolic_list)

        if greatest_count > 0:
            for i in range(greatest_count):
                # Get symbolic byte
                curr_byte = state.memory.load(location + position + i, 1)
                if state.solver.satisfiable(extra_constraints=[curr_byte == b"A"]):
                    state.add_constraints(curr_byte == b"A")

            command_string = state.solver.eval(var_data, cast_to=bytes)
            print_formated = "{}\t->\t{}".format(hex(location), command_string)
            logging.info(
                "Command Injection in function at {}".format(
                    hex(state.globals["func_addr"])
                )
            )
            logging.info(print_formated)

            state.globals["exploitable"] = True
            state.globals["cmd"] = print_formated

    def run(self, cmd):
        self.check_exploitable(cmd)
        return super(type(self), self).run(cmd)
