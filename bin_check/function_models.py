import angr
import logging

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


class FormatDetector:
    def checkExploitable(self):
        """
        For each value passed to printf
        Check to see if there are any symbolic bytes
        Passed in that we control
        """
        i = self.input_index
        state = self.state
        solv = state.solver.eval

        printf_arg = self.arg(i)

        var_loc = solv(printf_arg)

        # Parts of this argument could be symbolic, so we need
        # to check every byte
        var_data = state.memory.load(var_loc, MAX_READ_LEN)
        var_len = get_max_strlen(state, var_data)

        # Reload with just our max len
        var_data = state.memory.load(var_loc, var_len)

        symbolic_list = [
            state.memory.load(var_loc + x, 1).symbolic for x in range(var_len)
        ]

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
        logging.info(
            "[+] Found symbolic buffer at position {} of length {}".format(
                position, greatest_count
            )
        )

        if greatest_count > 0:
            # for i in range(greatest_count):
            #     # Get symbolic byte
            #     curr_byte = state.memory.load(var_loc + position + i, 1)
            #     if state.solver.satisfiable(extra_constraints=[curr_byte == b"A"]):
            #         state.add_constraints(curr_byte == b"A")

            command_string = state.solver.eval(var_data, cast_to=bytes)
            print_formated = "{}\t->\t{}".format(hex(var_loc), command_string)
            logging.info(
                "Format String bug in function at {}".format(
                    hex(state.globals["func_addr"])
                )
            )
            logging.info(print_formated)

            state.globals["exploitable"] = True
            state.globals["cmd"] = print_formated
            return True
        return False


"""
I was dynamically creating these classes with the
type function, but when you do that, then they don't
like getting pickled. So here we have manual classes
"""


class PrintfCheck(angr.procedures.libc.printf.printf, FormatDetector):
    IS_FUNCTION = True
    input_index = 0

    def run(self):
        if not self.checkExploitable():
            return super(type(self), self).run()


class FprintfCheck(angr.procedures.libc.fprintf.fprintf, FormatDetector):
    IS_FUNCTION = True
    input_index = 1

    def run(self, file_ptr, fmt):
        if not self.checkExploitable():
            return super(type(self), self).run(file_ptr, fmt)


class SprintfCheck(angr.procedures.libc.sprintf.sprintf, FormatDetector):
    IS_FUNCTION = True
    input_index = 1

    def run(self, dst_ptr, fmt):
        if not self.checkExploitable():
            return super(type(self), self).run(dst_ptr, fmt)


class SnprintfCheck(angr.procedures.libc.snprintf.snprintf, FormatDetector):
    IS_FUNCTION = True
    input_index = 2

    def run(self, dst_ptr, size, fmt):
        if not self.checkExploitable():
            return super(type(self), self).run(dst_ptr, size, fmt)


class VsnprintfCheck(angr.procedures.libc.vsnprintf.vsnprintf, FormatDetector):
    IS_FUNCTION = True
    input_index = 2

    def run(self, str_ptr, size, fmt, ap):
        if not self.checkExploitable():
            return super(type(self), self).run(str_ptr, size, fmt, ap)


"""
Basic check to see if symbolic input makes it's way into
an argument for a system call
"""


class SystemLibc(angr.procedures.libc.system.system):
    def check_exploitable(self, cmd):

        state = self.state

        # We can't interact with raw bitvectors as potential system candidates
        if "claripy.ast.bv.BV" in str(type(cmd)):
            return False

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


printf_mapping = {
    "printf": PrintfCheck,
    "fprintf": FprintfCheck,
    "sprintf": SprintfCheck,
    "snprintf": SnprintfCheck,
    "vsnprintf": VsnprintfCheck,
}
