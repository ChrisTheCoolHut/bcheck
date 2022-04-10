#!/usr/bin/env python
import argparse
import logging

logging.basicConfig()

from bin_check.filter_binary import should_check_binary
from bin_check.celery_app import *
from bin_check.tracing import get_funcs_and_prj

log_things = ["angr", "pyvex", "claripy", "cle"]
for log in log_things:
    logger = logging.getLogger(log)
    logger.disabled = True
    logger.propagate = False


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="Binary file to check")

    parser.add_argument(
        "-p",
        "--printf",
        help="Enable printf checking",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-s",
        "--system",
        help="Enable command injection checking",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-f",
        "--filter",
        help="Enables basic binary filtering",
        action="store_true",
        default=False,
    )
    worker_options = parser.add_argument_group(title="Worker Options")
    worker_options.add_argument(
        "-t",
        "--timeout",
        help="Set worker timeout. Default 60 seconds",
        type=int,
        default=60,
    )
    worker_options.add_argument(
        "-m",
        "--memory_limit",
        help="Set worker memory limit in GB. Default 2GB",
        type=int,
        default=2097152,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        help="Increases logging verbosity",
        action="store_true",
        default=False,
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    app.conf["task_time_limit"] = args.timeout
    app.conf["worker_max_memory_per_child"] = args.memory_limit * 1024 * 1024

    if not args.system and not args.printf:
        print("Please select check mode of printf checking (-p) or command injection testing (-s). Or both")
        exit(0)

    print("[~] {}".format(args.file))

    if args.filter:
        if not should_check_binary(args.file):
            print("Filtered out binary")
            exit(0)

    if args.system:
        print("[~] Checking for command injections")

    if args.printf:
        print("[~] Checking for format string vulnerabilities")

    funcs, proj = get_funcs_and_prj(args.file, args.system, args.printf)

    if len(funcs) == 0:
        print("No test sites found. Exitting (Maybe no xrefs to checked functions?)")
        exit(0)

    # Remove any previous exitted runs
    app.control.purge()

    worker = app.Worker(quiet=True)

    t = start_workers(worker)

    pool_args = []

    for func in funcs:
        pool_args.append((proj, func))

    results = async_and_iter(do_trace, pool_args)

    app.control.shutdown()

    t.join()

    func_addres = [x for x, y in results]

    print("[-] Scanned functions:")
    for func in funcs:
        func_name = proj.loader.find_symbol(func)
        if func_name:
            func_name = func_name.name
        if func in func_addres:
            print("[+] : {} : {}".format(hex(func), func_name))
            pair = [(x, y) for x, y in results if x == func][0]
            print(pair[1])
        else:
            print("[-] : {} : {}".format(hex(func), func_name))


if __name__ == "__main__":
    main()
