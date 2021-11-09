from celery import Celery
import multiprocessing
from celery.result import allow_join_result
import tqdm
import time
import atexit
import sys

options = {
    "broker_url": "pyamqp://guest@localhost//",
    "result_backend": "rpc://",
    "worker_max_memory_per_child": 2048000,  # 2GB
    "task_time_limit": 60,  # 1 minute timeout
    "accept_content": ["pickle", "json"],
    "result_serializer": "pickle",
    "task_serializer": "pickle",
}


app = Celery("CeleryTask")
app.config_from_object(options)


# Keep it simple. Make a blank state and let it run
# arguments are already symbolic data so we don't
# need to build a call state.
@app.task
def do_trace(proj, func_addr):
    fix_sys_bugs()

    state = proj.factory.blank_state(addr=func_addr)
    state.globals["func_addr"] = func_addr
    simgr = proj.factory.simgr(state)
    simgr.explore(find=lambda s: "exploitable" in s.globals)

    if "found" in simgr.stashes and len(simgr.found):
        return (func_addr, simgr.found[0].globals["cmd"])
    if "errored" in simgr.stashes and len(simgr.errored):
        for err_record in simgr.errored:
            print(err_record)
            print(err_record.state.globals.items())
            if "exploitable" in err_record.state.globals:
                return (func_addr, err_record.state.globals["cmd"])
    return None, None


def start_workers(worker):
    p = multiprocessing.Process(target=worker.start)
    p.start()
    atexit.register(worker.stop)
    atexit.register(p.join)
    return p


def async_and_iter(async_function, async_list):

    async_funcs = []

    for item in async_list:
        # n_task = async_function.delay(item)
        n_task = async_function.apply_async(args=[item[0], item[1]])
        async_funcs.append(n_task)

    bar = tqdm.tqdm(total=len(async_funcs))
    # If a process get's sigkilled, it kills this main parent
    # Sp just break when it fully fails
    while True:
        try:
            while not all([x.successful() or x.failed() for x in async_funcs]):
                done_count = len(
                    [
                        x.successful() or x.failed()
                        for x in async_funcs
                        if x.successful() or x.failed()
                    ]
                )
                bar.update(done_count - bar.n)
                time.sleep(1)
            break
        except ConnectionResetError:
            pass
    bar.close()

    with allow_join_result():
        return [x.get(propagate=False) for x in async_funcs if not x.failed()]


def fix_sys_bugs():
    try:
        import sys

        sys.stdout.encoding = (
            "UTF-8"  # AttributeError: 'LoggingProxy' object has no attribute 'encoding'
        )
    except (AttributeError, TypeError):  # AttributeError: readonly attribute
        pass
