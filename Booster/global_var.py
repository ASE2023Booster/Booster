from trace_reader import read

class global_var:
    latest_optimize = ''
    trailed_traces = {}
    start_time = 0

def get_start_time():
    return global_var.start_time

def set_start_time(time):
    global_var.start_time = time


def set_latest_optimize(latest_optimize):
    global_var.latest_optimize = latest_optimize
    print("Current optimize is:", latest_optimize)

def get_latest_optimize():
    return global_var.latest_optimize

def add_trailed_traces(events, result):
    event_str = gen_event_string(events)
    global_var.trailed_traces[event_str]=result

def is_trailed(events):
    event_str = gen_event_string(events)
    try:
        global_var.trailed_traces[event_str]
        return True
    except:
        return False

def get_trail_result(events):
    event_str = gen_event_string(events)
    try:
        return global_var.trailed_traces[event_str]
    except:
        return None

def gen_event_string(events):
    event_str = ""
    for event in events:
        event_str+=event.event
        event_str+=event.post_action
    return event_str