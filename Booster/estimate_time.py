from trace_reader import read

def estimate_event_time(event):
    if "perform_click_event" in event:
        return float(event.split(",")[3])

    elif "perform_swipe_event" in event:
        try:
            duration = float(event.split(']')[1].replace(",","").replace(")","").replace(" ",""))
        except:
            duration = 0.01

        points = len(event.split("[")[1].split("]")[0].split(","))
        return duration*(points-1)

    else:
        return 1

def estimate_post_action_time(post_action):
    time = float(post_action.split("(")[1].split(")")[0])
    return time+1.5

def estimate_time(circuit):
    edges = circuit.edges
    events = []
    post_actions = []
    for edge in edges:
        events.append(edge.event)
        post_actions.append(edge.post_action)
    time = 0
    for i in range(len(events)):
        time += estimate_event_time(events[i])
        time += estimate_post_action_time(post_actions[i])
    # print(round(time,2))
    return round(time,2)

