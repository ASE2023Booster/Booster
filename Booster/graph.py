import xml.etree.ElementTree as ET
from state_abstraction import xml_compare
from trace_reader import read
import os
from config import Config
from glob import glob
from tqdm import tqdm
# from visualize_graph import visualize
from util import print_circuits, print_edges
# from GDD import reduce
from TGHDD import reduce, trial
from generate_SARA_script import generate_script
import global_var
import time


class Edge:
    def __init__(self, source, end, event, post_action):
        self.source = source
        self.end = end
        self.event = event
        self.post_action = post_action


class Vertice:
    def __init__(self, name, layout, activity):
        self.name = name
        self.layout = layout
        self.activity = activity


class Circuit:
    def __init__(self, start, end, edges, num):
        self.start = start
        self.end = end
        self.edges = edges
        self.label = -1
        self.num = num

    def print(self):
        tempstr = ""
        for edge in self.edges:
            tempstr += edge.source.name + "-->" + edge.end.name + "   "
        print({'num:':self.num,'start:': self.start, 'end:': self.end, 'path:': tempstr})

class Graph:
    def __init__(self, abstraction_level):
        self.vertices = []
        # all edges should be inserted in sequential order
        self.edges = []
        # a tree structure organizing nested circuits
        self.circuits = []
        self.circuits_num = 0
        self.abstraction_level = abstraction_level
        self.has_circuit = False
        self.has_self_loop = False

    # All edges should be inserted in sequential order
    def add_edge(self, edge, is_target=False):
        # Make sure there is no same vertice inserted before
        # If found matched former vertice, merge the current vertice with the former one
        founded_source = find_same_former_vertice(self.vertices, edge.source, self.abstraction_level)

        # print("founded",founded_source,founded_end)
        if founded_source is None:
            self.vertices.append(edge.source)
        else:
            edge.source = founded_source

        # The target state is never merged to the former states
        if not is_target:
            founded_end = find_same_former_vertice(self.vertices, edge.end, self.abstraction_level)
            if founded_end is None:
                self.vertices.append(edge.end)
            else:
                edge.end = founded_end
        else:
            self.vertices.append(edge.end)

        # Delete self-loop
        if edge.source.name == edge.end.name:
            if not self.has_self_loop:
                self.has_self_loop = True
            return
        self.edges.append(edge)

    def find_circuits(self):
        print("all edges:")
        print_edges(self.edges)
        print()
        num = 0
        for i in range(len(self.edges)):

            for j in range(i + 1, len(self.edges)):
                if self.edges[i].source.name == self.edges[j].end.name:
                    tempstr = ""
                    for edge in self.edges[i:j + 1]:
                        tempstr += edge.source.name + "-->" + edge.end.name + "   "
                    print("adding circuit", num, ", starting from", i, "ending at", j, tempstr)
                    self.circuits_num += 1
                    self.circuits.append(Circuit(i, j, self.edges[i:j + 1],num))
                    num+=1
                    if not self.has_circuit:
                        self.has_circuit = True
                    break


def find_same_former_vertice(former_vertices, current_vertice, abstraction_level):
    for former_vertice in former_vertices:
        if xml_compare(former_vertice, current_vertice, level=abstraction_level):
            return former_vertice
    return None


def read_events(script_path):
    events, post_actions, layouts, activities, screenshots = read(script_path, script_path.replace(".py", ""),
                                                                  is_need_layout=True, is_need_activity=True)
    return events, post_actions, layouts, activities


def build_graph_and_calculate_circuits(events, post_actions, layouts, activities, abstraction_level):
    graph = Graph(abstraction_level)
    for i in range(len(events)):
        edge = Edge(Vertice(str(i), layouts[i], activities[i]), Vertice(
            str(i + 1), layouts[i + 1], activities[i + 1]), events[i], post_actions[i])
        if i == len(events) - 1:
            graph.add_edge(edge, is_target=True)
        else:
            graph.add_edge(edge)

    # target_point_key = folder.split("\\")[-1]
    print("num of events:", len(events))
    print("num of layouts:", len(layouts))
    print("target vertice:", str(len(layouts) - 1))

    graph.find_circuits()
    print("num of circuits:", graph.circuits_num)
    for circuit in graph.circuits:
        circuit.print()

    return graph


def build_graph_and_reduce(input_path, output_path, abstraction_level):
    # Check whether the initial trace satisfies the oracle, and meanwhile, get the essential information (layouts etc.) for building graph
    os.system("python " + input_path + " --path " + input_path.replace('.py',
                                                                       '') + " --package " + Config().package + " --main_activity " + Config().main_activity)

    from TGHDD import oracle_check
    if not oracle_check(input_path.replace('.py', '')):
        raise ValueError('Initial example does not satisfy condition')

    start_time = time.time()
    global_var.set_start_time(start_time)
    global_var.set_latest_optimize(os.path.join(output_path, "original.py"))

    # Read in essential information for building graph
    events, post_actions, layouts, activities = read_events(input_path)

    # Build graph, find circuits
    graph = build_graph_and_calculate_circuits(events, post_actions, layouts, activities, abstraction_level)

    reduce(graph, output_path)

    # calculate the time used while reduction completed
    print("The reduction terminates in " + str(time.time() - start_time) + " seconds.")
    print("The final reduced script is:", global_var.get_latest_optimize())


# def visualize_graph(graph, vertice_levels, folder):
#     color_list = ['r', 'g', 'b']
#     colors = []
#     for vertice in graph.vertices:
#         colors.append(color_list[vertice_levels[vertice.name] % 3])
#     visualize(graph, './visualize/'+folder.split("\\")
#               [-1]+"level4.jpg", colors)


if __name__ == "__main__":
    target_points = read_target_points()

    folders = read_folders(target_points)

    for folder in tqdm(folders):
        events, post_actions, layouts, activities = read_events(
            folder, target_points)

        graph, vertice_levels = build_graph_and_calculate_circuits(
            events, post_actions, layouts, target_points)

        graph.circuits.print()

        reduced_trace = reduce(graph, "./output")

        # visualize_graph(graph, vertice_levels, folder)

        # break
