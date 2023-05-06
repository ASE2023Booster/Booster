
import time
from util import print_circuits, print_edges
from glob import glob
from config import Config
import os
from generate_SARA_script import generate_script
import oracles
import global_var
from copy import copy
from estimate_time import estimate_time

deleted = []
all_edges = []
output_path = ""

class treeNode():
    def __init__(self, circuit, level, parent, children):
        self.circuit = circuit
        self.level = level
        self.parent = parent
        self.children = children
        

def get_output_filepath(path):
	files = glob(os.path.join(path,"trial*.py"))
	if len(files)==0:
		return os.path.join(path, "trial0.py")
	else:
		files = sorted(files, key = lambda x: int(x.split("trial")[1].replace(".py","")))
		return os.path.join(path,"trial"+str(int(files[-1].split("trial")[1].replace(".py",""))+1)+".py")
    # return os.path.join(path,"trial"+str(trial_num)+".py")

def oracle_check(output_file_path):
    # restore trace
    if Config().restore != '':
        os.system(r'python '+Config().restore + " --package " + Config().package + " --main_activity " + Config().main_activity)

    print("Checking oracle")
    files = glob(os.path.join(output_file_path,"ui*.xml"))
    if len(files)==0:
        print("Oracle failed")
        return False
    else:
        files = sorted(files, key = lambda x: int(x.split("ui_")[-1].replace(".xml","")))
        # Validate oracle
        if Config.oracle(files[-1]):
            print("Oracle passed")
            return True
        else:
            print("Oracle failed")
            return False

def trial(circuits_to_delete, first_try=False):
    global output_path
    print("trialing")
    print(circuits_to_delete)
    

    script_path = get_output_filepath(output_path)
    event_trace = gen_event_trace(circuits_to_delete,first_try)
    

    try:
        if global_var.is_trailed(event_trace):
            print("Using cached result instead of real execution")
            trail_result = global_var.get_trail_result(event_trace)
            if trail_result:
                # global_var.set_latest_optimize(trail_result[1])
                return True
            else:
                return False
    except:
        return False

    generate_script(event_trace, script_path)
            
    os.system("python "+script_path+" --path "+script_path.replace('.py','')+" --package "+Config().package+" --main_activity "+Config().main_activity)

    output_file_path = script_path.replace('.py','')
    if oracle_check(output_file_path):
        with open(os.path.join(output_path,'oracle_passed.txt'),'a') as f:
            f.write(script_path.replace('.py','')+"\n")
        global_var.set_latest_optimize(output_file_path+".py")
        global_var.add_trailed_traces(event_trace, True)
        print("The current trial finished in: "+str(time.time()-global_var.get_start_time())+" seconds,counting from reduction start")
        return True
    else:
        global_var.add_trailed_traces(event_trace, False)
        print("The current trial finished in: " + str(time.time() - global_var.get_start_time()) + " seconds,counting from reduction start")
        return False


def gen_event_trace(circuits_to_delete, first_try=False):
    global all_edges
    global deleted

    current_trial_delete = deleted+circuits_to_delete

    to_del = [False for i in range(len(all_edges))]
    for circuit in current_trial_delete:
        for i in range(circuit.start, circuit.end+1):
            # If two circuits have overlap, reject the execution since simutanuously delete two 
            # overlapped circuits leads the deletion to be not a complete circuit in graph
            if not first_try:
                if to_del[i]:
                    return False
            to_del[i] = True

    retain_edges = [all_edges[i] for i in range(len(all_edges)) if not to_del[i]]

    return retain_edges






def tghdd(root):
    level = 1
    nodes = []
    get_nodes_on_given_level(root, level,nodes)
    circuits = [node.circuit for node in nodes]

    while len(circuits)!=0:
        print("level",level)
        # dfs(root)

        if not trial(circuits,first_try = True):
            ddmin(circuits,2)
        else:
            add_to_deleted(circuits)

        prune_tree(root)

        level+=1
        nodes = []
        get_nodes_on_given_level(root, level, nodes)
        circuits = [node.circuit for node in nodes]
    return

def get_nodes_on_given_level(root,level,circuits):
    if root.level==level:
        circuits.append(root)
    for child in root.children:
        get_nodes_on_given_level(child, level, circuits)


def prune_tree(root):
    if node_is_deleted(root):
        for i in range(len(root.parent.children)-1,-1,-1):
            if root.parent.children[i].circuit.num==root.circuit.num:
                del(root.parent.children[i])
    for i in range(len(root.children)-1,-1,-1):
        prune_tree(root.children[i])

def node_is_deleted(node):
    if node.circuit is None:
        return False
    global deleted
    for deleted_circuit in deleted:
        if deleted_circuit.num==node.circuit.num:
            return True
    return False


def ddmin(circuits, partition_num):
    
    partitions = divide(circuits, partition_num)
    for partition in partitions:
        # print("complement")
        complement = generate_complement(circuits,partition)
        if trial(complement):
            add_to_deleted(complement)
            ddmin(complement,max(partition_num-1,2))
            return
        # print("partition")
        if trial(partition):
            add_to_deleted(partition)
            ddmin(partition,2)
            return

    if partition_num<len(circuits):
        ddmin(circuits,min(len(circuits),2*partition_num))

def divide(circuits, partition_num):
    print("partition_num:",partition_num)
    if partition_num==len(circuits):
        all_partitions = []
        for circuit in circuits:
            all_partitions.append([circuit])
        return all_partitions

    times = []
    for circuit in circuits:
        times.append(estimate_time(circuit))
    total_time = sum(times)

    combined = zip(circuits, times)
    sorted_combined = sorted(combined, key=lambda x: x[1], reverse=True)
    sorted_circuits = [x[0] for x in sorted_combined]
    sorted_times = [x[1] for x in sorted_combined]
    # print(sorted_times)

    avg_time = total_time/partition_num
    curr_time = 0
    all_partitions = []
    curr_partition = []

    for i in range(len(sorted_circuits)):
        curr_partition.append(sorted_circuits[i])
        curr_time += sorted_times[i]
        if curr_time>=avg_time:
            all_partitions.append(curr_partition)
            curr_partition = []
            curr_time = 0

    if len(curr_partition)>0:
        all_partitions.append(curr_partition)

    return all_partitions

        
def generate_complement(circuits,partition):
    complement = copy(circuits)
    for i in range(len(partition)-1,-1,-1):
        for j in range(len(complement)-1,-1,-1):
            if partition[i].num == complement[j].num:
                del(complement[j])
    return complement


def add_to_deleted(to_delete):
    global deleted
    for i in to_delete:
        found = False
        for j in deleted:
            if i.num==j.num:
                found = True
        if not found:
            deleted.append(i)



def find_parent(root, circuit):
    if root.circuit is not None:
        if root.circuit.start < circuit.start and root.circuit.end > circuit.end:
            for child in root.children:
                achild = find_parent(child, circuit)
                if achild is not None:
                    return achild
            return root

    for child in root.children:
        return find_parent(child, circuit)
    return None

def create_tree(circuits):
    root = treeNode(None, 0, None, [])
    for circuit in circuits:
        parent = find_parent(root,circuit)
        if parent is not None:
            newNode = treeNode(circuit, parent.level+1, parent, [])
            parent.children.append(newNode)
        else:
            newNode = treeNode(circuit, root.level+1, root, [])
            root.children.append(newNode)

    return root



def reduce(graph, output_path1):
    # start_time = time.time()

    circuits = graph.circuits
    global all_edges
    all_edges = graph.edges
    global output_path
    output_path = output_path1

    # If no circuit and no self-loop, terminates
    if (not graph.has_circuit) and (not graph.has_self_loop):
        print("There is no circuit or self-loop to reduce, terminating")
        return

    # If no circuit but have self-loop, try deleting only self-loops
    if not graph.has_circuit:
        print("There is no circuit to reduce, trying only reduce self-loops")
        # Try reducing self-loops
        if trial([]):
            print("Reducing self-loop succeed")
            return
        else:
            print("Reducing self-loop failed")
            return

    # build the hierarchy tree
    root = create_tree(circuits)

    # run the TGHDD reduction
    tghdd(root)

    global deleted
    # If no circuit is successfully deleted, try deleting only self-loops
    if graph.has_circuit and len(deleted)==0:
        print("There is no circuit reduced by TGHDD, trying only reduce self-loops")
        if trial([]):
            print("Reducing self-loop succeed")
            return
        else:
            print("Reducing self-loop failed")
            return
    
    # # calculate the time used while reduction completed
    # print("The reduction terminates in "+str(time.time()-start_time)+" seconds.")
    # print("The final reduced script is:", global_var.get_latest_optimize())
