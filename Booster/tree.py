from pprint import pprint

class Node:
    def __init__(self, start, end, edges):
        self.start = start
        self.end = end
        self.edges = edges
        self.children = []
        self.level = 0

class Tree:
    def __init__(self, start, end, edges):
        self.root = Node(start, end, edges)

    def add(self, root, new_node):
        insert_flag = True
        counter = 0
        for child in root.children:
            if child.start>=new_node.end:
                new_node.level = root.level+1
                root.children.insert(counter,new_node)
                insert_flag = False
                break
            if child.start>new_node.start and child.end>new_node.end:
                new_node.level = root.level+1
                root.children.insert(counter,new_node)
                insert_flag = False
                break
            if child.start<=new_node.start and child.end>=new_node.end:
                self.add(child,new_node)
                insert_flag = False
                break
            counter+=1
        if insert_flag:
            new_node.level = root.level+1
            root.children.append(new_node)
        return

    def give_levels(self):
        record = {}
        search_queue = []
        search_queue.append([self.root,0])
        is_root = True
        while len(search_queue)!=0:
            node = search_queue[0]
            search_queue.remove(search_queue[0])

            # root, give level to all vertices
            if is_root:
                is_root = False
                record[node[0].edges[0].source.name]=node[1]
                for i in range(len(node[0].edges)):
                    record[node[0].edges[i].end.name]=node[1]
            # not root, do not give level to the cycle starting / ending vertice
            else:
                for i in range(len(node[0].edges)):
                    if i!=len(node[0].edges)-1:
                        record[node[0].edges[i].end.name]=node[1]

            for child in node[0].children:
                search_queue.append([child,node[1]+1])

        return record

    def get_all_circuits(self):
        return tree_dfs(self.root, [])

    def print(self):
        seedata(self.root)

def seedata(root):
    tempstr = ""
    for edge in root.edges:
        tempstr+=edge.source.name+"-->"+edge.end.name+"   "
    print({'start:':root.start,'end:':root.end,'level:':root.level,'path:':tempstr})
    print()
    for child in root.children:
        seedata(child)

def tree_dfs(root, circuits):
    circuits.append(root)
    for child in root.children:
        tree_dfs(child, circuits)
    return circuits