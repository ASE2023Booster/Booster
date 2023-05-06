def print_circuits(circuits):
	for circuit in circuits:
		tempstr = ""
		for edge in circuit.edges:
			tempstr+=edge.source.name+"-->"+edge.end.name+"   "
		print({'start:':circuit.start,'end:':circuit.end,'level:':circuit.level,'path:':tempstr})

def print_edges(edges):
	tempstr = ""
	for edge in edges:
		tempstr+=edge.source.name+"-->"+edge.end.name+"   "
	print("curr event trace:",tempstr)
