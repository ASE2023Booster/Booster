import xml.etree.ElementTree as ET
import logging
import copy

def xml_compare(vertice1, vertice2, level):
    if level == 1:
        return whole_compare(vertice1.layout, vertice2.layout)
    elif level == 2:
        try:
            vertice1.abstracted_layout
        except:
            vertice1.abstracted_layout = copy.copy(vertice1.layout)
            remove_leaf_nodes_base_on_duplicate_bounds(vertice1.abstracted_layout)
        try:
            vertice2.abstracted_layout
        except:
            vertice2.abstracted_layout = copy.copy(vertice2.layout)
            remove_leaf_nodes_base_on_duplicate_bounds(vertice2.abstracted_layout)
        return layout_compare(vertice1.abstracted_layout, vertice2.abstracted_layout)
    elif level == 3:
        return component_compare(vertice1.layout, vertice2.layout)
    elif level == 4:
        return activity_compare(vertice1.activity, vertice2.activity)
    else:
        raise ValueError('Not a valid abstraction level')

def activity_compare(a1, a2):
    return a1==a2

def dfs(root, component_set):
    try:
        component_set.add(root.attrib['class'])
    except:
        pass
    for child in root:
        dfs(child, component_set)
    return

def component_compare(x1,x2):
    root1 = x1
    root2 = x2

    component_set1 = set()
    component_set2 = set()

    dfs(root1, component_set1)
    dfs(root2, component_set2)

    component_set1 = sorted(list(component_set1))
    component_set2 = sorted(list(component_set2))

    if len(component_set1)!=len(component_set2):
        return False
    for i in range(len(component_set1)):
        if component_set1[i]!=component_set2[i]:
            return False
    return True

def layout_compare(x1, x2, excludes=['content-desc','text'], debugging=False):
    if x1.tag != x2.tag:
        if debugging:
            print('Tags do not match: %s and %s' % (x1.tag, x2.tag))
        return False
    for name, value in x1.attrib.items():
        if not name in excludes:
            if x2.attrib.get(name) != value:
                if debugging:
                    print('Attributes do not match: %s=%r, %s=%r' % (name, value, name, x2.attrib.get(name)))
                return False
    for name in x2.attrib.keys():
        if not name in excludes:
            if name not in x1.attrib:
                if debugging:
                    print('x2 has an attribute x1 is missing: %s' % name)
                return False
    cl1 = x1.getchildren()
    cl2 = x2.getchildren()
    if len(cl1) != len(cl2):
        if debugging:
            print('children length differs, %i != %i' % (len(cl1), len(cl2)))
        return False
    i = 0
    for c1, c2 in zip(cl1, cl2):
        i += 1
        if not c1.tag in excludes:
            if not layout_compare(c1, c2, excludes):
                if debugging:
                    print('children %i do not match: %s' % (i, c1.tag))
                return False
    return True

def whole_compare(x1, x2, excludes=[], debugging=False):
    if x1.tag != x2.tag:
        if debugging:
            print('Tags do not match: %s and %s' % (x1.tag, x2.tag))
        return False
    for name, value in x1.attrib.items():
        if not name in excludes:
            if x2.attrib.get(name) != value:
                if debugging:
                    print('Attributes do not match: %s=%r, %s=%r' % (name, value, name, x2.attrib.get(name)))
                return False
    for name in x2.attrib.keys():
        if not name in excludes:
            if name not in x1.attrib:
                if debugging:
                    print('x2 has an attribute x1 is missing: %s' % name)
                return False
    if not text_compare(x1.text, x2.text):
        if debugging:
            print('text: %r != %r' % (x1.text, x2.text))
        return False
    if not text_compare(x1.tail, x2.tail):
        if debugging:
            print('tail: %r != %r' % (x1.tail, x2.tail))
        return False
    cl1 = x1.getchildren()
    cl2 = x2.getchildren()
    if len(cl1) != len(cl2):
        if debugging:
            print('children length differs, %i != %i' % (len(cl1), len(cl2)))
        return False
    i = 0
    for c1, c2 in zip(cl1, cl2):
        i += 1
        if not c1.tag in excludes:
            if not whole_compare(c1, c2, excludes):
                if debugging:
                    print('children %i do not match: %s' % (i, c1.tag))
                return False
    return True

def text_compare(t1, t2):
    if not t1 and not t2:
        return True
    if t1 == '*' or t2 == '*':
        return True
    return (t1 or '').strip() == (t2 or '').strip()



def remove_leaf_nodes_base_on_duplicate_bounds(root):
    """
    Recursively iterates through the XML tree and removes leaf nodes
    that share the same bounds.
    """
    # Get all leaf nodes
    leaf_nodes = [child for child in root if len(child) == 0]
    # Create a dictionary to store bounds and corresponding leaf nodes
    bounds_dict = {}
    # Iterate through leaf nodes
    for leaf_node in leaf_nodes:
        # Extract bounds as a string
        bounds = leaf_node.get('bounds')
        if bounds == None:
            continue
        # If bounds already exists in the dictionary, remove the leaf node
        if bounds in bounds_dict:
            root.remove(leaf_node)
        else:
            bounds_dict[bounds] = leaf_node

    # Recursively call the function on child elements
    for child in root:
        remove_leaf_nodes_base_on_duplicate_bounds(child)


if __name__ == "__main__":
    print(xml_compare(ET.parse("../SARA_modified/traces_data/BBC/bbc_read_my_news_replay_dir/ui_19.xml").getroot(),ET.parse("../SARA_modified/traces_data/BBC/bbc_read_my_news_replay_dir/ui_29.xml").getroot()))