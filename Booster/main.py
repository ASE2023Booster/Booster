import os
import time
from shutil import copyfile
from graph import build_graph_and_reduce
from config import Config
import traceback


if __name__ == '__main__':
    script_path = Config().script_path
    output_path = "./output/" + script_path.split('/')[-1].split('_replay')[0] + "_" + time.strftime("%Y_%m_%d_%H_%M_%S", time.localtime())

    # Make output dir and copy essential SARA files
    if not os.path.exists(output_path):
        os.makedirs(output_path)
    copyfile(script_path, os.path.join(output_path, "original.py"))
    os.makedirs(os.path.join(output_path, "sara_script"))
    copyfile('./sara_script/util.py', os.path.join(output_path, "sara_script", "util.py"))
    copyfile('./sara_script/parse_view_hierarchy.py', os.path.join(output_path, "sara_script", "parse_view_hierarchy.py"))

    print("==============================================================")
    # for level in range(4,0,-1):
    # Start reduction
    # Abstraction level
    level = 2
    try:
        build_graph_and_reduce(os.path.join(output_path, "original.py"), output_path, level)
    except ValueError:
        traceback.print_exc()


