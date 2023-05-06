import os
import cv2
import xml.etree.ElementTree as ET


def read(script_path, log_path="", is_need_layout=False, is_need_activity=False, is_need_screenshot=False):
    with open(script_path, 'r', encoding="utf-8") as f:
        content = f.read()
        content = content.split("post_action(0)")[-1]
        content = content.split("except Exception as e:")[0]
        content = content.split('\n')

    post_actions = []
    for i in range(len(content)-1, -1, -1):
        content[i] = content[i].replace(' ', '')
        # remove empty lines, sleep, and comments
        if content[i] == "" or "post_action" in content[i] or content[i][0] == '#':
            if "post_action" in content[i]:
                post_actions.append(content[i])
            content.remove(content[i])
    while "" in content:
        content.remove("")
    layouts = []
    screenshots = []
    activities = []
    if is_need_layout or is_need_screenshot:
        counter = 0
        try:
            assert log_path != ""
        except:
            print("log_path is not provided")
            exit(0)

    if is_need_layout:
        try:
            for counter in range(len(content)+1):
                filename = os.path.join(log_path, "ui_"+str(counter)+".xml")
                layouts.append(ET.parse(filename).getroot())
        except:
            print("No enough layout files")
            exit(0)
    
    if is_need_activity:
        try:
            for counter in range(len(content)+1):
                filename = os.path.join(log_path, "activity_"+str(counter)+".txt")
                with open(filename,'r') as f:
                    activity = f.read()
                activities.append(activity)
        except:
            print("No enough activity files")
            exit(0)

    if is_need_screenshot:
        counter = 0
        try:
            for counter in range(len(content)+1):
                filename = os.path.join(
                    log_path, "screenshot_"+str(counter)+".jpg")
                screenshots.append(cv2.imread(filename))
        except:
            print("No enough screenshot files")
            exit(0)
    return content, post_actions, layouts, activities, screenshots
