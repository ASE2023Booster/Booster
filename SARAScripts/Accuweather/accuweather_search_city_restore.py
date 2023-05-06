# coding=utf8

import os
import sys
import time
import json
import argparse
import traceback
import uiautomator2 as u2
sys.path.append(os.path.abspath(os.path.dirname(os.getcwd())))
from sara_script import util

xml = None
action_count = 0
current_popup_window = None

device_id = "emulator-5554"
os.system('adb connect -s ' + device_id)
d = u2.connect(device_id)


def log(desc):
    global action_count
    # print('[ReplayAction]-%d: ' % action_count, desc)

def post_action(custom_interval):
    global xml
    global d

    # print('[ReplayTimeInterval]-%d: %s' % (action_count, json.dumps({'interval': custom_interval})))
    if action_count > 0:
        time.sleep(1)
        if custom_interval > 0:
            time.sleep(custom_interval)
    xml = d.dump_hierarchy()
    xml = util.parse_xml(xml)


def set_text(rid, bounds, text):
    global xml
    view = util.find_view(rid, bounds, xml)

    if view is None:
        print('TextView ' + rid + ' does not exist')
    else:
        if len(rid) > 0:
            d(resourceId=rid, focused=True).set_text(text)
        else:
            d(focused=True).set_text(text)
        log('[set_text]-%s' % json.dumps({'rid': rid, 'text': text, 'bounds': bounds}))


def perform_click_event(tap_type, x, y, duration, view_type):
    if tap_type == 'LongTap':
        d.long_click(x, y, duration)
    elif tap_type == 'Tap':
        d.long_click(x, y, duration)
    elif tap_type == 'DoubleTap':
        d.double_click(x, y, 0.1)

def perform_swipe_event(pointers, duration=0.01):
    d.swipe_points(pointers, duration)
    log('[swipe]-%s' % json.dumps({'pointers': pointers, 'duration': duration}))


def perform_key_event(key_code):
    d.press(key_code)
    log('[press]-%s' % json.dumps({'key_code': key_code}))


def webview_set_text_with_u2(text):
    d(focused=True).set_text(text)
    log('[webview_set_text]-%s' % json.dumps({'text': text}))



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Argument Parser')
    parser.add_argument('--package', help='package name', required=True)
    parser.add_argument('--main_activity', help='main activity name', required=True)
    args = parser.parse_args()
    package_name = args.package
    activity_name = args.main_activity

    os.system("adb shell am start -n "+package_name+"/"+activity_name)

    time.sleep(10)

    try:

        print("===========Restoring=============")
        perform_click_event("Tap", 46.934814, 94.925842, 0.012000, "Activity")
        post_action(0.000970)
        perform_click_event("Tap", 379.472961, 328.743164, 0.167000, "Activity")
        post_action(11.345422)
        set_text("android:id/search_src_text", "[128,70][592,142]", "kongkong")
        post_action(1.444719)
        perform_click_event("Tap", 117.836342, 233.817337, 0.112000, "Activity")
        post_action(2.359922)


    except Exception as e:

        print(e)

        traceback_str = ''.join(traceback.format_tb(e.__traceback__))

        print(traceback_str)

    os.system("adb shell am force-stop " + package_name)