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
    global action_count

    # print('[ReplayTimeInterval]-%d: %s' % (action_count, json.dumps({'interval': custom_interval})))
    if action_count > 0:
        time.sleep(1)
        if custom_interval > 0:
            time.sleep(custom_interval)
    xml = d.dump_hierarchy()
    xml = util.parse_xml(xml)
    action_count += 1


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
        # log('[click]-%s' % json.dumps({'tap_type': tap_type, 'x': x, 'y': y, 'duration': duration, 'candidate': candidates, 'view_type': view_type}))

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
        perform_click_event("Tap", 203.717072, 233.817337, 0.143000, "Activity")
        post_action(1.563048)
        perform_click_event("Tap", 461.202515, 562.701019, 0.080000, "Activity")
        post_action(2.761031)
        perform_swipe_event([(495.31207275390625, 462.6385498046875), (490.1316833496094, 471.7097473144531),(457.5398254394531, 555.73583984375), (433.9224548339844, 630.5819091796875), (409.7303161621094, 734.5789184570312), (393.99468994140625, 825.5897827148438),(385.1463928222656, 901.1201782226562), (381.4849548339844, 943.1448364257812),(378.9736328125, 961.2490234375), (379.47296142578125, 970.2420043945312)])
        post_action(1.600642)
        perform_swipe_event([(495.31207275390625, 462.6385498046875), (490.1316833496094, 471.7097473144531), (457.5398254394531, 555.73583984375), (433.9224548339844, 630.5819091796875), (409.7303161621094, 734.5789184570312), (393.99468994140625, 825.5897827148438),(385.1463928222656, 901.1201782226562), (381.4849548339844, 943.1448364257812), (378.9736328125, 961.2490234375), (379.47296142578125, 970.2420043945312)])
        post_action(1.600642)
        perform_swipe_event([(495.31207275390625, 462.6385498046875), (490.1316833496094, 471.7097473144531),(457.5398254394531, 555.73583984375), (433.9224548339844, 630.5819091796875),(409.7303161621094, 734.5789184570312), (393.99468994140625, 825.5897827148438),(385.1463928222656, 901.1201782226562), (381.4849548339844, 943.1448364257812),(378.9736328125, 961.2490234375), (379.47296142578125, 970.2420043945312)])
        post_action(1.600642)



    except Exception as e:

        print(e)

        traceback_str = ''.join(traceback.format_tb(e.__traceback__))

        print(traceback_str)

    os.system("adb shell am force-stop " + package_name)