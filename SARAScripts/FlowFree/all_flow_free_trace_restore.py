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
        perform_click_event("Tap", 362.134521, 473.746277, 0.197000, "Activity")
        time.sleep(1.2)
        perform_click_event("Tap", 234.134521, 260.746277, 0.197000, "Activity")
        time.sleep(1.2)
        perform_swipe_event([(84.88211059570312, 1060.1717529296875), (157.16188049316406, 1069.02392578125), (220.31919860839844, 1067.937255859375), (309.6777648925781, 1060.9981689453125),(367.86346435546875, 1053.606201171875), (415.42303466796875, 1046.682373046875), (458.12103271484375, 1044.4073486328125), (524.9378051757812, 1039.73681640625),(556.220703125, 1039.1881103515625), (580.3787231445312, 1041.2032470703125), (621.1373291015625, 1043.18505859375), (645.4550170898438, 1045.1834716796875), (660.99560546875, 1046.1826171875), (688.3687133789062, 1048.084716796875), (696.0332641601562, 1049.679931640625), (700.0830078125, 1051.206298828125), (701.1943359375, 1051.1787109375), (703.0236206054688, 1052.177978515625),(705.0208129882812, 1053.17724609375)])
        post_action(1.401969)
        perform_swipe_event([(84.88211059570312, 1060.1717529296875), (157.16188049316406, 1069.02392578125),(220.31919860839844, 1067.937255859375), (309.6777648925781, 1060.9981689453125), (367.86346435546875, 1053.606201171875), (415.42303466796875, 1046.682373046875), (458.12103271484375, 1044.4073486328125), (524.9378051757812, 1039.73681640625), (556.220703125, 1039.1881103515625), (580.3787231445312, 1041.2032470703125),(621.1373291015625, 1043.18505859375), (645.4550170898438, 1045.1834716796875),(660.99560546875, 1046.1826171875), (688.3687133789062, 1048.084716796875), (696.0332641601562, 1049.679931640625), (700.0830078125, 1051.206298828125), (701.1943359375, 1051.1787109375), (703.0236206054688, 1052.177978515625),(705.0208129882812, 1053.17724609375)])
        post_action(1.401969)
        perform_swipe_event([(84.88211059570312, 1060.1717529296875), (157.16188049316406, 1069.02392578125),(220.31919860839844, 1067.937255859375), (309.6777648925781, 1060.9981689453125), (367.86346435546875, 1053.606201171875), (415.42303466796875, 1046.682373046875), (458.12103271484375, 1044.4073486328125), (524.9378051757812, 1039.73681640625), (556.220703125, 1039.1881103515625), (580.3787231445312, 1041.2032470703125),(621.1373291015625, 1043.18505859375), (645.4550170898438, 1045.1834716796875), (660.99560546875, 1046.1826171875), (688.3687133789062, 1048.084716796875), (696.0332641601562, 1049.679931640625), (700.0830078125, 1051.206298828125),(701.1943359375, 1051.1787109375), (703.0236206054688, 1052.177978515625),(705.0208129882812, 1053.17724609375)])
        post_action(1.401969)
        perform_swipe_event([(84.88211059570312, 1060.1717529296875), (157.16188049316406, 1069.02392578125),(220.31919860839844, 1067.937255859375), (309.6777648925781, 1060.9981689453125),(367.86346435546875, 1053.606201171875), (415.42303466796875, 1046.682373046875),(458.12103271484375, 1044.4073486328125), (524.9378051757812, 1039.73681640625),(556.220703125, 1039.1881103515625), (580.3787231445312, 1041.2032470703125), (621.1373291015625, 1043.18505859375), (645.4550170898438, 1045.1834716796875),  (660.99560546875, 1046.1826171875), (688.3687133789062, 1048.084716796875), (696.0332641601562, 1049.679931640625), (700.0830078125, 1051.206298828125), (701.1943359375, 1051.1787109375), (703.0236206054688, 1052.177978515625),(705.0208129882812, 1053.17724609375)])
        post_action(1.401969)
        perform_swipe_event([(84.88211059570312, 1060.1717529296875), (157.16188049316406, 1069.02392578125),(220.31919860839844, 1067.937255859375), (309.6777648925781, 1060.9981689453125), (367.86346435546875, 1053.606201171875), (415.42303466796875, 1046.682373046875),  (458.12103271484375, 1044.4073486328125), (524.9378051757812, 1039.73681640625), (556.220703125, 1039.1881103515625), (580.3787231445312, 1041.2032470703125),(621.1373291015625, 1043.18505859375), (645.4550170898438, 1045.1834716796875), (660.99560546875, 1046.1826171875), (688.3687133789062, 1048.084716796875),(696.0332641601562, 1049.679931640625), (700.0830078125, 1051.206298828125),(701.1943359375, 1051.1787109375), (703.0236206054688, 1052.177978515625),(705.0208129882812, 1053.17724609375)])
        post_action(1.401969)
        perform_click_event("Tap", 167.766998, 375.706482, 0.055000, "Activity")
        post_action(1.401969)
    except Exception as e:

        print(e)

        traceback_str = ''.join(traceback.format_tb(e.__traceback__))

        print(traceback_str)

    os.system("adb shell am force-stop " + package_name)