# coding=utf8

import os
import sys
import time
import json
import argparse
import traceback
import uiautomator2 as u2
sys.path.append(os.path.abspath(os.getcwd()))
sys.path.append(os.path.abspath(os.getcwd()))
from sara_script import util

frida_session = None
xml = None
view_hierarchy = None
save_path = None
action_count = 0
current_popup_window = None
curr_webview_address = None

device_id = "emulator-5554"
os.system('adb connect -s ' + device_id)
d = u2.connect(device_id)
print(d.info)


def log(desc):
    global action_count
    print('[ReplayAction]-%d: ' % action_count, desc)


def error_handler(func):
    def wrapper(message, data):
        if message['type'] == 'error':
            print('[Func]: %s, [Error-msg]: %s' % (func.__name__, message))
            print('[Func]: %s, [Error-des]: %s' % (func.__name__, message['description']))
            print('[Func]: %s, [Error-sta]: %s' % (func.__name__, message['stack']))
            print('[Func]: %s, [Error-dat]: %s' % (func.__name__, data))
            return None
        else:
            return func(message, data)
    return wrapper


def preprocess_path():
    global save_path
    if save_path is None:
        return False
    if not os.path.exists(save_path):
        os.mkdir(save_path)
    else:
        for file in os.listdir(save_path):
            os.remove(os.path.join(save_path, file))
    return True


def post_action(custom_interval):
    global xml
    global d
    global action_count
    global save_path
    global view_hierarchy

    print('[ReplayTimeInterval]-%d: %s' % (action_count, json.dumps({'interval': custom_interval})))
    if action_count > 0:
        time.sleep(1)
        if custom_interval > 0:
            time.sleep(custom_interval)
    xml = d.dump_hierarchy()
    xml = util.parse_xml(xml)
    activity = d.app_current()['activity']
    activity_filename = os.path.join(save_path, '_'.join(['activity', str(action_count) + '.txt']))
    screenshot_filename = os.path.join(save_path, '_'.join(['screenshot', str(action_count)]) + '.jpg')
    xml_filename = os.path.join(save_path, '_'.join(['ui', str(action_count)]) + '.xml')
    view_hierarchy_filename = os.path.join(save_path, '_'.join(['view_hierarchy', str(action_count)]) + '.xml')
    d.screenshot(screenshot_filename)
    util.save_xml(xml, xml_filename)
    with open(activity_filename, 'w') as f:
        f.write(activity)
    f.close()
    view_hierarchy, lxml_view_hierarchy = util.dump_view_hierarchy(d, view_hierarchy_filename)
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


def press_soft_keyboard(key_name):
    global xml
    index = util.find_soft_key(key_name, xml)
    if index is None:
        raise Exception('Key ' + key_name + ' does not exist')
    key_x, key_y = index[0], index[1]
    d.click(key_x, key_y)
    log('[press_key]-%s' % json.dumps({'key_name': key_name}))


def hide_soft_keyboard():
    global xml
    if util.check_soft_keyboard(xml):
        print('Hide soft keyboard')
        d.press('back')
        log('[hide_keyboard]')


def record_popup_window():
    global current_popup_window
    current_popup_window = util.get_current_window(d)
    log('[record_popup_window]-%s' % json.dumps({'window': current_popup_window}))


def close_popup_window():
    global current_popup_window
    if current_popup_window is not None:
        window = util.get_current_window(d)
        if window == current_popup_window:
            d.press('back')
            log('[hide_popup_window]-%s' % json.dumps({'window': current_popup_window}))
            current_popup_window = None


@error_handler
def get_instrument_WebView_message(message, data):
    global curr_webview_address
    print('[WebView]: ', message)
    curr_webview_address = util.get_view_address(message['payload']['webview'])


def perform_click_event(tap_type, x, y, duration, view_type):
    global action_count
    global view_hierarchy

    if view_type == 'Activity':
        candidates = util.find_component_candidates(view_hierarchy, x, y)
        if tap_type == 'LongTap':
            d.long_click(x, y, duration)
        elif tap_type == 'Tap':
            d.long_click(x, y, duration)
        elif tap_type == 'DoubleTap':
            d.double_click(x, y, 0.1)

        log('[click]-%s' % json.dumps({'tap_type': tap_type, 'x': x, 'y': y, 'duration': duration, 'candidate': candidates, 'view_type': view_type}))

    else:
        # Dialog & PopupWindow
        # command `adb shell dumpsys activity top` fails to extract view hierarchy of Dialog & PopupWindow
        if tap_type == 'LongTap':
            d.long_click(x, y, duration)
        elif tap_type == 'Tap':
            d.long_click(x, y, duration)
        elif tap_type == 'DoubleTap':
            d.double_click(x, y, 0.1)
        log('[click]-%s' % json.dumps({'tap_type': tap_type, 'x': x, 'y': y, 'duration': duration, 'view_type': view_type}))


@error_handler
def get_instrument_view_message(message, data):
    print('[ReplayViewInstrumentation]: %s' % json.dumps(message))


def perform_swipe_event(pointers, duration=0.01):
    d.swipe_points(pointers, duration)
    log('[swipe]-%s' % json.dumps({'pointers': pointers, 'duration': duration}))


def perform_key_event(key_code):
    d.press(key_code)
    log('[press]-%s' % json.dumps({'key_code': key_code}))


def webview_set_text_with_u2(text):
    d(focused=True).set_text(text)
    log('[webview_set_text]-%s' % json.dumps({'text': text}))


@error_handler
def get_webview_set_text_message(message, data):
    print('[WebViewSetText]: ', message)

@error_handler
def get_instrument_chrome_client_message(message, data):
    print('[Console]: ', message)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Argument Parser')
    parser.add_argument('--path', help='save path', required=True)
    parser.add_argument('--package', help='package name', required=True)
    parser.add_argument('--main_activity', help='main activity name', required=True)
    args = parser.parse_args()
    save_path = args.path
    package_name = args.package
    activity_name = args.main_activity

    if not preprocess_path():
        print('Save path not found')
        sys.exit()

    os.system("adb shell am start -n "+package_name+"/"+activity_name)

    time.sleep(10)
    try:
        post_action(0)


        perform_click_event("Tap", 691.040222, 994.223267, 0.040000, "Activity")
        post_action(0.649812)
        record_popup_window()
        post_action(5.952300)
        perform_click_event("Tap", 559.223328, 827.353638, 0.195000, "None")
        post_action(0.035386)
        close_popup_window()
        post_action(3.202231)
        perform_click_event("Tap", 419.417480, 1026.198242, 0.080000, "Activity")
        post_action(2.755547)
        perform_click_event("Tap", 119.833565, 222.825912, 0.099000, "Activity")
        post_action(2.418183)
        set_text("ch.sbb.mobile.android.b2c:id/text", "[0,192][720,244]", "metalli")
        post_action(1.445878)
        perform_click_event("Tap", 667.761444, 1228.644806, 0.085000, "Activity")
        post_action(1.451753)
        perform_click_event("Tap", 135.811371, 445.651825, 0.112000, "Activity")
        post_action(3.072472)
        perform_click_event("DoubleTap", 353.509033, 792.380920, 0.068000, "Activity")
        post_action(0.048356)
        perform_click_event("Tap", 361.497925, 703.450439, 0.111000, "Activity")
        post_action(2.533381)
        perform_click_event("Tap", 127.822472, 1189.071045, 0.095000, "Activity")
        post_action(1.122964)
        perform_click_event("Tap", 108.848824, 212.833725, 0.099000, "Activity")
        post_action(1.645645)
        perform_click_event("Tap", 674.063843, 224.824356, 0.086000, "Activity")
        post_action(1.016976)
        set_text("ch.sbb.mobile.android.b2c:id/text", "[0,192][720,244]", "victor")
        post_action(1.574091)
        perform_click_event("Tap", 667.761444, 1228.644806, 0.085000, "Activity")
        post_action(1.384257)
        perform_click_event("Tap", 146.796127, 470.632324, 0.098000, "Activity")
        post_action(2.716006)
        perform_click_event("Tap", 585.187256, 1185.074219, 0.068000, "Activity")
        post_action(1.236889)
        perform_click_event("Tap", 36.948685, 118.907104, 0.095000, "Activity")
        post_action(3.434213)
        perform_swipe_event([(202.71844482421875, 432.6619873046875), (212.94142150878906, 465.5849304199219), (217.15054321289062, 483.65673828125), (223.3118438720703, 506.9029235839844), (228.86956787109375, 526.4321899414062), (236.67129516601562, 567.0841064453125), (239.073974609375, 581.387939453125), (242.0501251220703, 599.0771484375), (246.1297149658203, 619.637939453125), (249.09710693359375, 639.6018676757812), (251.59597778320312, 660.047607421875), (254.15130615234375, 678.739013671875), (258.2182922363281, 700.2222900390625), (264.9167175292969, 729.6635131835938), (271.2950744628906, 752.8753662109375), (276.4150695800781, 775.7858276367188), (277.61444091796875, 787.7603149414062), (281.2352600097656, 800.50390625), (282.60748291015625, 811.9019165039062), (284.0596008300781, 818.2689208984375), (284.604736328125, 822.8370971679688), (284.604736328125, 824.35595703125), (285.60333251953125, 825.7271728515625), (285.60333251953125, 826.3544311523438), (285.60333251953125, 827.3536376953125), (285.60333251953125, 828.3528442382812), (286.6019592285156, 828.3528442382812), (286.6019592285156, 827.3536376953125), (287.6268615722656, 824.3033447265625), (287.6005554199219, 817.9609375), (288.59918212890625, 811.5823974609375), (288.59918212890625, 804.195068359375), (287.9137268066406, 790.9500732421875), (286.6019592285156, 777.9921264648438), (284.1903991699219, 758.4284057617188), (276.6748962402344, 710.2142333984375), (270.6241455078125, 683.9656982421875), (266.1667785644531, 669.086669921875), (263.4228820800781, 659.8507080078125), (259.5530700683594, 646.2357788085938), (256.8415222167969, 633.6943359375), (252.9101104736328, 618.301025390625), (250.5606689453125, 605.7984008789062), (244.05966186523438, 580.3438720703125), (243.66159057617188, 576.6884765625), (242.66297912597656, 573.0523681640625), (241.66436767578125, 571.0684204101562), (241.66436767578125, 570.5542602539062), (240.54254150390625, 569.4317626953125), (240.66574096679688, 569.5550537109375)], 0.033000)
        post_action(0.369244)
        perform_click_event("Tap", 212.704575, 528.587036, 0.080000, "Activity")
        post_action(1.427890)
        perform_click_event("Tap", 88.876564, 276.783752, 0.099000, "Activity")
        post_action(5.789105)
        perform_swipe_event([(365.49237060546875, 1050.1795654296875), (378.1265869140625, 1011.3849487304688), (396.94635009765625, 945.5711669921875), (410.7328186035156, 879.8815307617188), (429.478271484375, 819.6904907226562), (437.4209899902344, 786.2431640625), (453.6612548828125, 718.7416381835938), (465.3319091796875, 678.20947265625), (480.8143615722656, 634.5756225585938), (483.3287353515625, 623.298583984375), (484.32733154296875, 620.1121826171875), (485.3259582519531, 620.5151977539062), (485.3259582519531, 624.4166259765625), (484.3978271484375, 638.9359741210938), (480.2518005371094, 685.0331420898438), (473.8351135253906, 745.627197265625), (461.7599182128906, 827.9425659179688), (455.3675537109375, 903.4880981445312), (456.3269958496094, 932.6245727539062), (454.7532958984375, 963.1682739257812), (452.4955749511719, 983.115478515625), (452.3717041015625, 1003.2518310546875), (453.3703308105469, 1021.7595825195312), (453.3703308105469, 1028.94873046875), (454.53399658203125, 1030.1951904296875), (454.3689270019531, 1031.947998046875), (454.3689270019531, 1032.193603515625)], 0.050000)
        post_action(0.646700)




    except Exception as e:

        print(e)

        traceback_str = ''.join(traceback.format_tb(e.__traceback__))

        print(traceback_str)

    os.system("adb shell am force-stop " + package_name)
    