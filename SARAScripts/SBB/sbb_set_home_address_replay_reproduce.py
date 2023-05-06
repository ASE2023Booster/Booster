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



        perform_click_event("Tap", 53.925106, 119.906326, 0.084000, "Activity")
        post_action(1.478193)
        perform_click_event("Tap", 460.360626, 209.836060, 0.112000, "Activity")
        post_action(1.014577)
        perform_click_event("Tap", 455.367554, 329.742401, 0.084000, "Activity")
        post_action(1.501154)
        perform_click_event("Tap", 582.191406, 228.821228, 0.068000, "Activity")
        post_action(1.653134)
        perform_click_event("Tap", 667.073547, 218.829041, 0.095000, "Activity")
        post_action(1.451874)
        set_text("ch.sbb.mobile.android.b2c:id/text", "[0,192][720,244]", "victor")
        post_action(0.868924)
        perform_click_event("Tap", 667.761444, 1228.644806, 0.085000, "Activity")
        post_action(2.015837)
        perform_click_event("Tap", 501.303741, 452.646362, 0.111000, "Activity")
        post_action(3.867649)
        perform_click_event("Tap", 53.925106, 110.913345, 0.112000, "Activity")
        post_action(1.454924)
        perform_click_event("Tap", 39.944523, 109.914131, 0.143000, "Activity")
        post_action(1.717669)
        perform_click_event("Tap", 74.895981, 111.912567, 0.111000, "Activity")
        post_action(1.135623)
        perform_click_event("Tap", 611.151184, 768.399658, 0.081000, "Activity")
        post_action(3.219047)
        perform_swipe_event([(619.1400756835938, 328.7431640625), (596.1719970703125, 332.74005126953125), (576.9404296875, 336.39447021484375), (555.3929443359375, 340.1393737792969), (546.732177734375, 342.1712341308594), (529.0662231445312, 346.5290222167969), (519.7346801757812, 348.86334228515625), (500.1513671875, 353.96966552734375), (473.74853515625, 361.0985107421875), (447.9844055175781, 367.1918029785156), (423.6107177734375, 372.6590881347656), (406.6650390625, 375.89886474609375), (382.0937805175781, 379.58990478515625), (356.5048522949219, 382.2013854980469), (337.69464111328125, 382.7010192871094), (327.26104736328125, 382.7010192871094), (312.1889343261719, 381.5051574707031), (292.2056884765625, 381.7017822265625), (270.97650146484375, 380.70257568359375), (243.32574462890625, 380.70257568359375), (221.48931884765625, 379.703369140625), (204.05397033691406, 378.7041320800781), (186.2413330078125, 377.7049255371094), (177.57696533203125, 376.7056884765625), (161.447021484375, 375.4851989746094), (152.45843505859375, 375.70648193359375), (145.7991180419922, 375.70648193359375), (136.96713256835938, 374.7072448730469), (132.8081512451172, 374.4555969238281), (125.13566589355469, 373.7080383300781), (118.7258071899414, 373.7080383300781), (116.44202423095703, 372.5108642578125), (113.34258270263672, 372.7088317871094), (111.10189819335938, 372.7088317871094), (108.84056091308594, 372.7088317871094), (108.84882354736328, 372.7088317871094)], 0.033000)
        post_action(1.069023)
        perform_swipe_event([(636.1165161132812, 352.72442626953125), (615.1456298828125, 355.7220764160156), (593.3417358398438, 359.12432861328125), (575.4075317382812, 361.1919860839844), (559.8078002929688, 361.6524353027344), (539.466064453125, 361.7174072265625), (517.1146850585938, 362.71661376953125), (507.1708068847656, 363.4285583496094), (478.67083740234375, 364.9570617675781), (456.05450439453125, 367.04443359375), (441.7090148925781, 368.4541015625), (420.9732360839844, 369.7111511230469), (408.6590576171875, 370.9413146972656), (384.466064453125, 374.707275390625), (372.18157958984375, 376.1664123535156), (349.795654296875, 377.9195861816406), (340.09063720703125, 377.7049255371094), (313.8270263671875, 378.7041320800781), (293.12939453125, 379.703369140625), (267.6654357910156, 380.70257568359375), (242.7655487060547, 381.7017822265625), (222.16302490234375, 380.6439208984375), (200.72653198242188, 380.0787353515625), (183.60873413085938, 379.703369140625), (170.3546142578125, 379.703369140625), (157.2316131591797, 379.703369140625), (144.217041015625, 379.703369140625), (129.32040405273438, 379.703369140625), (116.67173767089844, 380.70257568359375), (105.03288269042969, 380.70257568359375), (95.93620300292969, 381.7017822265625), (93.44532012939453, 381.7017822265625), (88.92733764648438, 381.7017822265625), (86.61510467529297, 381.7017822265625), (84.51747131347656, 381.7017822265625), (83.88349914550781, 381.7017822265625), (82.91339111328125, 381.7017822265625), (82.8848876953125, 381.7017822265625), (81.88626861572266, 381.7017822265625)], 0.033000)
        post_action(2.228496)
        perform_click_event("Tap", 170.762833, 327.743958, 0.095000, "Activity")
        post_action(3.222651)
        perform_click_event("Tap", 392.454926, 230.819672, 0.081000, "Activity")
        post_action(1.352927)
        set_text("ch.sbb.mobile.android.b2c:id/text", "[0,192][720,244]", "metalli")
        post_action(0.348063)
        perform_click_event("Tap", 667.761444, 1228.644806, 0.085000, "Activity")
        post_action(2.468735)
        perform_click_event("Tap", 82.884888, 443.653381, 0.112000, "Activity")
        post_action(6)




    except Exception as e:

        print(e)

        traceback_str = ''.join(traceback.format_tb(e.__traceback__))

        print(traceback_str)

    os.system("adb shell am force-stop " + package_name)
    