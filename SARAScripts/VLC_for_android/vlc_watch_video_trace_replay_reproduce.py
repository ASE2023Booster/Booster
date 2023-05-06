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



        perform_click_event("Tap", 51.927879, 118.907104, 0.211000, "Activity")
        post_action(2.501277)
        perform_click_event("Tap", 450.374481, 206.838409, 0.236000, "Activity")
        post_action(1.860685)
        perform_click_event("Tap", 514.285706, 447.650269, 0.236000, "Activity")
        post_action(4.112269)
        perform_swipe_event([(537.2538452148438, 685.4644775390625), (536.208740234375, 664.550048828125), (536.2551879882812, 665.4801025390625), (537.753173828125, 648.9930419921875), (539.2510375976562, 642.498046875), (540.3722534179688, 634.6451416015625), (540.2496948242188, 635.5035400390625), (540.2496948242188, 629.028076171875), (541.9305419921875, 623.0970458984375), (542.2468872070312, 617.1300048828125), (542.2468872070312, 612.01318359375), (545.7420654296875, 595.03515625), (548.2425537109375, 580.522705078125), (551.5347900390625, 570.8020629882812), (553.9541625976562, 556.2243041992188), (557.2255859375, 545.57568359375), (558.2246704101562, 534.3500366210938), (560.221923828125, 524.2640380859375), (561.2327880859375, 519.544921875), (562.2191772460938, 509.9457702636719), (562.2191772460938, 499.1100769042969), (564.3866577148438, 486.9375305175781), (565.4928588867188, 479.7902526855469), (566.868408203125, 473.007568359375), (569.1055297851562, 464.0537109375), (570.373779296875, 458.9776916503906), (571.7059326171875, 453.64556884765625), (572.877685546875, 448.62957763671875), (574.3654174804688, 442.16522216796875), (575.3499755859375, 440.3577880859375), (575.2011108398438, 437.677490234375), (576.19970703125, 435.9356994628906), (576.9641723632812, 434.1298828125), (578.50537109375, 430.04632568359375), (579.6530151367188, 427.74957275390625), (579.195556640625, 425.86993408203125), (580.1942138671875, 423.00390625), (581.2125244140625, 421.65081787109375), (581.1928100585938, 417.0215148925781), (582.19140625, 413.67681884765625), (582.19140625, 409.5188903808594), (584.1886596679688, 405.0418395996094), (585.0759887695312, 402.7967224121094), (585.187255859375, 400.1883850097656), (586.0403442382812, 398.8341369628906), (586.1858520507812, 397.189697265625), (586.1858520507812, 397.6893005371094)])
        post_action(1.612211)
        perform_swipe_event([(540.2496948242188, 667.478515625), (543.7924194335938, 636.9902954101562), (545.2427368164062, 623.5128784179688), (551.0682983398438, 595.5327758789062), (553.6464233398438, 581.0538940429688), (557.1419677734375, 572.7211303710938), (560.3854370117188, 557.073486328125), (562.6311645507812, 545.510986328125), (565.6128540039062, 536.7838745117188), (568.4464721679688, 526.6446533203125), (571.8505859375, 519.3046264648438), (575.0547485351562, 510.8939514160156), (578.4053344726562, 502.9809875488281), (580.9268188476562, 493.1474609375), (582.4083251953125, 488.18414306640625), (582.19140625, 484.62139892578125), (582.19140625, 483.6221618652344), (582.19140625, 482.2269287109375), (583.1900024414062, 481.175537109375), (583.1900024414062, 480.62451171875), (583.1900024414062, 479.62530517578125), (583.1900024414062, 478.3858947753906), (584.1886596679688, 477.6268615722656), (584.1886596679688, 476.62762451171875), (584.1886596679688, 475.62841796875), (585.9573974609375, 472.859375), (587.2339477539062, 470.5828552246094), (588.18310546875, 467.147705078125), (590.0445556640625, 464.7727966308594), (591.23583984375, 462.58160400390625), (592.1775512695312, 459.4051818847656), (593.1761474609375, 456.7853088378906), (594.4757690429688, 454.3436279296875), (595.1734008789062, 452.146728515625), (596.0960083007812, 451.72320556640625), (596.1719970703125, 450.4476623535156), (596.1719970703125, 449.14910888671875), (597.1705932617188, 447.93890380859375), (598.6685791015625, 446.1514587402344), (598.1692504882812, 445.6518249511719), (599.0507202148438, 443.7705993652344), (599.1678466796875, 442.6541748046875), (599.1678466796875, 441.65496826171875), (600.1664428710938, 441.65496826171875), (600.1664428710938, 440.6557312011719)])
        post_action(2.736214)
        perform_click_event("Tap", 491.317627, 511.552673, 0.112000, "Activity")
        post_action(1.287439)
        perform_click_event("Tap", 492.316223, 1222.045288, 0.125000, "Activity")
        post_action(0.000000)




    except Exception as e:

        print(e)

        traceback_str = ''.join(traceback.format_tb(e.__traceback__))

        print(traceback_str)

    os.system("adb shell am force-stop " + package_name)