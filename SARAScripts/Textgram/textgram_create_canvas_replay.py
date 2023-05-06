# coding=utf8

import os
import sys
import time
import json
import frida
import argparse
import traceback
import uiautomator2 as u2
sys.path.append(os.path.abspath(os.getcwd()))
from script import util

frida_session = None
xml = None
view_hierarchy = None
save_path = None
action_count = 0
current_popup_window = None
curr_webview_address = None

d = u2.connect()
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
        # time.sleep(1)
        if custom_interval > 0:
            time.sleep(custom_interval)
    xml = d.dump_hierarchy()
    xml = util.parse_xml(xml)
    screenshot_filename = os.path.join(save_path, '_'.join(['screenshot', str(action_count)]) + '.jpg')
    xml_filename = os.path.join(save_path, '_'.join(['ui', str(action_count)]) + '.xml')
    view_hierarchy_filename = os.path.join(save_path, '_'.join(['view_hierarchy', str(action_count)]) + '.xml')
    d.screenshot(screenshot_filename)
    util.save_xml(xml, xml_filename)
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


def clean_up():
    global frida_session
    print('Clean Up....')
    frida_session.detach()


def detect_webview():
    # Get WebView handle
    global frida_session
    instrument_script = frida_session.create_script(util.instrument_WebView())
    instrument_script.on('message', get_instrument_WebView_message)
    instrument_script.load()


@error_handler
def get_instrument_WebView_message(message, data):
    global curr_webview_address
    print('[WebView]: ', message)
    curr_webview_address = util.get_view_address(message['payload']['webview'])


def perform_click_event(tap_type, x, y, duration, view_type):
    global action_count
    global view_hierarchy
    global frida_session

    if view_type == 'Activity':
        candidates = util.find_component_candidates(view_hierarchy, x, y)
        # Instrument
        instrument_script = None
        code = util.instrument_view([candidate['classname'] for candidate in candidates], [candidate['address'] for candidate in candidates], action_count)
        instrument_script = frida_session.create_script(code)
        instrument_script.on('message', get_instrument_view_message)
        instrument_script.load()
        if tap_type == 'LongTap':
            d.long_click(x, y, duration)
        elif tap_type == 'Tap':
            d.long_click(x, y, duration)
        elif tap_type == 'DoubleTap':
            d.double_click(x, y, 0.1)

        # time.sleep(1)
        instrument_script.unload()
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


def webview_set_text(input_selector, text, webview_classname, package_name):
    # Set Text
    global curr_webview_address
    code = util.webview_set_text(input_selector, text, webview_classname, curr_webview_address, package_name)
    instrument_script = frida_session.create_script(code)
    instrument_script.on('message', get_webview_set_text_message)
    instrument_script.load()


def webview_set_text_with_u2(text):
    d(focused=True).set_text(text)
    log('[webview_set_text]-%s' % json.dumps({'text': text}))


@error_handler
def get_webview_set_text_message(message, data):
    print('[WebViewSetText]: ', message)


def instrument_chrome_client():
    code = util.instrument_chrome_client()
    script = frida_session.create_script(code)
    script.on('message', get_instrument_chrome_client_message)
    script.load()


@error_handler
def get_instrument_chrome_client_message(message, data):
    print('[Console]: ', message)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Argument Parser')
    parser.add_argument('--path', help='save path', required=True)
    parser.add_argument('--package', help='package name', required=True)
    parser.add_argument('--pid', help='pid name', required=True)
    args = parser.parse_args()
    
    save_path = args.path
    package_name = args.package
    pid = int(args.pid)

    if not preprocess_path():
        print('Save path not found')
        sys.exit()

    # Setup Dynamic instrument   
    all_devices = frida.enumerate_devices()
    device = frida.get_usb_device()

    # Attach
    frida_session = device.attach(pid)
    print(frida_session)

    try:
        detect_webview()
        # instrument_chrome_client()
        post_action(0)

        perform_click_event("Tap", 630.124817, 1102.138916, 0.042000, "Activity")
        post_action(1.412299)
        perform_click_event("Tap", 617.142883, 964.246704, 0.041000, "Activity")
        post_action(2.754915)
        perform_click_event("Tap", 674.063843, 108.914909, 0.055000, "Activity")
        post_action(2.493982)
        perform_click_event("Tap", 163.772537, 1040.187378, 0.082000, "Activity")
        post_action(3.032252)
        perform_click_event("Tap", 361.497925, 1006.213867, 0.095000, "Activity")
        post_action(5.764774)
        perform_click_event("Tap", 257.642181, 962.248230, 0.142000, "Dialog")
        post_action(2.148161)
        perform_click_event("Tap", 32.954231, 122.903984, 0.099000, "Activity")
        post_action(0.953635)
        perform_click_event("Tap", 70.901527, 123.903198, 0.099000, "Activity")
        post_action(0.847928)
        perform_click_event("Tap", 573.203918, 755.409851, 0.069000, "Dialog")
        post_action(1.857043)
        perform_click_event("Tap", 634.119263, 1105.136597, 0.081000, "Activity")
        post_action(1.068469)
        perform_click_event("Tap", 637.115112, 794.379395, 0.068000, "Activity")
        post_action(2.488869)
        perform_click_event("Tap", 681.054077, 108.914909, 0.084000, "Activity")
        post_action(1.988365)
        perform_click_event("Tap", 129.819702, 1030.195190, 0.081000, "Activity")
        post_action(3.217517)
        perform_click_event("Tap", 338.529816, 1014.207642, 0.124000, "Activity")
        post_action(5.871903)
        perform_click_event("Tap", 257.642181, 954.254517, 0.128000, "Dialog")
        post_action(1.450198)
        perform_click_event("Tap", 37.947296, 122.903984, 0.099000, "Activity")
        post_action(1.068341)
        perform_click_event("Tap", 46.934814, 126.900856, 0.068000, "Activity")
        post_action(0.735336)
        perform_click_event("Tap", 595.173401, 737.423889, 0.086000, "Dialog")
        post_action(1.300510)
        perform_click_event("LongTap", 156.782257, 387.697113, 1.440000, "Activity")
        post_action(0.000000)
        record_popup_window()
        post_action(4.302521)
        perform_click_event("Tap", 147.794739, 639.500366, 0.141000, "None")
        post_action(0.115913)
        close_popup_window()
        post_action(1.453789)
        perform_click_event("Tap", 593.176147, 731.428589, 0.084000, "Dialog")
        post_action(1.054739)
        perform_click_event("LongTap", 165.769775, 422.669800, 0.959000, "Activity")
        post_action(0.000000)
        record_popup_window()
        post_action(1.733907)
        perform_click_event("Tap", 166.768387, 635.503540, 0.139000, "None")
        post_action(0.081192)
        close_popup_window()
        post_action(1.151159)
        perform_click_event("Tap", 582.191406, 736.424683, 0.082000, "Dialog")
        post_action(0.000000)

    except Exception as e:
        print(e)
        traceback_str = ''.join(traceback.format_tb(e.__traceback__))
        print(traceback_str)
    clean_up()
    