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
        focused = d(focused=True)
        if focused.count > 0:
            d(focused=True).set_text(text)
        else:
            d.shell('input text "%s"' % text)
        log('[set_text]-%s' % json.dumps({'rid': rid, 'text': text, 'bounds': bounds}))
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

        perform_click_event("Tap", 173.758667, 362.716614, 0.055000, "Activity")
        post_action(4.568777)
        perform_swipe_event([(64.90985107421875, 343.7314453125), (73.48494720458984, 376.36566162109375), (75.92667388916016, 422.408935546875), (76.89320373535156, 491.6159362792969), (74.89598083496094, 543.4012451171875), (74.89598083496094, 591.0602416992188), (80.81744384765625, 658.4257202148438), (88.47640228271484, 722.828857421875), (93.77056121826172, 775.9512329101562), (98.08879852294922, 794.8916625976562), (106.16535949707031, 818.0647583007812), (116.84153747558594, 842.3495483398438), (129.8197021484375, 861.82666015625), (139.56900024414062, 873.0806884765625), (148.13058471679688, 876.649169921875), (161.4598388671875, 879.2604370117188), (181.03684997558594, 878.059814453125), (202.21914672851562, 876.81494140625), (219.1776885986328, 877.3145751953125), (229.75784301757812, 877.3145751953125)], 0.033000)
        post_action(0.598491)
        perform_swipe_event([(383.4674072265625, 320.7494201660156), (359.4295654296875, 309.43060302734375), (334.19879150390625, 309.8182373046875), (291.8817138671875, 312.8507385253906), (260.2768859863281, 321.39862060546875), (241.6610565185547, 329.8865661621094), (235.96896362304688, 335.36712646484375), (229.9224090576172, 345.24676513671875), (229.34156799316406, 347.748046875), (229.68099975585938, 369.94970703125), (230.64590454101562, 388.0893249511719), (234.674072265625, 457.14288330078125), (230.16159057617188, 501.5174865722656), (223.9744110107422, 537.9141845703125), (219.69485473632812, 570.0546264648438), (217.69764709472656, 605.8780517578125), (220.0957794189453, 645.5177612304688), (223.55177307128906, 675.9387817382812), (227.7451629638672, 713.3033447265625), (232.44061279296875, 741.0018310546875), (236.67129516601562, 759.9063720703125), (238.45034790039062, 767.7447509765625), (242.36627197265625, 778.7973022460938), (242.66297912597656, 781.3895263671875)], 0.033000)
        post_action(0.356713)
        perform_swipe_event([(349.5145568847656, 487.6190490722656), (348.5199890136719, 528.5385131835938), (347.01800537109375, 569.055419921875), (343.7274169921875, 610.8359375), (342.5242919921875, 660.6299438476562), (346.7519836425781, 713.2456665039062), (349.3299255371094, 748.566162109375), (355.8572082519531, 789.942138671875), (359.1309814453125, 822.6550903320312), (360.6164245605469, 839.9300537109375), (360.49932861328125, 849.1148071289062), (360.49932861328125, 855.4193725585938), (361.4481201171875, 864.1254272460938), (361.4979248046875, 871.4857788085938), (362.4965515136719, 872.3184814453125)], 0.033000)
        post_action(0.295005)
        perform_swipe_event([(503.3009948730469, 754.41064453125), (500.3051452636719, 737.4238891601562), (495.5217590332031, 694.55712890625), (490.29815673828125, 622.2426147460938), (488.32177734375, 564.948974609375), (489.3204040527344, 509.102294921875), (490.3190002441406, 454.05902099609375), (489.3204040527344, 419.5752868652344), (491.1608581542969, 391.9496154785156), (495.5715637207031, 379.05426025390625), (500.30511474609375, 364.715087890625), (506.2933654785156, 353.7282409667969), (509.6991882324219, 349.1844177246094), (517.1132202148438, 344.8149108886719), (536.7760620117188, 342.9573669433594), (566.537353515625, 339.3745422363281), (591.9799194335938, 336.33709716796875), (617.2216186523438, 332.7312927246094), (633.224853515625, 331.7408142089844), (642.108154296875, 331.7408142089844), (643.1068115234375, 331.7408142089844)], 0.033000)
        post_action(0.271212)
        perform_swipe_event([(622.1359252929688, 477.6268615722656), (625.1317749023438, 510.0189208984375), (626.13037109375, 535.9949340820312), (626.13037109375, 568.7701416015625), (627.1290283203125, 605.21435546875), (629.5731201171875, 645.2091064453125), (633.0787963867188, 672.701904296875), (637.3076171875, 704.606201171875), (637.1151123046875, 732.3275756835938), (635.6171875, 754.91015625), (632.6697387695312, 790.317626953125), (629.5087280273438, 818.3706665039062), (627.2320556640625, 847.2034912109375), (624.9500732421875, 865.5973510742188), (623.134521484375, 877.814208984375), (617.1806030273438, 885.2706298828125), (613.8135986328125, 887.5291748046875), (602.935791015625, 894.6371459960938), (591.6510620117188, 901.5592651367188), (579.4822998046875, 906.9765625), (561.7435913085938, 911.0606689453125), (543.2025756835938, 917.295654296875), (529.38427734375, 922.9058227539062)], 0.033000)
        post_action(0.000000)

    except Exception as e:
        print(e)
        traceback_str = ''.join(traceback.format_tb(e.__traceback__))
        print(traceback_str)
    clean_up()
    