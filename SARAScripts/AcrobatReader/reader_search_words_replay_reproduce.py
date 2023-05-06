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

        perform_click_event("Tap", 203.717072, 233.817337, 0.143000, "Activity")
        post_action(1.563048)
        perform_click_event("Tap", 243.303741, 564.692413, 0.026000, "Activity")
        post_action(2.830010)
        perform_swipe_event([(518.2801513671875, 854.3325805664062), (514.2153930664062, 816.306396484375), (506.1685485839844, 727.8118286132812), (505.4043884277344, 614.6061401367188), (530.5836791992188, 405.0271911621094), (556.8649291992188, 317.59576416015625), (560.221923828125, 309.75799560546875), (559.2233276367188, 309.75799560546875), (558.2246704101562, 313.856201171875), (553.9672241210938, 341.683349609375), (544.2720336914062, 439.2935791015625), (542.2468872070312, 566.9478759765625), (548.7797241210938, 688.0684814453125), (555.881103515625, 736.3436889648438), (571.006591796875, 820.2572631835938), (577.5930786132812, 847.3143310546875), (581.40625, 864.9654541015625), (582.9005126953125, 879.8630981445312), (586.384765625, 894.2972412109375), (590.57080078125, 916.1527709960938), (595.338623046875, 940.2581176757812), (596.9052734375, 953.6608276367188), (598.1692504882812, 973.2396850585938)], 0.050000)
        post_action(0.536362)
        perform_click_event("Tap", 585.187256, 74.941452, 0.055000, "Activity")
        post_action(2.432746)
        set_text("com.adobe.reader:id/search_src_text", "[160,20][704,92]", "blockchain")
        post_action(0.471146)
        perform_click_event("Tap", 673.187256, 1230.941452, 0.055000, "Activity")
        post_action(6.302902)
        perform_swipe_event([(576.19970703125, 516.596435546875), (572.25537109375, 483.1245422363281), (572.2052612304688, 469.3913879394531), (573.1290283203125, 436.55865478515625), (575.6028442382812, 391.8661193847656), (578.5936889648438, 362.3331298828125), (581.435546875, 331.8236083984375), (584.8363037109375, 310.19085693359375), (594.8260498046875, 276.75775146484375), (599.8753662109375, 264.492919921875), (607.6560668945312, 237.814208984375), (610.6519165039062, 232.31849670410156), (612.1701049804688, 221.7657012939453), (613.29541015625, 218.68197631835938), (613.1484375, 218.82904052734375)], 0.033000)
        post_action(0.462787)
        perform_swipe_event([(462.35784912109375, 917.2833862304688), (464.79449462890625, 867.7216186523438), (468.3207092285156, 821.6756591796875), (479.8128662109375, 748.7310791015625), (490.3187255859375, 688.0638427734375), (500.804443359375, 639.0007934570312), (505.8016052246094, 609.7056274414062), (511.1866455078125, 581.8380737304688), (520.8018798828125, 539.4779052734375), (526.9647216796875, 492.3344421386719), (529.0990600585938, 477.789306640625), (534.258056640625, 448.14990234375), (535.957763671875, 435.4469909667969), (536.2551879882812, 428.5539855957031), (537.2538452148438, 420.1752014160156), (538.25244140625, 414.185302734375), (538.25244140625, 411.6683044433594), (539.5960693359375, 411.6783752441406), (539.2510375976562, 411.6783752441406), (538.25244140625, 411.6783752441406)], 0.033000)
        post_action(0.581588)
        perform_swipe_event([(380.4715881347656, 1053.17724609375), (381.4701843261719, 1032.193603515625), (391.95562744140625, 963.2474975585938), (409.47491455078125, 869.2332763671875), (444.9752197265625, 743.5906372070312), (471.5127258300781, 652.470703125), (489.30718994140625, 588.5887451171875), (501.7772521972656, 540.3864135742188), (504.7989196777344, 518.09521484375), (513.4276123046875, 486.4126892089844), (517.60986328125, 470.317626953125), (521.72265625, 450.8586120605469), (521.2760009765625, 445.22943115234375), (522.1156616210938, 438.9754943847656), (522.274658203125, 438.65728759765625), (521.2760009765625, 438.65728759765625)], 0.033000)
        post_action(0.447231)
        perform_swipe_event([(344.5215148925781, 996.2216796875), (352.4746398925781, 949.21435546875), (365.1041564941406, 875.426513671875), (396.44940185546875, 757.9078369140625), (409.9306640625, 716.9398803710938), (436.91644287109375, 654.3947143554688), (445.8824157714844, 636.4993286132812), (459.8351745605469, 617.5594482421875), (463.10595703125, 611.7728881835938), (463.3564453125, 611.522216796875), (462.35784912109375, 610.5230102539062)], 0.033000)
        post_action(0.470340)
        perform_click_event("Tap", 568.210815, 636.502747, 0.072000, "Activity")
        post_action(2.015395)
        perform_swipe_event([(634.1192626953125, 902.2951049804688), (627.6047973632812, 860.5771484375), (646.1026611328125, 587.7653198242188), (646.1026611328125, 544.5745239257812)], 0.034000)
        post_action(0.365742)
        perform_click_event("DoubleTap", 626.130371, 418.672913, 0.072000, "Activity")
        post_action(0.068728)
        perform_swipe_event([(384.4660339355469, 753.411376953125), (490.5721740722656, 612.8096923828125), (618.1414794921875, 422.3588562011719), (620.6380615234375, 419.672119140625), (622.9371948242188, 417.6737060546875), (623.134521484375, 417.6737060546875), (622.1359252929688, 419.672119140625), (600.158935546875, 434.9158630371094), (558.6373291015625, 450.6479187011719), (543.1827392578125, 452.6463623046875), (541.248291015625, 452.6463623046875), (540.2496948242188, 452.6463623046875)], 0.150000)
        post_action(1.268364)
        perform_swipe_event([(456.3661804199219, 1096.1436767578125), (460.9458312988281, 1057.1927490234375), (485.2451171875, 916.7694091796875), (496.89801025390625, 810.8377075195312), (501.3037414550781, 785.3319091796875), (502.3023681640625, 779.39111328125), (502.3023681640625, 778.3919067382812)], 0.133500)
        post_action(1.069250)
        perform_click_event("DoubleTap", 672.066589, 692.459045, 0.055000, "Activity")
        post_action(0.042089)
        perform_swipe_event([(539.2510375976562, 383.7002258300781), (536.2551879882812, 413.52862548828125), (540.2496948242188, 523.7438354492188), (533.2593994140625, 650.830810546875), (527.620849609375, 744.175048828125), (519.7802124023438, 877.3062133789062), (515.2843627929688, 916.6231689453125), (514.2857055664062, 923.2420654296875), (513.287109375, 924.2778930664062)], 0.150000)
        post_action(0.286114)
        perform_swipe_event([(509.29266357421875, 415.6752624511719), (505.5539855957031, 438.352294921875), (501.3037414550781, 524.890380859375), (496.3106994628906, 586.9771728515625), (492.57965087890625, 674.5161743164062), (487.32318115234375, 834.6864624023438), (481.661376953125, 939.953125), (479.3342590332031, 962.2482299804688), (478.3356628417969, 965.7454833984375), (476.83770751953125, 966.2451171875), (477.3370361328125, 967.2443237304688), (481.2029113769531, 938.9102783203125), (496.5503234863281, 825.5155029296875), (501.3037414550781, 651.5829467773438), (518.719970703125, 478.5433349609375), (528.830078125, 395.4328308105469), (529.264892578125, 385.69866943359375), (529.264892578125, 386.6979064941406)], 0.128000)
        post_action(1.638135)
        perform_swipe_event([(371.48406982421875, 971.2412109375), (370.63665771484375, 949.1951293945312), (386.31585693359375, 812.6935424804688), (387.46185302734375, 763.933837890625), (388.4604797363281, 738.9637451171875), (387.46185302734375, 733.427001953125)], 0.123000)
        post_action(0.413029)
        perform_click_event("Tap", 214.701813, 905.292725, 0.070000, "Activity")
        post_action(0.000000)




    except Exception as e:

        print(e)

        traceback_str = ''.join(traceback.format_tb(e.__traceback__))

        print(traceback_str)

    os.system("adb shell am force-stop " + package_name)
    