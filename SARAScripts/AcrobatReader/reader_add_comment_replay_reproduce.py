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
        perform_click_event("Tap", 461.202515, 562.701019, 0.080000, "Activity")
        post_action(2.761031)
        perform_swipe_event([(519.27880859375, 958.2513427734375), (516.282958984375, 936.2685546875), (516.0676879882812, 859.6998901367188), (520.7767333984375, 809.8672485351562), (530.740234375, 746.5526733398438), (544.0120239257812, 683.0933227539062), (560.1576538085938, 614.551025390625), (576.6317138671875, 537.8944091796875), (593.24267578125, 476.9609375), (611.1311645507812, 409.7534484863281), (620.328369140625, 381.5372009277344), (624.3930053710938, 366.19354248046875), (627.1290283203125, 355.40350341796875), (628.144287109375, 350.7093200683594), (628.1276245117188, 350.7259826660156)], 0.067000)
        post_action(0.470829)
        perform_swipe_event([(516.282958984375, 907.2911987304688), (516.282958984375, 891.252197265625), (518.770263671875, 859.947998046875), (526.4231567382812, 798.216552734375), (534.014404296875, 744.8572998046875), (546.698974609375, 693.2639770507812), (559.349609375, 650.9855346679688), (570.92919921875, 616.592529296875), (583.3157958984375, 579.9171752929688), (589.1817016601562, 565.314697265625), (590.6621704101562, 564.0767822265625), (589.1817016601562, 564.5589599609375)], 0.066000)
        post_action(0.755927)
        perform_swipe_event([(3.9944522380828857, 875.316162109375), (39.944522857666016, 879.8126831054688), (59.59731674194336, 879.3130493164062), (85.2369384765625, 881.3114624023438), (115.05673217773438, 882.3106689453125), (139.4974822998047, 881.3114624023438), (162.3535919189453, 879.4550170898438), (186.00941467285156, 878.3138427734375), (209.20944213867188, 877.3145751953125), (232.17208862304688, 876.3153686523438), (244.2633514404297, 875.1382446289062), (262.8575439453125, 874.0393676757812), (291.0665588378906, 873.3177490234375), (303.3184814453125, 872.4234008789062), (339.5143737792969, 869.8214721679688), (371.0977478027344, 868.3215942382812), (393.5507507324219, 867.316650390625), (430.5784606933594, 865.196044921875), (456.43865966796875, 862.3190307617188), (500.13153076171875, 858.7927856445312), (539.9844360351562, 855.9931030273438), (565.3644409179688, 853.936767578125), (582.2723999023438, 852.31787109375), (599.634033203125, 851.0267944335938), (614.6463623046875, 848.8367919921875), (630.005126953125, 845.0464477539062), (643.5978393554688, 841.8450927734375), (654.4684448242188, 837.6568603515625), (660.4913330078125, 835.2113037109375), (664.0777587890625, 835.347412109375), (665.0626220703125, 834.34814453125), (665.0762939453125, 834.34814453125)], 0.033000)
        post_action(0.587417)
        perform_click_event("Tap", 493.314850, 339.734589, 0.124000, "Activity")
        post_action(1.476494)
        perform_click_event("Tap", 55.925106, 1227.049194, 0.098000, "Activity")
        post_action(3.078340)
        perform_click_event("Tap", 662.080444, 812.365356, 0.138000, "Activity")
        post_action(2.510995)
        set_text("com.adobe.reader:id/popupnotewidget_edittext", "[72,40][648,507]", "comment")
        post_action(0.947081)
        perform_click_event("Tap", 565.195557, 467.636230, 0.128000, "Activity")
        post_action(2.114534)
        perform_swipe_event([(469.34814453125, 1064.1685791015625), (468.41455078125, 1023.549072265625), (475.55377197265625, 965.7457885742188), (480.53240966796875, 910.6917724609375), (485.27044677734375, 815.0859985351562), (488.8946838378906, 763.7979736328125), (497.9251403808594, 688.9671020507812), (512.4041137695312, 614.2338256835938), (531.0055541992188, 537.18896484375), (547.87841796875, 484.9325256347656), (558.4420776367188, 455.99072265625), (562.2191772460938, 443.8135070800781), (565.7142333984375, 434.660400390625), (567.42529296875, 427.4526672363281), (569.20947265625, 424.668212890625)], 0.050000)
        post_action(0.377446)
        perform_swipe_event([(384.4660339355469, 1023.2006225585938), (386.8113098144531, 983.3064575195312), (399.359375, 932.6152954101562), (413.1919860839844, 881.2481079101562), (424.48651123046875, 841.07666015625), (435.1558837890625, 807.848388671875), (441.1009521484375, 784.24658203125), (445.8487854003906, 769.462890625), (448.37725830078125, 762.4043579101562), (447.378662109375, 762.4043579101562)], 0.050000)
        post_action(0.566458)
        perform_click_event("Tap", 49.940361, 1229.040649, 0.082000, "Activity")
        post_action(0.898289)
        perform_click_event("Tap", 327.545074, 877.314575, 0.055000, "Activity")
        post_action(1.660279)
        set_text("com.adobe.reader:id/popupnotewidget_edittext", "[72,40][648,507]", "comment e")
        post_action(1.355795)
        perform_click_event("Tap", 565.185852, 467.629181, 0.168000, "Activity")
        post_action(0.000000)




    except Exception as e:

        print(e)

        traceback_str = ''.join(traceback.format_tb(e.__traceback__))

        print(traceback_str)

    os.system("adb shell am force-stop " + package_name)
    