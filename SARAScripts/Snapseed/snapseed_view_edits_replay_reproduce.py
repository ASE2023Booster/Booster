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

        perform_click_event("Tap", 72.147034, 107.161621, 0.080000, "Activity")
        post_action(2.038942)
        perform_click_event("Tap", 495.147034, 1018.161621, 0.080000, "Activity")
        post_action(2.038942)
        perform_click_event("Tap", 460.360626, 1240.031250, 0.112000, "Activity")
        post_action(0.904086)
        perform_click_event("Tap", 358.360626, 877.031250, 0.112000, "Activity")
        post_action(0.904086)
        perform_click_event("Tap", 98.862694, 762.404358, 0.156000, "Activity")
        post_action(1.937123)
        perform_click_event("Tap", 660.083252, 280.780640, 0.081000, "Activity")
        post_action(0.625414)
        record_popup_window()
        post_action(4.250260)
        perform_click_event("Tap", 457.364777, 304.761902, 0.098000, "None")
        post_action(0.077722)
        close_popup_window()
        post_action(5.738036)
        perform_click_event("Tap", 597.170593, 107.915688, 0.212000, "Activity")
        post_action(1.776160)
        perform_click_event("Tap", 451.373108, 882.310669, 0.123000, "Dialog")
        post_action(2.841678)
        perform_click_event("Tap", 594.174744, 928.274780, 0.223000, "Activity")
        post_action(0.042274)
        record_popup_window()
        post_action(4.910670)
        perform_click_event("Tap", 435.395294, 921.280273, 0.124000, "None")
        post_action(0.014026)
        close_popup_window()
        post_action(3.481318)
        perform_click_event("Tap", 359.500702, 1236.034302, 0.112000, "Activity")
        post_action(1.884181)
        perform_click_event("Tap", 552.233032, 935.269348, 0.125000, "Activity")
        post_action(1.191788)
        perform_click_event("Tap", 54.923717, 1252.021851, 0.097000, "Activity")
        post_action(1.431519)
        perform_click_event("Tap", 626.130371, 1021.202209, 0.143000, "Activity")
        post_action(5.368850)
        perform_click_event("Tap", 547.239929, 1032.193604, 0.182000, "Activity")
        post_action(0.046848)
        record_popup_window()
        post_action(2.962704)
        perform_click_event("Tap", 453.370331, 1028.196777, 0.124000, "None")
        post_action(0.000000)
        close_popup_window()
        post_action(2.332932)
        perform_click_event("Tap", 292.593628, 1236.034302, 0.099000, "Activity")
        post_action(2.447213)
        perform_swipe_event([(390.45770263671875, 961.2490234375), (397.447998046875, 934.2700805664062), (402.5552673339844, 915.6463623046875), (408.39276123046875, 897.4190673828125), (417.15435791015625, 877.8467407226562), (422.86822509765625, 857.6004028320312), (430.40789794921875, 839.3291015625), (437.891845703125, 821.85791015625), (443.84423828125, 804.8094482421875), (450.1706237792969, 787.52783203125), (454.6634521484375, 773.5109252929688), (460.0054626464844, 761.8789672851562), (463.3290100097656, 748.9835815429688), (466.6646423339844, 738.1414184570312), (470.6372985839844, 725.7056274414062), (472.8006896972656, 714.1552734375), (476.8193359375, 706.48486328125), (480.5960388183594, 698.66357421875), (482.70257568359375, 693.7120971679688), (485.3259582519531, 689.4839477539062), (487.60736083984375, 688.462158203125), (488.32177734375, 685.964111328125), (490.4296569824219, 685.4644775390625), (490.3190002441406, 685.4644775390625), (490.3190002441406, 688.4837646484375), (489.3204040527344, 691.7625732421875), (487.5887145996094, 704.8538818359375), (485.32086181640625, 718.4692993164062), (481.8780212402344, 738.0449829101562), (479.4989929199219, 758.7575073242188), (475.3136901855469, 778.509521484375), (470.34674072265625, 798.3762817382812), (465.69305419921875, 818.8309936523438), (460.7818603515625, 839.65673828125), (458.7078552246094, 858.9144287109375), (457.51422119140625, 868.974365234375), (455.2334289550781, 888.3804931640625), (452.87103271484375, 905.7923583984375), (451.41546630859375, 922.98193359375), (450.2698974609375, 935.8972778320312), (448.7024841308594, 951.302734375), (448.37725830078125, 960.0695190429688), (447.378662109375, 967.033935546875), (447.378662109375, 971.2412109375), (447.378662109375, 967.2442626953125), (450.87152099609375, 954.7608642578125), (454.8053283691406, 932.0867919921875), (459.50897216796875, 911.1259155273438), (463.8141784667969, 887.2927856445312), (471.5345153808594, 860.9661254882812), (474.84051513671875, 850.335693359375), (481.01806640625, 825.505859375), (488.5655517578125, 803.82275390625), (495.21405029296875, 779.6853637695312), (500.0805358886719, 761.1925048828125), (503.993896484375, 743.990234375), (507.71466064453125, 727.752197265625), (511.2156982421875, 709.0404052734375), (513.287109375, 690.960205078125), (514.9940185546875, 676.5068359375), (516.4622192382812, 662.5848999023438), (516.282958984375, 648.493408203125), (516.282958984375, 635.6245727539062), (515.2843627929688, 615.7780151367188), (512.8880615234375, 600.733642578125), (509.27703857421875, 580.4214477539062), (506.96099853515625, 564.2147827148438), (504.7989196777344, 549.071044921875), (505.2982177734375, 534.565673828125), (504.2995910644531, 526.505615234375), (503.3009948730469, 518.984619140625), (502.3023681640625, 512.2769165039062), (502.3023681640625, 502.6073303222656), (501.3037414550781, 492.7122802734375), (501.3037414550781, 483.10845947265625), (500.3051452636719, 463.3252258300781), (500.3051452636719, 442.9181823730469), (500.3051452636719, 424.7042541503906), (501.3037414550781, 417.2712097167969), (502.2982177734375, 411.6866455078125), (504.79888916015625, 408.1811218261719), (505.78155517578125, 407.6814880371094), (505.2982177734375, 406.6822814941406), (506.29681396484375, 406.6822814941406), (506.29681396484375, 405.68304443359375), (507.2954406738281, 405.68304443359375), (507.2954406738281, 404.683837890625), (508.2940368652344, 404.683837890625), (509.29266357421875, 404.683837890625)], 0.033000)
        post_action(2.109070)
        perform_click_event("Tap", 39.944523, 1250.023438, 0.128000, "Activity")
        post_action(1.525764)
        perform_click_event("Tap", 652.094299, 1128.118652, 0.168000, "Activity")
        post_action(2.122087)
        perform_click_event("Tap", 531.262146, 1137.111572, 0.124000, "Activity")
        post_action(0.062501)
        record_popup_window()
        post_action(0.937513)
        perform_click_event("Tap", 446.380035, 1128.118652, 0.082000, "None")
        post_action(0.015622)
        close_popup_window()
        post_action(4.022878)
        perform_click_event("Tap", 54.923717, 1255.019531, 0.113000, "Activity")
        post_action(1.324553)
        perform_click_event("Tap", 610.152588, 1208.056152, 0.139000, "Activity")
        post_action(1.376378)
        perform_click_event("Tap", 651.095703, 1122.123291, 0.095000, "Activity")
        post_action(1.068992)
        perform_click_event("Tap", 644.105408, 1014.207642, 0.099000, "Activity")
        post_action(0.789644)
        perform_click_event("Tap", 621.137329, 929.273987, 0.082000, "Activity")
        post_action(0.000000)




    except Exception as e:

        print(e)

        traceback_str = ''.join(traceback.format_tb(e.__traceback__))

        print(traceback_str)

    os.system("adb shell am force-stop " + package_name)
    