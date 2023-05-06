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



        perform_click_event("Tap", 434.396667, 591.537842, 0.055000, "Activity")
        post_action(0.821500)
        perform_click_event("Tap", 562.219177, 1171.085083, 0.085000, "Activity")
        post_action(1.369429)
        perform_click_event("Tap", 425.409149, 578.548035, 0.071000, "Activity")
        post_action(1.219330)
        perform_click_event("Tap", 564.216370, 1213.052246, 0.068000, "Activity")
        post_action(0.568385)
        perform_click_event("Tap", 243.661591, 603.528503, 0.099000, "Activity")
        post_action(1.451812)
        perform_click_event("Tap", 561.220520, 1184.074951, 0.111000, "Activity")
        post_action(0.452518)
        perform_swipe_event([(708.0166625976562, 867.3223876953125), (651.1719360351562, 876.8219604492188), (610.325927734375, 885.1324462890625), (552.4041748046875, 893.8742065429688), (476.41326904296875, 902.4374389648438), (411.79730224609375, 910.9513549804688), (371.2812805175781, 916.5986328125), (315.06243896484375, 923.7783203125), (282.47784423828125, 927.6907958984375), (249.3674774169922, 932.7970581054688), (224.56565856933594, 934.8262329101562), (205.3748321533203, 938.068115234375), (160.09429931640625, 946.7152709960938), (145.24986267089844, 949.9468383789062), (118.06332397460938, 957.6836547851562), (110.8460464477539, 959.2505493164062), (92.8790054321289, 962.2470703125), (82.49198913574219, 963.4021606445312), (63.05562210083008, 973.6498413085938), (52.84635925292969, 983.5418090820312), (46.91905975341797, 986.2357788085938), (38.59251022338867, 991.1282348632812), (37.14682388305664, 991.6260375976562), (36.94868469238281, 993.2462158203125), (33.988590240478516, 993.2240600585938), (34.95145797729492, 993.2240600585938)])
        post_action(0.531065)
        perform_click_event("Tap", 277.614441, 704.449646, 0.097000, "Activity")
        post_action(0.907759)
        perform_swipe_event([(175.7559051513672, 885.308349609375), (202.71844482421875, 885.308349609375), (213.20388793945312, 885.308349609375), (243.4148712158203, 885.308349609375), (316.87860107421875, 885.308349609375), (380.9224853515625, 885.308349609375), (436.9727478027344, 888.1636352539062), (507.2633972167969, 890.7315063476562), (565.2391357421875, 890.304443359375), (626.4163818359375, 888.0205078125), (646.6555786132812, 884.9437866210938), (660.083251953125, 883.3099365234375)])
        post_action(0.581877)
        perform_click_event("Tap", 273.619965, 965.245911, 0.097000, "Activity")
        post_action(0.831623)
        perform_swipe_event([(707.01806640625, 887.3067626953125), (670.0541381835938, 883.0391845703125), (618.0563354492188, 890.3192749023438), (531.9390258789062, 912.47900390625), (435.3952941894531, 946.2607421875), (394.6686096191406, 960.8890380859375), (328.6574401855469, 984.1883544921875), (311.95068359375, 989.0007934570312), (261.12530517578125, 1004.385986328125), (240.29693603515625, 1008.8856811523438), (190.23577880859375, 1021.7017822265625), (175.18643188476562, 1024.3626708984375), (153.84828186035156, 1029.18359375), (131.77603149414062, 1034.701904296875), (97.4245376586914, 1046.1588134765625), (79.70474243164062, 1055.281005859375), (67.50437927246094, 1060.1324462890625), (59.28935241699219, 1064.0447998046875), (56.92094421386719, 1065.1678466796875)])
        post_action(0.584367)
        perform_click_event("Tap", 460.360626, 1168.087402, 0.099000, "Activity")
        post_action(1.449783)
        perform_swipe_event([(188.7378692626953, 878.3138427734375), (214.99310302734375, 878.3138427734375), (298.7307434082031, 876.42236328125), (347.24298095703125, 874.6466674804688), (469.34814453125, 870.8197021484375), (541.4786987304688, 869.2753295898438), (586.185302734375, 867.12255859375), (622.3245849609375, 863.7267456054688), (652.9448852539062, 861.2496948242188), (680.0555419921875, 860.327880859375)])
        post_action(1.207334)
        perform_click_event("Tap", 588.183105, 1204.059326, 0.067000, "Activity")
        post_action(1.892932)
        perform_swipe_event([(700.0277709960938, 926.2763671875), (652.8839721679688, 924.2778930664062), (630.7937622070312, 925.3829345703125), (534.0068969726562, 941.9252319335938), (430.041259765625, 975.657470703125), (336.5491638183594, 1009.557861328125), (290.1176452636719, 1022.958251953125), (253.85939025878906, 1038.1065673828125), (206.21359252929688, 1059.172607421875), (170.60646057128906, 1075.7379150390625), (141.8865509033203, 1094.26611328125), (122.82940673828125, 1110.1326904296875)])
        post_action(0.496978)
        perform_click_event("Tap", 491.317627, 868.321594, 0.054000, "Activity")
        post_action(0.621171)
        perform_swipe_event([(201.71983337402344, 902.2951049804688), (238.6072235107422, 894.9131469726562), (305.30731201171875, 885.8092651367188), (382.07318115234375, 881.1780395507812), (467.97772216796875, 879.3130493164062), (539.1270751953125, 882.3057250976562), (559.4169921875, 884.3091430664062), (613.1484375, 884.3091430664062), (647.1012573242188, 880.312255859375)])
        post_action(0.498290)
        perform_click_event("Tap", 257.642181, 931.272461, 0.068000, "Activity")
        post_action(0.475576)
        perform_swipe_event([(707.01806640625, 877.3145751953125), (650.6470336914062, 882.600341796875), (576.8992919921875, 899.3722534179688), (455.3675231933594, 939.26611328125), (354.9339294433594, 982.2080078125), (274.4501037597656, 1012.8987426757812), (223.5820770263672, 1036.90771484375), (203.71502685546875, 1047.405029296875), (167.2498321533203, 1071.86865234375), (154.01611328125, 1085.9217529296875)])
        post_action(0.476681)
        perform_click_event("Tap", 441.386963, 1175.081909, 0.071000, "Activity")
        post_action(0.689770)
        perform_swipe_event([(195.72816467285156, 885.308349609375), (224.6879425048828, 881.3114624023438), (359.32781982421875, 868.337890625), (505.4425964355469, 866.7713012695312), (609.454345703125, 866.3120727539062), (655.0901489257812, 860.327880859375)])
        post_action(1.169471)
        perform_click_event("Tap", 574.202515, 890.304443, 0.081000, "Activity")
        post_action(0.378172)
        perform_swipe_event([(710.0138549804688, 860.327880859375), (643.4154052734375, 866.089599609375), (521.775390625, 902.794677734375), (391.44915771484375, 965.5086669921875), (327.38397216796875, 998.9124755859375), (260.4690246582031, 1027.9388427734375), (230.9317169189453, 1040.257568359375), (180.966064453125, 1064.63623046875), (154.31629943847656, 1080.684326171875), (106.85160827636719, 1113.13037109375)])
        post_action(0.649294)
        perform_click_event("Tap", 286.601959, 1027.197510, 0.069000, "Activity")
        post_action(0.463837)
        perform_swipe_event([(150.7905731201172, 873.3177490234375), (208.1875457763672, 866.3592529296875), (320.869873046875, 859.7813110351562), (448.8765563964844, 854.3325805664062), (533.8948974609375, 860.445068359375), (591.1095581054688, 860.327880859375), (650.9531860351562, 846.23681640625), (654.091552734375, 845.339599609375)])
        post_action(1.523791)
        perform_click_event("Tap", 572.205261, 1197.064819, 0.082000, "Activity")
        post_action(0.622894)
        perform_swipe_event([(686.0471801757812, 909.2896118164062), (662.8008422851562, 909.2896118164062), (604.0800170898438, 920.0842895507812), (546.0911254882812, 939.8742065429688), (412.67401123046875, 991.32666015625), (322.4017028808594, 1025.4122314453125), (253.13037109375, 1045.8023681640625), (204.87759399414062, 1062.44921875), (179.365966796875, 1071.8480224609375), (162.07371520996094, 1080.856201171875)])
        post_action(0.989937)
        perform_click_event("Tap", 444.382812, 1030.195190, 0.085000, "Activity")
        post_action(0.413922)
        perform_swipe_event([(182.74618530273438, 936.2685546875), (236.5953369140625, 932.6473999023438), (323.878173828125, 925.4396362304688), (415.4017333984375, 918.3638305664062), (526.5447998046875, 911.573974609375), (610.688720703125, 908.805419921875), (646.9966430664062, 901.663818359375), (651.095703125, 900.296630859375)])
        post_action(0.637453)
        perform_click_event("Tap", 592.177551, 714.441833, 0.055000, "Activity")
        post_action(0.758534)
        perform_swipe_event([(686.0471801757812, 909.2896118164062), (662.8008422851562, 909.2896118164062), (604.0800170898438, 920.0842895507812), (546.0911254882812, 939.8742065429688), (412.67401123046875, 991.32666015625), (322.4017028808594, 1025.4122314453125), (253.13037109375, 1045.8023681640625), (204.87759399414062, 1062.44921875), (179.365966796875, 1071.8480224609375), (162.07371520996094, 1080.856201171875)])
        post_action(0.545568)
        perform_click_event("Tap", 638.113770, 1167.088257, 0.087000, "Activity")
        post_action(0.614816)
        perform_swipe_event([(255.6449432373047, 919.2817993164062), (271.62274169921875, 918.2825927734375), (336.03326416015625, 916.7838134765625), (431.40032958984375, 909.8745727539062), (534.6473388671875, 904.5238037109375), (602.4198608398438, 898.0023803710938), (640.1109619140625, 889.3052368164062)])
        post_action(0.706000)
        perform_click_event("Tap", 68.904305, 776.393433, 0.068000, "Activity")
        post_action(1.481287)
        perform_click_event("Tap", 429.403625, 1175.081909, 0.111000, "Activity")
        post_action(0.000000)




    except Exception as e:

        print(e)

        traceback_str = ''.join(traceback.format_tb(e.__traceback__))

        print(traceback_str)

    os.system("adb shell am force-stop " + package_name)
    