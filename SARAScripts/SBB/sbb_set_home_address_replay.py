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
        press_soft_keyboard("next")
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
        press_soft_keyboard("next")
        post_action(2.468735)
        perform_click_event("Tap", 82.884888, 443.653381, 0.112000, "Activity")
        post_action(6.852742)
        perform_swipe_event([(201.71983337402344, 1074.1607666015625), (197.70144653320312, 1058.0775146484375), (191.8413848876953, 1018.5538330078125), (186.7406463623047, 977.2365112304688), (184.62098693847656, 944.7906494140625), (181.0986785888672, 916.0859985351562), (170.27413940429688, 852.504150390625), (161.53439331054688, 812.1591796875), (153.8380889892578, 779.29931640625), (138.36219787597656, 727.87158203125), (123.33418273925781, 669.4988403320312), (116.29739379882812, 647.6412963867188), (113.87628936767578, 638.6044311523438), (110.34674072265625, 627.509765625), (108.10639190673828, 619.2857666015625), (105.64828491210938, 611.9070434570312), (104.8543701171875, 609.024169921875), (104.8543701171875, 607.525390625), (104.8543701171875, 608.0828247070312), (105.65277099609375, 611.1215209960938), (111.71338653564453, 629.1141357421875), (119.08443450927734, 651.615478515625), (134.2987060546875, 690.9158935546875), (145.39376831054688, 720.4263916015625), (160.32875061035156, 760.9678955078125), (182.69448852539062, 822.5440063476562), (194.44224548339844, 856.2521362304688), (202.8617706298828, 888.2613525390625), (210.99349975585938, 911.3854370117188), (215.6250762939453, 928.0109252929688), (218.19696044921875, 941.7642211914062), (220.4554443359375, 951.54150390625), (221.6920928955078, 955.4094848632812), (222.90455627441406, 959.6785888671875), (225.4859619140625, 966.8428955078125), (226.76473999023438, 973.4785766601562), (227.68377685546875, 979.734619140625), (229.5968017578125, 983.1476440429688), (230.7633514404297, 986.3970947265625), (230.6796112060547, 990.2264404296875), (231.67822265625, 992.1371459960938), (231.67822265625, 993.2240600585938), (231.67822265625, 994.2232666015625)], 0.033000)
        post_action(0.299830)
        perform_swipe_event([(136.8099822998047, 670.4761962890625), (147.80934143066406, 704.98583984375), (154.65707397460938, 726.0484619140625), (162.77392578125, 749.9141845703125), (173.2004852294922, 786.3703002929688), (177.33494567871094, 800.8617553710938), (180.57603454589844, 810.6739501953125), (183.16175842285156, 823.4375), (186.32675170898438, 833.6907958984375), (188.81686401367188, 843.6572875976562), (190.12884521484375, 851.9061279296875), (192.23300170898438, 857.829833984375), (193.73092651367188, 862.8156127929688), (194.72955322265625, 864.9562377929688), (195.72816467285156, 868.2521362304688), (195.72816467285156, 869.3208618164062), (195.72816467285156, 870.8197021484375), (196.72677612304688, 871.3192749023438), (196.72677612304688, 872.3184814453125), (195.72816467285156, 870.2581787109375), (193.34579467773438, 864.78173828125), (186.9561767578125, 848.8763427734375), (183.44369506835938, 837.139892578125), (179.32545471191406, 825.7910766601562), (175.82943725585938, 812.8068237304688), (169.83355712890625, 796.1210327148438), (165.3566131591797, 782.8540649414062), (159.2902374267578, 769.4218139648438), (152.68106079101562, 753.19775390625), (144.4672393798828, 733.208251953125), (137.22705078125, 714.694580078125), (133.3328857421875, 700.4888916015625), (126.85636901855469, 686.5178833007812), (117.60303497314453, 668.3937377929688), (114.84049987792969, 661.4832153320312)], 0.033000)
        post_action(0.884438)
        perform_click_event("Tap", 29.958391, 104.918030, 0.137000, "Activity")
        post_action(2.041663)

    except Exception as e:
        print(e)
        traceback_str = ''.join(traceback.format_tb(e.__traceback__))
        print(traceback_str)
    clean_up()
    