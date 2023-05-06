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

        perform_click_event("Tap", 167.766998, 375.706482, 0.055000, "Activity")
        post_action(1.609301)
        perform_swipe_event([(90.87378692626953, 291.7720642089844), (91.85733032226562, 333.4678955078125), (91.87239837646484, 392.3559265136719), (93.67961883544922, 450.8908996582031), (95.86296081542969, 504.5162353515625), (96.86546325683594, 556.0656127929688), (95.06786346435547, 598.5343017578125), (93.60794830322266, 640.9540405273438), (92.87101745605469, 666.584228515625), (92.87101745605469, 684.3527221679688), (94.29785919189453, 696.1714477539062), (93.86962890625, 701.8400268554688), (91.78988647460938, 718.93408203125), (91.87239837646484, 730.375), (90.87378692626953, 735.925048828125), (90.87378692626953, 740.4215698242188)], 0.033000)
        post_action(0.380430)
        perform_swipe_event([(199.7226104736328, 316.7525329589844), (202.71844482421875, 348.7275695800781), (204.73341369628906, 360.8246765136719), (208.7101287841797, 398.18890380859375), (211.52117919921875, 436.5133361816406), (213.97943115234375, 477.3294677734375), (217.96189880371094, 520.2398071289062), (220.37875366210938, 544.4229736328125), (221.6920928955078, 586.6929931640625), (220.2454071044922, 610.599609375), (217.0825653076172, 645.7346801757812), (213.5103759765625, 684.0103149414062), (208.9139862060547, 716.0115966796875), (205.307861328125, 739.7536010742188), (201.2372283935547, 760.3390502929688), (198.09251403808594, 775.9232788085938), (193.94158935546875, 798.7431030273438), (190.89064025878906, 807.9015502929688), (180.74896240234375, 826.3544311523438), (173.56329345703125, 838.0046997070312), (165.15638732910156, 850.359375), (156.78225708007812, 860.3278198242188), (147.58999633789062, 869.5256958007812), (133.59751892089844, 878.6436767578125), (121.05270385742188, 885.419921875), (111.70384216308594, 891.444580078125), (103.7994155883789, 895.0050659179688), (101.85853576660156, 894.3013305664062)], 0.033000)
        post_action(0.429252)
        perform_swipe_event([(309.5700378417969, 319.75018310546875), (307.57281494140625, 335.7377014160156), (307.57281494140625, 366.2138671875), (307.442626953125, 406.63775634765625), (305.3340759277344, 435.8036193847656), (302.7520446777344, 464.7388916015625), (300.4651184082031, 485.5612487792969), (298.08599853515625, 504.60577392578125), (294.6508483886719, 516.3562622070312), (294.5908508300781, 516.596435546875)], 0.033000)
        post_action(0.403167)
        perform_swipe_event([(312.5658874511719, 676.4714965820312), (335.53399658203125, 668.4777221679688), (366.287353515625, 657.9374389648438), (383.64508056640625, 649.3909912109375), (398.44659423828125, 639.5003662109375), (407.6836242675781, 633.0680541992188), (415.24932861328125, 625.6851196289062), (420.67132568359375, 613.1264038085938), (424.2657470703125, 596.8388671875), (425.4091491699219, 563.303955078125), (423.7915344238281, 528.6690063476562), (421.3059387207031, 489.87445068359375), (422.84356689453125, 459.60931396484375), (426.8544006347656, 431.9791259765625), (431.9728088378906, 405.8191833496094), (437.46734619140625, 386.47332763671875), (446.270751953125, 359.96502685546875), (455.5182800292969, 343.71728515625), (461.3592529296875, 329.7424011230469), (469.7281188964844, 322.36767578125), (474.4234619140625, 317.66943359375), (483.85430908203125, 309.8631896972656), (494.64569091796875, 304.0294189453125), (505.15179443359375, 300.3020324707031), (512.217529296875, 299.76580810546875), (518.53076171875, 299.76580810546875), (522.1331176757812, 302.1930847167969), (523.2732543945312, 302.7634582519531)], 0.033000)
        post_action(0.313452)
        perform_swipe_event([(527.2677001953125, 417.6737060546875), (526.2691040039062, 433.66119384765625), (526.2691040039062, 447.6502685546875), (525.2704467773438, 492.25872802734375), (526.2691040039062, 526.868896484375), (527.2677001953125, 551.569091796875), (527.2677001953125, 577.9393920898438), (527.2677001953125, 589.4613037109375), (526.2691040039062, 613.2688598632812), (524.4019775390625, 635.20068359375), (523.1526489257812, 647.7015380859375), (520.27734375, 676.4715576171875), (516.4096069335938, 696.9482421875), (512.1080932617188, 709.9873657226562), (507.29541015625, 720.936767578125), (500.4801025390625, 731.9901123046875), (489.5191955566406, 742.8604125976562), (474.9521179199219, 753.3369750976562), (466.92523193359375, 758.0798950195312), (451.8901062011719, 763.8267211914062), (441.3869934082031, 767.9000854492188), (425.671875, 771.8312377929688), (409.1227722167969, 775.7679443359375), (395.9501037597656, 777.8922119140625), (384.2958068847656, 780.18310546875), (375.4151611328125, 784.0963745117188), (372.482666015625, 784.38720703125)], 0.033000)
        post_action(0.509811)
        perform_swipe_event([(329.54229736328125, 921.2802734375), (371.75634765625, 913.7974853515625), (419.88653564453125, 909.248779296875), (483.3287048339844, 903.7938842773438), (534.5318603515625, 896.9766235351562), (588.77490234375, 883.5117797851562), (621.6972045898438, 871.0513916015625), (636.643798828125, 860.4318237304688), (666.020751953125, 832.4038696289062), (688.0443725585938, 805.870361328125), (696.1138916015625, 766.9168090820312), (698.4000854492188, 743.7179565429688), (700.0277709960938, 695.9562377929688), (700.0277709960938, 638.3046264648438), (700.0277709960938, 576.9434814453125), (697.170654296875, 533.5423583984375), (694.9778442382812, 486.65283203125), (692.9259643554688, 471.7937927246094), (688.04443359375, 440.65576171875), (686.2551879882812, 412.82318115234375), (684.0499267578125, 387.13262939453125), (681.0540771484375, 366.1297302246094), (681.0540771484375, 350.1080322265625), (681.0540771484375, 333.7392883300781), (679.056884765625, 324.7581481933594), (677.0596313476562, 317.0757141113281), (677.0596313476562, 313.7548828125), (677.0596313476562, 311.9274597167969), (675.9818725585938, 310.6780090332031)], 0.033000)
        post_action(0.000000)

    except Exception as e:
        print(e)
        traceback_str = ''.join(traceback.format_tb(e.__traceback__))
        print(traceback_str)
    clean_up()
    