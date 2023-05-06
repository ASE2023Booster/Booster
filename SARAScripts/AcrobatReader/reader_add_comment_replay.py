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

        perform_click_event("Tap", 574.202515, 382.701019, 0.080000, "Activity")
        post_action(2.761031)
        perform_swipe_event([(519.27880859375, 958.2513427734375), (516.282958984375, 936.2685546875), (516.0676879882812, 859.6998901367188), (520.7767333984375, 809.8672485351562), (530.740234375, 746.5526733398438), (544.0120239257812, 683.0933227539062), (560.1576538085938, 614.551025390625), (576.6317138671875, 537.8944091796875), (593.24267578125, 476.9609375), (611.1311645507812, 409.7534484863281), (620.328369140625, 381.5372009277344), (624.3930053710938, 366.19354248046875), (627.1290283203125, 355.40350341796875), (628.144287109375, 350.7093200683594), (628.1276245117188, 350.7259826660156)], 0.067000)
        post_action(0.470829)
        perform_swipe_event([(516.282958984375, 907.2911987304688), (516.282958984375, 891.252197265625), (518.770263671875, 859.947998046875), (526.4231567382812, 798.216552734375), (534.014404296875, 744.8572998046875), (546.698974609375, 693.2639770507812), (559.349609375, 650.9855346679688), (570.92919921875, 616.592529296875), (583.3157958984375, 579.9171752929688), (589.1817016601562, 565.314697265625), (590.6621704101562, 564.0767822265625), (589.1817016601562, 564.5589599609375)], 0.066000)
        post_action(0.755927)
        perform_swipe_event([(3.9944522380828857, 875.316162109375), (39.944522857666016, 879.8126831054688), (59.59731674194336, 879.3130493164062), (85.2369384765625, 881.3114624023438), (115.05673217773438, 882.3106689453125), (139.4974822998047, 881.3114624023438), (162.3535919189453, 879.4550170898438), (186.00941467285156, 878.3138427734375), (209.20944213867188, 877.3145751953125), (232.17208862304688, 876.3153686523438), (244.2633514404297, 875.1382446289062), (262.8575439453125, 874.0393676757812), (291.0665588378906, 873.3177490234375), (303.3184814453125, 872.4234008789062), (339.5143737792969, 869.8214721679688), (371.0977478027344, 868.3215942382812), (393.5507507324219, 867.316650390625), (430.5784606933594, 865.196044921875), (456.43865966796875, 862.3190307617188), (500.13153076171875, 858.7927856445312), (539.9844360351562, 855.9931030273438), (565.3644409179688, 853.936767578125), (582.2723999023438, 852.31787109375), (599.634033203125, 851.0267944335938), (614.6463623046875, 848.8367919921875), (630.005126953125, 845.0464477539062), (643.5978393554688, 841.8450927734375), (654.4684448242188, 837.6568603515625), (660.4913330078125, 835.2113037109375), (664.0777587890625, 835.347412109375), (665.0626220703125, 834.34814453125), (665.0762939453125, 834.34814453125)], 0.033000)
        post_action(0.587417)
        perform_click_event("Tap", 493.314850, 339.734589, 0.124000, "Activity")
        post_action(1.476494)
        perform_click_event("Tap", 53.925106, 1217.049194, 0.098000, "Activity")
        post_action(3.078340)
        perform_click_event("Tap", 662.080444, 812.365356, 0.138000, "Activity")
        post_action(2.510995)
        set_text("com.adobe.reader:id/popupnotewidget_edittext", "[72,40][648,507]", "comment")
        post_action(0.947081)
        perform_click_event("Tap", 579.195557, 465.636230, 0.128000, "Activity")
        post_action(2.114534)
        perform_swipe_event([(469.34814453125, 1064.1685791015625), (468.41455078125, 1023.549072265625), (475.55377197265625, 965.7457885742188), (480.53240966796875, 910.6917724609375), (485.27044677734375, 815.0859985351562), (488.8946838378906, 763.7979736328125), (497.9251403808594, 688.9671020507812), (512.4041137695312, 614.2338256835938), (531.0055541992188, 537.18896484375), (547.87841796875, 484.9325256347656), (558.4420776367188, 455.99072265625), (562.2191772460938, 443.8135070800781), (565.7142333984375, 434.660400390625), (567.42529296875, 427.4526672363281), (569.20947265625, 424.668212890625)], 0.050000)
        post_action(0.377446)
        perform_swipe_event([(384.4660339355469, 1023.2006225585938), (386.8113098144531, 983.3064575195312), (399.359375, 932.6152954101562), (413.1919860839844, 881.2481079101562), (424.48651123046875, 841.07666015625), (435.1558837890625, 807.848388671875), (441.1009521484375, 784.24658203125), (445.8487854003906, 769.462890625), (448.37725830078125, 762.4043579101562), (447.378662109375, 762.4043579101562)], 0.050000)
        post_action(0.566458)
        perform_click_event("Tap", 42.940361, 1228.040649, 0.082000, "Activity")
        post_action(0.898289)
        perform_click_event("Tap", 327.545074, 877.314575, 0.055000, "Activity")
        post_action(1.660279)
        set_text("com.adobe.reader:id/popupnotewidget_edittext", "[72,40][648,507]", "comment e")
        post_action(1.355795)
        perform_click_event("Tap", 586.185852, 474.629181, 0.168000, "Activity")
        post_action(1.564799)
        perform_swipe_event([(570.2080688476562, 622.513671875), (555.3812255859375, 661.6263427734375), (528.0826416015625, 733.9093627929688), (504.79888916015625, 825.854736328125), (487.5074462890625, 917.9910888671875), (481.33148193359375, 985.330810546875), (483.3287353515625, 1035.9046630859375), (482.3301086425781, 1061.259521484375), (482.3301086425781, 1064.5382080078125), (482.3301086425781, 1065.1678466796875)], 0.054000)
        post_action(0.432097)
        perform_swipe_event([(591.178955078125, 529.5862426757812), (574.4376831054688, 573.786376953125), (555.4610595703125, 631.8089599609375), (531.2077026367188, 730.75634765625), (516.1103515625, 831.7332153320312), (508.10296630859375, 893.215576171875), (502.3591613769531, 974.4424438476562), (499.3065185546875, 1029.1099853515625), (496.9017028808594, 1059.8046875), (496.3106994628906, 1069.1201171875), (496.3106994628906, 1071.0438232421875), (496.3106994628906, 1071.1632080078125), (495.31207275390625, 1067.9173583984375), (495.31207275390625, 1041.45703125), (496.11114501953125, 1007.4118041992188), (498.7569274902344, 981.884033203125), (500.3051452636719, 968.0184326171875), (501.3037414550781, 961.5369262695312), (501.3037414550781, 958.497802734375), (501.3037414550781, 958.2513427734375), (501.3037414550781, 957.2521362304688)], 0.066000)
        post_action(0.360422)
        perform_click_event("Tap", 674.063843, 798.376282, 0.111000, "Activity")
        post_action(1.156398)
        perform_click_event("Tap", 663.079102, 1120.124878, 0.069000, "Activity")
        post_action(0.828950)
        perform_swipe_event([(514.2857055664062, 1081.1553955078125), (503.70587158203125, 1043.51513671875), (507.66302490234375, 976.5037841796875), (525.7591552734375, 863.3892211914062), (547.5883178710938, 712.3154296875), (554.9419555664062, 648.79150390625), (568.015380859375, 557.7385864257812), (577.4617309570312, 492.9774169921875), (583.9839477539062, 464.9442138671875), (585.187255859375, 460.64013671875), (586.1858520507812, 460.64013671875)], 0.050000)
        post_action(0.350307)
        perform_swipe_event([(455.3675537109375, 983.2318725585938), (460.85992431640625, 941.7642211914062), (478.7265319824219, 862.9558715820312), (500.12841796875, 785.3597412109375), (504.96307373046875, 756.0805053710938), (505.2982177734375, 754.41064453125)], 0.046000)
        post_action(0.480696)
        perform_click_event("Tap", 334.535370, 924.277893, 0.155000, "Activity")
        post_action(1.071363)
        perform_click_event("Tap", 670.069336, 1118.126465, 0.080000, "Activity")
        post_action(0.883325)
        perform_swipe_event([(613.1484375, 492.6151428222656), (568.6339111328125, 654.2407836914062), (546.818359375, 804.5377807617188), (542.8131103515625, 898.9266357421875), (540.9994506835938, 984.9684448242188), (538.2764892578125, 1048.8914794921875), (536.2551879882812, 1076.8370361328125), (534.2579956054688, 1090.652099609375), (534.2579956054688, 1092.9576416015625), (534.75732421875, 1094.1451416015625), (534.2579956054688, 1094.1451416015625)], 0.066000)
        post_action(0.243663)
        perform_swipe_event([(567.2122192382812, 424.668212890625), (563.0455322265625, 441.3450927734375), (540.0656127929688, 544.6998901367188), (506.6881408691406, 706.2997436523438), (488.2178955078125, 884.6480102539062), (478.3356628417969, 1023.98046875), (478.3356628417969, 1070.2354736328125), (479.83355712890625, 1079.656494140625), (479.3342590332031, 1079.1568603515625)], 0.060000)
        post_action(0.311735)
        perform_swipe_event([(555.2288818359375, 397.6893005371094), (542.96044921875, 446.435791015625), (520.38525390625, 537.5538330078125), (494.81756591796875, 670.9518432617188), (474.5575256347656, 794.7752075195312), (461.71002197265625, 886.0925903320312), (451.466552734375, 989.3382568359375), (446.634765625, 1057.623046875), (445.185546875, 1078.1385498046875), (443.3841857910156, 1099.59130859375), (441.386962890625, 1110.447265625), (440.38836669921875, 1125.3829345703125), (437.39251708984375, 1147.1038818359375)], 0.050000)
        post_action(0.415799)
        perform_key_event(4)
        post_action(2.345169)
        perform_swipe_event([(630.1248168945312, 638.5011596679688), (628.748779296875, 641.427001953125), (614.1629028320312, 678.9193725585938), (590.46728515625, 759.1387939453125), (578.77197265625, 811.0631713867188), (569.2424926757812, 870.105224609375), (566.213623046875, 893.95849609375), (566.213623046875, 906.5557250976562), (566.213623046875, 909.2896118164062), (566.213623046875, 909.9109497070312), (566.213623046875, 912.2872924804688)], 0.034000)
        post_action(0.309437)
        perform_key_event(4)
        post_action(0.000000)

    except Exception as e:
        print(e)
        traceback_str = ''.join(traceback.format_tb(e.__traceback__))
        print(traceback_str)
    clean_up()
    