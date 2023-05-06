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

        perform_click_event("Tap", 402.441071, 1217.049194, 0.086000, "Activity")
        post_action(1.235793)
        perform_click_event("Tap", 559.223328, 261.795471, 0.099000, "Activity")
        post_action(2.095760)
        perform_click_event("Tap", 464.355072, 723.434814, 0.124000, "Activity")
        post_action(4.605255)
        perform_swipe_event([(389.4591064453125, 1070.1639404296875), (389.4706115722656, 1032.0670166015625), (392.73193359375, 1005.4115600585938), (398.85919189453125, 970.3497924804688), (403.3376159667969, 941.7070922851562), (409.6468811035156, 912.4239501953125), (416.7247619628906, 882.3287353515625), (425.26702880859375, 852.7962646484375), (436.3938903808594, 818.8602294921875), (446.3248596191406, 789.127197265625), (456.3981628417969, 763.8231201171875), (464.1895446777344, 742.305908203125), (473.5056457519531, 721.110107421875), (484.1053161621094, 700.8970947265625), (489.5483093261719, 689.0052490234375), (494.4808044433594, 680.2172241210938), (496.6711730957031, 675.7501220703125), (497.3092956542969, 675.4722900390625), (498.8072509765625, 675.4722900390625)], 0.033000)
        post_action(0.642273)
        perform_swipe_event([(512.2885131835938, 1070.1639404296875), (520.0556640625, 997.71923828125), (539.2359008789062, 859.4805297851562), (541.248291015625, 801.0361938476562), (549.013916015625, 666.5758666992188), (562.9033813476562, 586.20263671875), (571.7059936523438, 549.5706176757812), (579.3231201171875, 521.9534912109375), (583.3824462890625, 507.4473876953125), (586.960205078125, 497.06085205078125), (588.18310546875, 494.61358642578125), (589.1817016601562, 492.13092041015625), (589.1817016601562, 490.75604248046875), (590.212890625, 490.61669921875), (590.1802978515625, 489.1178894042969), (589.2498168945312, 489.61749267578125), (589.1817016601562, 489.61749267578125)], 0.034000)
        post_action(0.429214)
        perform_swipe_event([(454.3689270019531, 1057.174072265625), (460.10467529296875, 1000.6531982421875), (472.9217834472656, 929.9590454101562), (493.2695007324219, 843.5135498046875), (504.7490539550781, 799.5418090820312), (511.54034423828125, 774.3919067382812), (522.5311279296875, 742.0211791992188), (533.0228271484375, 714.8573608398438), (549.1294555664062, 679.7027587890625), (560.4152221679688, 655.5039672851562), (567.7115478515625, 637.501953125), (577.652099609375, 621.6056518554688), (586.0974731445312, 605.9315185546875), (598.2223510742188, 585.0578002929688), (606.3878173828125, 570.0946044921875), (613.647705078125, 554.5667724609375), (616.8991088867188, 545.8176879882812), (618.1810302734375, 541.4977416992188), (619.639404296875, 540.5776977539062), (619.1400756835938, 540.5776977539062)], 0.033000)
        post_action(0.323541)
        perform_swipe_event([(394.4521484375, 1032.193603515625), (399.56396484375, 1000.2255249023438), (419.6156921386719, 927.6798095703125), (462.1148986816406, 807.9905395507812), (552.9284057617188, 585.7227172851562), (566.0374755859375, 557.9757080078125), (582.4199829101562, 524.1708374023438), (593.1884765625, 500.58428955078125), (604.6602783203125, 475.62841796875), (612.7617797851562, 458.62030029296875), (615.4277954101562, 451.79925537109375), (617.1428833007812, 450.6479187011719), (617.1428833007812, 449.5078125), (617.1428833007812, 449.6487121582031), (618.6407470703125, 449.6487121582031), (618.1414794921875, 449.6487121582031)], 0.033000)
        post_action(0.331771)
        perform_swipe_event([(385.4646301269531, 1067.166259765625), (386.046630859375, 1038.02978515625), (398.31341552734375, 967.084716796875), (409.43304443359375, 907.9495849609375), (437.773681640625, 815.218017578125), (462.1076354980469, 742.7545776367188), (493.3148498535156, 665.9796752929688), (522.0489501953125, 604.9793090820312), (546.4307861328125, 562.5380859375), (561.0025634765625, 536.0177612304688), (570.0567626953125, 521.8196411132812), (576.0243530273438, 513.3623046875), (577.98388671875, 510.6011047363281), (578.1969604492188, 509.10223388671875), (578.1969604492188, 508.6026611328125), (579.195556640625, 508.6026611328125), (578.1969604492188, 508.6026611328125), (576.4036865234375, 509.39776611328125), (568.8245849609375, 514.8290405273438), (545.7420654296875, 551.569091796875), (489.1970520019531, 664.4881591796875), (454.0410461425781, 753.345947265625), (432.8988037109375, 821.85791015625), (412.70782470703125, 892.7478637695312), (397.45867919921875, 948.2218017578125), (388.1408386230469, 994.839111328125), (381.7059020996094, 1026.7816162109375), (379.47296142578125, 1047.4805908203125), (377.4757385253906, 1051.8079833984375), (377.4757385253906, 1052.6776123046875), (377.4757385253906, 1051.1787109375), (377.4757385253906, 1050.1795654296875)], 0.033000)
        post_action(0.310686)
        perform_swipe_event([(562.2191772460938, 390.69476318359375), (555.2288818359375, 407.6814880371094), (504.47332763671875, 538.644287109375), (450.1621398925781, 749.1204223632812), (440.7453308105469, 800.8721313476562), (433.426025390625, 846.6004028320312), (430.7352600097656, 873.6490478515625), (431.4008483886719, 897.7217407226562), (429.93206787109375, 905.7047729492188), (430.4022216796875, 908.8033447265625), (429.40362548828125, 915.1483764648438), (428.015625, 919.061767578125), (428.4049987792969, 923.265380859375), (427.1111145019531, 925.5725708007812), (427.4064025878906, 926.2763671875), (428.4049987792969, 927.2755737304688)], 0.033000)
        post_action(0.717975)
        perform_click_event("Tap", 686.047180, 105.917252, 0.112000, "Activity")
        post_action(0.598145)
        record_popup_window()
        post_action(5.219452)
        perform_click_event("Tap", 559.223328, 484.621399, 0.082000, "None")
        post_action(0.099147)
        close_popup_window()
        post_action(1.922869)
        perform_click_event("Tap", 573.203918, 992.224792, 0.069000, "Dialog")
        post_action(1.624492)
        perform_click_event("Tap", 554.230225, 977.236511, 0.098000, "Dialog")
        post_action(1.753164)
        perform_click_event("Tap", 187.739258, 969.242798, 0.069000, "Dialog")
        post_action(1.061023)
        perform_click_event("Tap", 192.732315, 989.227173, 0.074000, "Dialog")
        post_action(1.320781)
        perform_click_event("Tap", 484.327332, 1177.080444, 0.043000, "Dialog")
        post_action(2.523170)
        perform_click_event("Tap", 271.622742, 1188.071777, 0.087000, "Dialog")
        post_action(1.265072)
        perform_click_event("Tap", 653.092957, 608.524597, 0.112000, "Dialog")
        post_action(1.202087)
        perform_click_event("Tap", 27.961166, 128.899292, 0.153000, "Activity")
        post_action(1.748153)
        perform_click_event("Tap", 496.310699, 887.306763, 0.099000, "Activity")
        post_action(0.674812)
        perform_swipe_event([(492.31622314453125, 925.277099609375), (497.61083984375, 904.0858154296875), (507.6204528808594, 874.671630859375), (518.15966796875, 847.6997680664062), (525.9959716796875, 824.1083374023438), (536.1032104492188, 796.29638671875), (544.3353271484375, 772.7282104492188), (552.7596435546875, 746.483154296875), (559.7225341796875, 722.4356079101562), (566.3958740234375, 694.114501953125), (577.5628051757812, 658.3668212890625), (585.4631958007812, 630.9764404296875), (597.3603515625, 599.9990844726562), (609.8317260742188, 562.8597412109375), (620.6380004882812, 540.5776977539062), (625.3965454101562, 525.9263916015625), (628.364990234375, 520.1182250976562), (629.9429931640625, 516.596435546875), (630.1248168945312, 516.596435546875), (631.1234741210938, 515.59716796875)], 0.033000)
        post_action(0.132255)
        perform_swipe_event([(385.4646301269531, 1086.1514892578125), (387.79168701171875, 1072.1806640625), (400.4295349121094, 1021.5972290039062), (422.0869445800781, 954.2349243164062), (438.21331787109375, 907.824951171875), (449.5908508300781, 871.4118041992188), (462.10546875, 834.6693115234375), (480.8251953125, 787.5029907226562), (503.495849609375, 728.376708984375), (530.0679321289062, 660.489990234375), (555.9910278320312, 601.5006713867188), (568.5177001953125, 564.9634399414062), (577.757568359375, 547.4523315429688), (582.1913452148438, 539.5785522460938), (586.7696533203125, 533.9981689453125), (591.1788940429688, 527.0881958007812), (595.47412109375, 521.2916259765625), (598.654541015625, 517.1100463867188), (599.1678466796875, 514.77880859375), (600.1664428710938, 514.5979614257812), (601.1650390625, 514.5979614257812)], 0.033000)
        post_action(0.235963)
        perform_swipe_event([(607.15673828125, 499.60968017578125), (586.8023071289062, 528.5582275390625), (557.506591796875, 599.5040283203125), (531.6593017578125, 661.9384155273438), (499.8058166503906, 747.416015625), (481.16778564453125, 811.1614379882812), (469.070556640625, 859.07958984375), (460.0216369628906, 909.3536987304688), (454.5472717285156, 952.6483764648438), (450.8738098144531, 987.7283325195312), (447.6934814453125, 1003.0095825195312), (444.2124938964844, 1012.7205200195312), (441.8942565917969, 1015.698486328125), (442.3855895996094, 1016.2061157226562)], 0.033000)
        post_action(0.315820)
        perform_swipe_event([(536.2551879882812, 447.6502685546875), (513.786376953125, 503.1069641113281), (479.3955383300781, 582.6727905273438), (450.8704833984375, 666.3396606445312), (439.0378723144531, 715.4583129882812), (432.4294738769531, 760.2456665039062), (428.8287353515625, 779.4059448242188), (425.4091796875, 790.8821411132812), (420.097900390625, 808.4837036132812), (416.91082763671875, 819.8898315429688), (412.7194519042969, 832.6178588867188), (410.2883605957031, 839.769287109375), (394.5133972167969, 881.18896484375), (390.5154113769531, 893.12890625), (386.9239807128906, 906.9072875976562), (382.46881103515625, 920.2810668945312), (379.47296142578125, 933.7085571289062), (376.2559509277344, 940.9293212890625), (372.482666015625, 947.2599487304688)], 0.034000)
        post_action(0.579226)
        perform_click_event("Tap", 54.923717, 117.907883, 0.095000, "Activity")
        post_action(1.117896)
        perform_click_event("Tap", 684.049927, 882.310669, 0.099000, "Activity")
        post_action(8.969534)
        perform_click_event("Tap", 491.317627, 1226.042114, 0.068000, "Dialog")
        post_action(3.268441)
        perform_click_event("Tap", 54.923717, 119.906326, 0.111000, "Activity")
        post_action(1.583222)
        perform_click_event("Tap", 84.882111, 1252.021851, 0.068000, "Activity")
        post_action(0.000000)

    except Exception as e:
        print(e)
        traceback_str = ''.join(traceback.format_tb(e.__traceback__))
        print(traceback_str)
    clean_up()
    