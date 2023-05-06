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

        perform_click_event("Tap", 162.773926, 387.697113, 0.041000, "Activity")
        post_action(3.285408)
        perform_swipe_event([(140.804443359375, 929.2739868164062), (90.2945556640625, 908.9031982421875), (68.30268859863281, 886.504150390625), (46.63962173461914, 855.6533203125), (24.95510482788086, 820.3284301757812), (14.312141418457031, 782.2150268554688), (7.090999603271484, 688.7728881835938), (9.980838775634766, 623.0794677734375), (18.249876022338867, 536.8604125976562), (26.99704933166504, 486.7056884765625), (41.220638275146484, 426.37481689453125), (50.6650276184082, 402.2561950683594), (65.25751495361328, 373.8812561035156), (74.99363708496094, 356.5503234863281), (85.22183990478516, 336.6416320800781), (99.41207122802734, 312.7928771972656), (114.5218734741211, 300.3245849609375), (136.45465087890625, 284.79437255859375), (156.81503295898438, 274.3266296386719), (177.0315704345703, 267.85430908203125), (199.1213836669922, 265.8525085449219), (241.02032470703125, 265.7923583984375), (270.01397705078125, 267.4901123046875), (294.3790283203125, 268.7900085449219), (316.10205078125, 269.1831359863281), (345.7766418457031, 269.7892150878906), (360.99859619140625, 268.2904052734375), (367.4833679199219, 268.7900085449219), (371.6233215332031, 268.7900085449219), (372.482666015625, 268.7900085449219)], 0.034000)
        post_action(3.399864)
        perform_swipe_event([(323.5506286621094, 562.5604858398438), (326.8150634765625, 585.4254760742188), (330.53509521484375, 612.4633178710938), (332.03887939453125, 637.0023193359375), (333.0845947265625, 651.1328125), (339.2252197265625, 660.1806030273438), (353.00970458984375, 661.9827880859375), (376.542236328125, 658.6788940429688), (406.2473449707031, 653.0211791992188), (412.42718505859375, 651.4910278320312)], 0.033000)
        post_action(1.933116)
        perform_swipe_event([(405.4368896484375, 562.5604858398438), (428.6484680175781, 560.5377197265625), (463.3564758300781, 559.5628662109375), (478.0653076171875, 562.7062377929688), (482.582275390625, 565.8104858398438), (483.3287353515625, 572.8842163085938), (484.32733154296875, 584.2931518554688), (485.82525634765625, 605.02734375), (490.2484436035156, 629.7308959960938), (496.1177673339844, 665.5140991210938), (497.0027770996094, 687.7000732421875), (495.0800476074219, 710.535888671875), (490.3805236816406, 728.2462158203125), (481.6799621582031, 747.8050537109375), (472.315673828125, 759.2294921875), (461.8585205078125, 765.402099609375), (451.188232421875, 767.4004516601562), (440.5382080078125, 766.4012451171875), (428.6646728515625, 763.6553955078125), (423.41192626953125, 762.4043579101562)], 0.033000)
        post_action(1.529395)
        perform_click_event("Tap", 500.305145, 471.631531, 0.024000, "Activity")
        post_action(0.771794)
        perform_swipe_event([(499.3065185546875, 487.6190490722656), (488.2064208984375, 449.1471862792969), (484.71099853515625, 399.21929931640625), (485.42645263671875, 358.00933837890625), (487.1893310546875, 324.5506286621094), (494.1457824707031, 293.1907653808594), (499.2633361816406, 282.8222961425781), (515.7078857421875, 271.0350646972656), (534.4402465820312, 266.79156494140625), (574.1879272460938, 265.06695556640625), (606.8941650390625, 266.0093078613281), (623.842041015625, 267.5326843261719), (646.2819213867188, 275.8742370605469), (657.228515625, 285.4536437988281), (667.20458984375, 297.9313049316406), (681.6478271484375, 322.50445556640625), (688.0443725585938, 352.1685485839844), (689.0430297851562, 367.1820373535156), (689.0430297851562, 382.7010192871094)], 0.035000)
        post_action(0.549186)
        perform_swipe_event([(405.4368896484375, 470.63232421875), (371.26727294921875, 459.586669921875), (327.7922668457031, 454.35296630859375), (288.50811767578125, 448.0317687988281), (268.28045654296875, 447.31890869140625), (247.67559814453125, 453.4627380371094), (234.6493377685547, 467.1783447265625), (219.1571502685547, 504.35595703125), (212.76406860351562, 535.634765625), (205.41636657714844, 598.8138427734375), (206.1822967529297, 622.1378173828125), (212.2505340576172, 677.1976318359375), (216.29461669921875, 699.9983520507812), (222.1924591064453, 737.9288940429688), (228.46092224121094, 761.3326416015625), (247.59002685546875, 814.1655883789062), (256.91729736328125, 829.71728515625), (270.67266845703125, 841.7081298828125), (308.01226806640625, 852.7000122070312), (337.8965148925781, 857.224609375), (364.0272216796875, 860.327880859375), (391.13262939453125, 862.4013061523438), (418.4437255859375, 861.7517700195312), (446.88995361328125, 860.327880859375), (498.0908508300781, 848.6412963867188), (531.7263793945312, 835.8070678710938), (552.6920166015625, 825.6791381835938), (567.766845703125, 810.8112182617188), (579.924072265625, 784.0637817382812), (590.2714233398438, 728.7918701171875), (596.3619995117188, 679.804931640625), (599.6881103515625, 646.2012939453125), (602.161865234375, 602.551025390625), (603.1622924804688, 578.1482543945312), (604.160888671875, 539.8005981445312), (603.1622924804688, 500.3494873046875), (602.1636962890625, 464.7593994140625), (601.1650390625, 430.5906066894531), (600.1664428710938, 415.7837829589844), (600.1664428710938, 393.99969482421875), (599.1678466796875, 384.6168518066406), (599.1678466796875, 378.7041320800781)], 0.050000)
        post_action(1.954846)
        perform_swipe_event([(394.4521484375, 483.6221618652344), (380.72509765625, 481.33294677734375), (336.8585510253906, 479.62530517578125), (314.4622802734375, 479.62530517578125), (286.2770080566406, 479.62530517578125), (269.1209411621094, 482.4581604003906), (249.46603393554688, 494.8384094238281), (237.25442504882812, 511.0788269042969), (223.31866455078125, 544.0029907226562), (218.3946533203125, 568.8778076171875), (216.69903564453125, 589.4422607421875), (214.8205108642578, 607.5744018554688), (214.29931640625, 629.7324829101562), (213.7032012939453, 646.5187377929688), (213.7032012939453, 664.2127075195312), (216.35597229003906, 681.749755859375), (218.94383239746094, 696.4475708007812), (221.00802612304688, 706.0233154296875), (225.5604705810547, 716.9348754882812), (230.29830932617188, 726.4627075195312), (235.75390625, 736.5059814453125), (241.04776000976562, 743.6102905273438), (245.6588134765625, 746.91650390625), (256.5785217285156, 747.4160766601562), (272.10302734375, 745.0635375976562), (287.7839660644531, 741.8974609375), (303.656005859375, 740.4215698242188), (313.57427978515625, 740.7578735351562), (319.19744873046875, 743.7005004882812), (323.9813232421875, 753.1304321289062), (329.54229736328125, 771.68603515625), (330.5409240722656, 784.687255859375), (332.03887939453125, 801.87353515625), (334.5209045410156, 812.3074340820312), (338.78948974609375, 819.8795776367188), (349.7268371582031, 830.1597900390625), (362.33721923828125, 835.3155517578125), (382.3481750488281, 838.3450317382812), (418.1859436035156, 838.3450317382812), (438.7167663574219, 837.3458251953125), (456.6120910644531, 835.740478515625), (481.22802734375, 834.0774536132812), (496.2385559082031, 833.3489379882812), (510.2197570800781, 831.5034790039062), (525.869140625, 827.6107177734375), (538.9614868164062, 823.1202392578125), (550.6038818359375, 814.0875244140625), (558.9655151367188, 803.75927734375), (568.9939575195312, 772.18798828125), (573.939453125, 747.7332153320312), (577.9417114257812, 719.0169067382812), (579.195556640625, 689.3544311523438), (580.1942138671875, 654.7952270507812), (580.9024658203125, 618.3316040039062), (580.020263671875, 571.243896484375), (580.1942138671875, 525.693603515625), (581.1928100585938, 493.10247802734375), (582.19140625, 454.18963623046875), (582.19140625, 430.7242736816406), (583.1530151367188, 416.85955810546875), (584.1886596679688, 403.15362548828125), (584.92919921875, 392.72674560546875), (586.4008178710938, 383.8390197753906), (586.1858520507812, 377.205322265625), (586.1858520507812, 373.92022705078125), (586.1858520507812, 371.3631896972656)], 0.033500)
        post_action(0.448181)
        perform_swipe_event([(394.4521484375, 393.6924133300781), (365.9135437011719, 386.2669372558594), (321.3428649902344, 375.0647888183594), (289.2398376464844, 369.88665771484375), (246.036865234375, 366.7135009765625), (224.41554260253906, 367.8540344238281), (201.60423278808594, 372.74737548828125), (174.98583984375, 387.9620361328125), (163.535888671875, 399.37237548828125), (153.9457244873047, 415.3564453125), (140.81622314453125, 441.1229553222656), (132.1473846435547, 471.1068420410156), (115.1231689453125, 532.6465454101562), (103.26891326904297, 590.2401733398438), (100.85991668701172, 626.5093994140625), (100.85991668701172, 648.1589965820312), (104.87169647216797, 680.5550537109375), (107.35090637207031, 705.948486328125), (108.64771270751953, 728.4169921875), (111.09918212890625, 755.1983642578125), (112.34397888183594, 771.3973388671875), (115.50357055664062, 794.53125), (124.52739715576172, 817.7618408203125), (135.1113739013672, 830.1102905273438), (146.10488891601562, 835.347412109375), (159.09634399414062, 838.73095703125), (176.5653076171875, 842.0293579101562), (195.49169921875, 846.779296875), (206.34129333496094, 852.5548706054688), (215.4327850341797, 860.06005859375), (221.33453369140625, 873.815185546875), (227.27191162109375, 887.4817504882812), (236.82778930664062, 907.6826782226562), (246.762451171875, 923.6046752929688), (263.5927429199219, 937.4346923828125), (283.8443298339844, 944.3417358398438), (310.4951171875, 945.2615356445312), (346.9185791015625, 946.2607421875), (381.6419982910156, 946.2607421875), (417.1286926269531, 946.2607421875), (454.2232666015625, 947.2599487304688), (485.13507080078125, 947.6031494140625), (519.4043579101562, 949.2583618164062), (545.663330078125, 950.2576293945312), (573.109130859375, 950.2576293945312), (613.2982177734375, 943.9175415039062), (635.2342529296875, 936.4388427734375), (653.2345581054688, 925.6041259765625), (666.53955078125, 909.2381591796875), (681.41162109375, 893.057861328125), (690.9780883789062, 863.6155395507812), (696.6260986328125, 827.0115966796875), (700.834228515625, 764.8662109375), (701.0263671875, 717.109619140625), (698.7471313476562, 671.6510620117188), (695.889404296875, 608.7865600585938), (695.03466796875, 563.1082763671875), (693.0374755859375, 519.9384155273438), (693.0374755859375, 475.3130187988281), (691.5253295898438, 454.587890625), (689.0430297851562, 433.7264099121094), (689.0430297851562, 422.6697998046875)], 0.033000)
        post_action(0.000000)

    except Exception as e:
        print(e)
        traceback_str = ''.join(traceback.format_tb(e.__traceback__))
        print(traceback_str)
    clean_up()
    