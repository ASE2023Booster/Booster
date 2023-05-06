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

        perform_click_event("Tap", 153.786407, 399.687744, 0.041000, "Activity")
        post_action(6.647718)
        perform_swipe_event([(151.7891845703125, 618.5167846679688), (194.17637634277344, 619.5159912109375), (221.4611358642578, 619.5159912109375), (251.15118408203125, 619.5159912109375), (272.6579284667969, 621.5144653320312), (285.6854553222656, 622.513671875), (290.59637451171875, 623.5128784179688), (290.5964050292969, 623.5128784179688), (291.5950012207031, 623.5128784179688), (292.5936279296875, 623.5128784179688)], 0.033000)
        post_action(3.175768)
        perform_swipe_event([(345.5201110839844, 456.64324951171875), (381.59918212890625, 457.87884521484375), (403.439697265625, 457.6424560546875), (427.93695068359375, 458.6416931152344), (446.8511657714844, 458.6416931152344), (464.1175537109375, 458.6416931152344), (475.3975524902344, 458.6416931152344), (483.73883056640625, 458.6416931152344), (488.0080261230469, 457.6424560546875), (490.3273620605469, 457.6424560546875), (494.3134765625, 457.6424560546875), (498.12744140625, 457.6424560546875), (501.5773620605469, 457.6424560546875), (503.93109130859375, 457.6424560546875), (506.1519470214844, 457.6424560546875), (506.29681396484375, 457.6424560546875)], 0.033000)
        post_action(0.802032)
        perform_swipe_event([(303.578369140625, 367.7127380371094), (349.86688232421875, 365.5005798339844), (371.98333740234375, 364.7150573730469), (398.294921875, 364.51959228515625), (429.99078369140625, 367.09552001953125), (453.9141845703125, 369.124755859375), (481.7173767089844, 371.74468994140625), (502.26751708984375, 372.7088317871094), (508.2940673828125, 374.2076416015625), (524.222412109375, 375.70648193359375), (539.964111328125, 376.7056884765625), (553.467529296875, 379.35089111328125), (563.8292236328125, 380.5734558105469), (575.0341186523438, 381.7017822265625), (581.0397338867188, 383.31610107421875), (588.6393432617188, 385.81280517578125), (597.452880859375, 390.5500183105469), (602.8751831054688, 393.11785888671875), (606.6619873046875, 397.19427490234375), (608.48046875, 399.01385498046875), (611.073974609375, 406.45050048828125), (612.1497802734375, 413.5132141113281), (613.1484375, 423.1694030761719), (613.1484375, 428.7439270019531), (613.1484375, 433.96697998046875), (612.1497802734375, 438.09906005859375), (611.1511840820312, 440.6422119140625), (611.1511840820312, 441.65496826171875)], 0.033000)
        post_action(1.028625)
        perform_swipe_event([(208.7101287841797, 385.69866943359375), (210.53196716308594, 418.91650390625), (214.26792907714844, 440.2008972167969), (216.34300231933594, 453.86273193359375), (218.5723876953125, 463.1419982910156), (222.16966247558594, 469.589599609375), (224.3267059326172, 469.6330871582031), (227.5570068359375, 470.59002685546875), (237.24822998046875, 469.51763916015625), (248.22564697265625, 468.18792724609375), (268.19342041015625, 464.9072570800781), (277.23883056640625, 462.7459411621094), (290.6150207519531, 459.23748779296875), (294.5908508300781, 457.6424560546875)], 0.033000)
        post_action(0.983441)
        perform_swipe_event([(128.8210906982422, 366.7135009765625), (131.81692504882812, 392.6932067871094), (135.9644012451172, 426.586181640625), (137.0025634765625, 455.34405517578125), (141.57461547851562, 488.102294921875), (145.86300659179688, 509.8968200683594), (153.19232177734375, 522.9332275390625), (156.0289764404297, 526.249755859375), (162.85023498535156, 531.6229248046875), (178.3296661376953, 535.2261352539062), (197.22607421875, 537.0804443359375), (223.2092742919922, 537.5800170898438), (246.2684326171875, 537.5800170898438), (274.693115234375, 537.5800170898438), (297.79925537109375, 537.5800170898438), (317.5589599609375, 537.5800170898438), (336.913330078125, 537.5800170898438), (353.0205993652344, 537.5800170898438), (361.99725341796875, 537.5800170898438), (370.2520751953125, 540.3441772460938), (371.48406982421875, 544.2333984375), (371.48406982421875, 553.008056640625), (369.58111572265625, 564.0872802734375), (369.4868469238281, 577.0319213867188), (368.48822021484375, 586.8199462890625), (367.3539733886719, 596.0775146484375), (367.4895935058594, 601.8564453125), (367.4895935058594, 603.5285034179688)], 0.033000)
        post_action(5.714587)
        perform_swipe_event([(124.82662963867188, 763.403564453125), (98.8626937866211, 761.4051513671875), (77.89181518554688, 762.4043579101562), (63.62144470214844, 767.1167602539062), (53.100852966308594, 777.2182006835938), (44.4027099609375, 788.553466796875), (37.703460693359375, 803.1051025390625), (36.94868469238281, 818.0782470703125), (36.94868469238281, 837.2931518554688), (40.564170837402344, 857.8118896484375), (43.318790435791016, 872.970703125), (56.786346435546875, 895.05810546875), (69.45890808105469, 908.5863647460938), (81.88627624511719, 917.2833251953125), (104.47429656982422, 924.4154052734375), (127.945068359375, 928.6604614257812), (163.47581481933594, 928.2747802734375), (197.49896240234375, 928.2747802734375), (244.06814575195312, 929.2739868164062), (282.5067443847656, 929.2739868164062), (321.6465148925781, 928.214111328125), (368.2852478027344, 928.2747802734375), (403.46038818359375, 929.1421508789062), (437.6039123535156, 929.2739868164062), (462.02410888671875, 929.9703369140625), (489.25628662109375, 931.183837890625), (521.775390625, 931.2724609375), (545.1863403320312, 931.2724609375), (569.7988891601562, 930.0966186523438), (589.1560668945312, 928.777587890625), (604.9713745117188, 928.2747802734375), (618.5064086914062, 926.0034790039062), (637.0145874023438, 919.8317260742188), (650.1466674804688, 912.2625122070312), (659.2208862304688, 905.0200805664062), (666.3632202148438, 897.0105590820312), (679.85009765625, 879.9887084960938), (695.6602783203125, 837.6227416992188), (699.0291137695312, 813.8641357421875), (700.0277709960938, 786.3838500976562), (700.0277709960938, 763.9308471679688), (700.0277709960938, 742.562744140625), (698.030517578125, 727.3502807617188), (698.030517578125, 713.1245727539062), (696.0333251953125, 704.8914794921875), (696.0333251953125, 699.3755493164062), (696.0333251953125, 696.95556640625), (695.03466796875, 694.5835571289062), (695.03466796875, 692.1187744140625), (695.03466796875, 690.9788818359375)], 0.033000)
        post_action(1.010812)
        perform_swipe_event([(141.8030548095703, 840.343505859375), (193.19854736328125, 835.3199462890625), (233.08213806152344, 833.1787719726562), (293.51708984375, 828.8587036132812), (351.25067138671875, 825.2984008789062), (411.74176025390625, 822.8857421875), (458.68017578125, 823.3567504882812), (478.7577819824219, 823.3567504882812), (514.3795166015625, 823.3567504882812), (530.2635498046875, 823.3567504882812), (555.6405639648438, 823.515380859375), (573.360107421875, 822.0497436523438), (582.1632690429688, 821.3583374023438), (586.0631103515625, 819.482666015625), (588.6578979492188, 817.8856201171875), (593.1292114257812, 813.4114990234375), (599.5542602539062, 806.9826049804688), (604.0391845703125, 798.619873046875), (607.8756103515625, 785.0674438476562), (610.152587890625, 761.7952880859375), (611.1511840820312, 744.7344360351562), (612.1497802734375, 727.9209594726562), (611.9339599609375, 713.1461181640625), (612.1497802734375, 702.9508056640625), (612.1497802734375, 697.380126953125), (612.1497802734375, 694.1246337890625), (612.1497802734375, 693.458251953125)], 0.033000)
        post_action(2.949281)
        perform_swipe_event([(149.79196166992188, 693.458251953125), (185.16249084472656, 696.6976318359375), (216.69903564453125, 698.9539794921875), (258.8226623535156, 700.5183715820312), (290.7953796386719, 700.4527587890625), (328.43939208984375, 699.4535522460938), (352.9487609863281, 697.415283203125), (379.09942626953125, 696.4558715820312), (402.96466064453125, 695.4566650390625), (423.6026611328125, 694.4574584960938), (444.88214111328125, 689.4613037109375), (449.3758544921875, 688.9617919921875), (460.8304138183594, 685.151123046875), (466.1218566894531, 681.954345703125), (469.1891174316406, 675.94970703125), (471.4605712890625, 668.0166015625), (471.3453674316406, 654.4886474609375), (471.3453674316406, 648.6941528320312), (469.4281921386719, 635.1451416015625), (467.28179931640625, 610.7613525390625), (464.3551025390625, 586.541748046875), (463.85577392578125, 576.549560546875), (462.35784912109375, 559.1642456054688), (462.35784912109375, 552.575927734375), (463.04669189453125, 546.1936645507812), (465.2560729980469, 540.8707275390625), (471.796142578125, 531.6494140625), (480.00439453125, 525.5860595703125), (492.28533935546875, 520.2705078125), (504.685791015625, 515.6425170898438), (521.760986328125, 514.5979614257812), (530.9805297851562, 512.6699829101562), (541.616455078125, 511.304443359375), (549.1346435546875, 508.7746887207031), (564.15771484375, 505.0289306640625), (574.1000366210938, 501.6337585449219), (576.7247314453125, 501.6081237792969), (580.6935424804688, 500.1092529296875), (583.1517944335938, 500.60888671875), (582.19140625, 499.60968017578125), (583.1900024414062, 499.60968017578125)], 0.033000)
        post_action(1.035225)
        perform_swipe_event([(211.70596313476562, 772.3965454101562), (242.39169311523438, 776.6316528320312), (270.8890075683594, 778.7677001953125), (312.7832336425781, 780.3903198242188), (362.68194580078125, 781.3895263671875), (400.7481994628906, 778.8021850585938), (436.90142822265625, 772.7405395507812), (455.5997619628906, 764.8742065429688), (469.34814453125, 757.907958984375), (477.3926696777344, 749.3588256835938), (481.62091064453125, 736.5550537109375), (485.0323486328125, 711.0906372070312), (487.2967224121094, 688.7269287109375), (492.12884521484375, 664.0132446289062), (498.6427307128906, 643.4913940429688), (504.2314453125, 629.6672973632812), (511.7891845703125, 618.5167236328125), (520.2850952148438, 610.5153198242188), (527.65576171875, 607.3959350585938), (544.7206420898438, 599.977294921875), (558.2247314453125, 597.533203125), (582.2083740234375, 593.7344360351562), (612.6177368164062, 591.1657104492188), (627.5300903320312, 588.5553588867188), (651.9275512695312, 581.0128784179688), (661.5263061523438, 576.3272094726562), (678.722900390625, 563.2752075195312), (688.543701171875, 545.0740966796875), (695.4993286132812, 515.8050537109375), (696.3916015625, 505.0177917480469), (696.0333251953125, 479.6016845703125), (693.1600952148438, 453.38262939453125), (687.0457763671875, 420.1717224121094), (681.84619140625, 398.06854248046875), (676.632080078125, 376.779052734375), (673.47314453125, 369.1341857910156), (665.2208862304688, 352.0986328125), (657.9894409179688, 342.6034240722656), (649.685791015625, 333.8566589355469), (638.9151611328125, 328.9035339355469), (625.0869140625, 324.73345947265625), (604.6602783203125, 318.2513427734375), (583.1513061523438, 312.3443298339844), (552.8754272460938, 305.92181396484375), (522.6812744140625, 299.50054931640625), (493.147216796875, 296.9089660644531), (460.5135803222656, 293.3210754394531), (435.25921630859375, 290.7728271484375), (400.87579345703125, 289.77362060546875), (366.5042419433594, 289.77362060546875), (326.3877258300781, 288.7743835449219), (282.0974426269531, 291.0379638671875), (249.18345642089844, 290.4311828613281), (225.4853973388672, 290.7728271484375), (193.2569580078125, 291.7720642089844), (156.78224182128906, 295.7689208984375), (129.56134033203125, 302.01641845703125), (103.72146606445312, 311.6103515625), (84.88211059570312, 320.7494201660156), (67.96235656738281, 329.2144470214844), (56.27104187011719, 339.3856506347656), (47.64341354370117, 349.01776123046875), (36.911678314208984, 551.2913818359375), (38.22575759887695, 572.0146484375), (40.943138122558594, 593.0367431640625), (42.94036102294922, 613.0211181640625), (42.73973083496094, 631.292236328125), (42.94036102294922, 664.0411376953125), (46.20926284790039, 682.9235229492188), (46.934814453125, 688.832763671875), (46.934814453125, 694.7353515625), (48.93204116821289, 696.9554443359375)], 0.033000)
        post_action(0.000000)

    except Exception as e:
        print(e)
        traceback_str = ''.join(traceback.format_tb(e.__traceback__))
        print(traceback_str)
    clean_up()
    