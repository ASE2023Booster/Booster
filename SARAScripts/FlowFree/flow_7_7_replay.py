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

        perform_click_event("Tap", 172.760056, 371.709595, 0.042000, "Activity")
        post_action(4.088103)
        perform_swipe_event([(157.78086853027344, 478.6260681152344), (156.282958984375, 454.644775390625), (168.96090698242188, 430.272705078125), (179.8930206298828, 413.4483947753906), (196.22744750976562, 397.68927001953125), (217.94862365722656, 386.4928894042969), (250.98475646972656, 375.46856689453125), (289.7337646484375, 370.3621826171875), (326.8283996582031, 369.7111511230469), (368.48822021484375, 372.2091979980469), (403.66766357421875, 372.7088317871094), (424.58367919921875, 372.7088317871094), (458.8339538574219, 373.86236572265625), (494.5011901855469, 376.4336242675781), (520.4637451171875, 379.7372741699219), (545.3793334960938, 383.6342468261719), (567.94970703125, 387.55706787109375), (577.4658813476562, 389.7624816894531), (589.9517822265625, 390.69476318359375), (597.669921875, 392.193603515625), (599.6671142578125, 391.6940002441406)], 0.033000)
        post_action(0.800687)
        perform_swipe_event([(643.1068115234375, 295.7689208984375), (594.330322265625, 298.13232421875), (555.2288818359375, 302.76348876953125), (496.52947998046875, 309.1741943359375), (450.6520690917969, 313.3662414550781), (421.7230224609375, 314.45391845703125), (378.7008972167969, 314.818603515625), (335.53399658203125, 311.75640869140625), (299.1561279296875, 310.04351806640625), (276.4624938964844, 308.69097900390625), (240.3811798095703, 308.7587890625), (216.69903564453125, 308.7587890625), (194.49603271484375, 308.7587890625), (157.7922821044922, 310.8189697265625), (123.8280258178711, 313.2552490234375), (112.09819030761719, 317.4757995605469), (90.39189147949219, 324.9270935058594), (83.39534759521484, 329.02227783203125), (68.68928527832031, 338.3079528808594), (64.1185531616211, 343.22235107421875), (53.92981719970703, 362.70721435546875), (43.258602142333984, 383.0633850097656), (36.99339294433594, 415.0489501953125), (36.94868469238281, 446.6619567871094), (44.43827819824219, 485.62060546875), (59.30073928833008, 529.3104248046875), (68.7491455078125, 566.1473388671875), (70.90153503417969, 585.0429077148438), (70.90152740478516, 611.9515380859375), (70.90152740478516, 640.7893676757812), (70.90152740478516, 653.4894409179688), (71.79031372070312, 686.9237060546875), (74.9513931274414, 717.2166137695312), (78.99009704589844, 738.288818359375), (87.87794494628906, 769.8984985351562), (99.61317443847656, 812.3713989257812), (111.2258529663086, 844.7571411132812), (123.19340515136719, 882.6581420898438), (132.48045349121094, 904.7881469726562), (139.30653381347656, 922.2794799804688), (149.82078552246094, 933.2996826171875), (158.23187255859375, 937.568603515625), (174.8778839111328, 939.2661743164062), (197.830322265625, 939.2661743164062), (229.18927001953125, 938.2669677734375), (255.9600830078125, 933.4238891601562), (280.8611145019531, 928.2291259765625), (307.57281494140625, 924.7774658203125), (317.5589599609375, 922.2794799804688), (342.1576232910156, 919.11865234375), (354.776123046875, 916.6895141601562), (372.82110595703125, 912.28515625), (381.54541015625, 909.5535888671875), (400.87725830078125, 905.9735107421875), (419.91680908203125, 901.2958984375), (427.83624267578125, 900.6175537109375), (445.50408935546875, 898.137939453125), (452.4342041015625, 898.2982177734375), (468.7462158203125, 898.2982177734375), (474.9993896484375, 898.2982177734375), (490.37017822265625, 899.2974243164062), (497.0820007324219, 899.2974243164062), (508.527587890625, 901.1427001953125), (518.4414672851562, 901.2958374023438), (528.765625, 901.2958374023438), (534.9703369140625, 901.2958374023438), (539.8987426757812, 901.2958374023438), (541.74755859375, 901.2958374023438)], 0.033000)
        post_action(1.030696)
        perform_swipe_event([(677.0596313476562, 299.76580810546875), (645.4597778320312, 297.1308898925781), (619.2688598632812, 296.7681579589844), (590.695556640625, 296.7681579589844), (559.2233276367188, 295.7689208984375), (530.72705078125, 293.7218017578125), (506.065185546875, 291.5862121582031), (473.3495178222656, 290.0047302246094), (441.6065368652344, 287.72320556640625), (405.0519714355469, 286.28399658203125), (364.4080505371094, 287.7751770019531), (328.4931640625, 288.7743835449219), (288.099853515625, 290.27325439453125), (244.67982482910156, 292.6591491699219), (201.77345275878906, 295.1192321777344), (165.90211486816406, 297.472412109375), (134.56399536132812, 300.6578369140625), (101.85853576660156, 304.76190185546875), (76.36407470703125, 308.26513671875), (52.8200569152832, 314.4565124511719), (24.9653263092041, 321.2490234375), (12.907266616821289, 329.2801513671875), (6.094803810119629, 338.52899169921875), (5.991678237915039, 344.6159973144531), (5.991678237915039, 356.4476013183594), (7.438579559326172, 373.29962158203125), (14.94974422454834, 399.5993347167969), (32.138671875, 436.02593994140625), (50.58664321899414, 470.848876953125), (67.7657470703125, 517.1475830078125), (75.4453125, 550.1458129882812), (83.38418579101562, 584.5433349609375), (90.07185363769531, 629.3793334960938), (89.87517547607422, 665.3611450195312), (89.0813217163086, 701.5813598632812), (85.7367935180664, 736.5775756835938), (83.38432312011719, 770.3963012695312), (85.7597427368164, 799.8001708984375), (88.92182159423828, 823.8549194335938), (94.468505859375, 850.3328247070312), (99.55689239501953, 869.1016845703125), (106.71764373779297, 887.6155395507812), (120.28961944580078, 910.6094360351562), (128.44015502929688, 921.0535888671875), (137.80859375, 929.2740478515625), (147.7721405029297, 934.2655639648438), (153.54254150390625, 935.42041015625), (164.17442321777344, 938.7470703125), (176.60299682617188, 940.2654418945312), (194.08941650390625, 941.6013793945312), (209.87318420410156, 940.2654418945312), (236.9055633544922, 938.2456665039062), (268.37310791015625, 934.6370849609375), (308.5714416503906, 927.2755126953125), (343.5849914550781, 921.93603515625), (366.2957763671875, 919.0015869140625), (395.97357177734375, 915.4078369140625), (421.4630432128906, 913.1159057617188), (446.87933349609375, 910.7883911132812), (472.46807861328125, 909.2772216796875), (491.7492980957031, 908.1314086914062), (516.7124633789062, 905.5494995117188), (539.5133056640625, 905.292724609375), (558.78759765625, 907.736328125), (573.4004516601562, 909.1558837890625), (583.3848266601562, 909.2896118164062), (590.6796264648438, 910.7884521484375), (593.0472412109375, 911.2880249023438), (594.1747436523438, 911.2880249023438), (595.1734008789062, 911.2880249023438)], 0.033000)
        post_action(0.916191)
        perform_swipe_event([(677.0596313476562, 399.687744140625), (679.056884765625, 437.4349060058594), (681.0540771484375, 454.50848388671875), (682.052734375, 468.0082092285156), (682.052734375, 477.22845458984375), (681.0540771484375, 485.1209716796875), (676.3712768554688, 490.9950866699219), (668.595703125, 496.9289245605469), (657.1611328125, 502.5704345703125), (646.3323364257812, 506.11260986328125), (628.6861572265625, 507.90826416015625), (609.4922485351562, 507.6034240722656), (541.3086547851562, 503.6065673828125), (449.2101745605469, 502.6073303222656), (409.5783996582031, 505.2082214355469), (372.1156005859375, 509.2730712890625), (329.355224609375, 515.44287109375), (297.70770263671875, 519.5112915039062), (270.8990783691406, 526.8300170898438), (251.8461456298828, 534.1849975585938), (245.46975708007812, 539.1303100585938), (236.9858856201172, 549.0459594726562), (234.23031616210938, 555.6768188476562), (230.05307006835938, 569.4373168945312), (231.58074951171875, 582.0572509765625), (231.67822265625, 593.470947265625), (230.1802978515625, 606.0265502929688), (220.67584228515625, 615.5323486328125), (216.070068359375, 618.98876953125), (205.31884765625, 623.4713134765625), (190.40444946289062, 627.0333251953125), (174.89950561523438, 633.4339599609375), (168.28823852539062, 639.97802734375), (155.9413604736328, 669.0350952148438), (149.00970458984375, 700.8469848632812), (144.79888916015625, 730.928955078125), (144.79888916015625, 759.5257568359375), (147.01869201660156, 773.9554443359375), (158.73643493652344, 796.083251953125), (173.41978454589844, 815.0238647460938), (189.2371826171875, 827.8532104492188), (207.1276092529297, 832.2847900390625), (226.5661163330078, 833.3489379882812), (259.99267578125, 830.682861328125), (292.6280517578125, 826.4830932617188), (323.2658386230469, 823.96337890625), (348.0198059082031, 823.3567504882812), (369.2392578125, 823.3567504882812), (404.43829345703125, 824.35595703125), (429.4261779785156, 825.4686889648438), (452.4462890625, 824.74072265625), (460.07568359375, 824.35595703125), (462.35784912109375, 823.3567504882812)], 0.033000)
        post_action(0.298424)
        perform_swipe_event([(244.6602020263672, 721.4364013671875), (274.61859130859375, 719.4379272460938), (311.782958984375, 711.7532348632812), (328.6771545410156, 703.9641723632812), (341.8985290527344, 694.5586547851562), (352.5565185546875, 685.4183349609375), (360.14453125, 669.2205810546875), (365.2564392089844, 656.1961669921875), (368.48236083984375, 639.5354614257812), (369.7722473144531, 630.0787963867188), (370.4854431152344, 620.015625), (371.48406982421875, 611.1808471679688), (372.7088623046875, 607.07275390625)], 0.033000)
        post_action(0.379402)
        perform_swipe_event([(458.3634033203125, 609.5238037109375), (482.3301086425781, 609.5238037109375), (518.5421752929688, 605.491943359375), (547.2999877929688, 601.2359619140625), (581.8689575195312, 596.088134765625), (610.0632934570312, 592.5445556640625), (635.1865844726562, 590.0869140625), (654.029541015625, 588.5402221679688), (667.2715454101562, 589.5724487304688), (678.5574951171875, 592.0374755859375), (687.5333251953125, 608.373291015625), (694.3792114257812, 648.2040405273438), (695.03466796875, 698.863037109375), (695.03466796875, 741.24609375), (695.03466796875, 781.88916015625), (695.03466796875, 808.493896484375), (695.03466796875, 823.1582641601562), (695.03466796875, 842.9811401367188), (695.03466796875, 865.69189453125), (693.0374755859375, 881.9027099609375), (693.0374755859375, 896.7994384765625), (693.0374755859375, 899.2974243164062)], 0.033000)
        post_action(0.304246)
        perform_swipe_event([(476.33843994140625, 705.4488525390625), (515.0833740234375, 705.4488525390625), (536.5244140625, 705.4488525390625), (558.7356567382812, 705.4488525390625), (570.99853515625, 709.32080078125), (579.4406127929688, 724.7548217773438), (580.1942138671875, 747.308837890625), (578.2084350585938, 768.2963256835938), (575.7003784179688, 792.880615234375), (574.2025146484375, 806.3699951171875)], 0.033000)
        post_action(0.000000)

    except Exception as e:
        print(e)
        traceback_str = ''.join(traceback.format_tb(e.__traceback__))
        print(traceback_str)
    clean_up()
    