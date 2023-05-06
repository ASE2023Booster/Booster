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

        perform_click_event("Tap", 379.472961, 322.747864, 0.111000, "Activity")
        post_action(2.464179)
        perform_swipe_event([(85.88072204589844, 704.4496459960938), (95.07646179199219, 692.619384765625), (131.79188537597656, 654.5137329101562), (184.0336456298828, 606.631591796875), (240.5073699951172, 560.5363159179688), (295.75811767578125, 515.2839965820312), (322.1678161621094, 495.7666320800781), (359.500732421875, 466.63543701171875), (402.483154296875, 433.92535400390625), (433.178466796875, 411.7536315917969), (462.1609802246094, 391.89227294921875), (490.00909423828125, 371.1353454589844), (520.7766723632812, 348.2279357910156), (545.4395751953125, 328.3679504394531), (566.1099853515625, 313.0583190917969), (586.19873046875, 297.4235534667969), (600.7213134765625, 287.1459655761719), (615.3377685546875, 278.3210144042969), (626.022705078125, 270.6194763183594), (632.89697265625, 266.8661804199219), (640.6102905273438, 264.29351806640625), (649.0061645507812, 260.34283447265625), (652.2326049804688, 258.7516784667969), (656.279296875, 256.6087951660156), (659.861572265625, 253.02432250976562), (661.1519775390625, 250.73390197753906), (662.5797119140625, 248.30599975585938), (662.0804443359375, 247.89796447753906), (662.0804443359375, 247.806396484375), (663.0791015625, 245.80796813964844)], 0.033000)
        post_action(5.741285)
        perform_swipe_event([(305.5755920410156, 1086.1514892578125), (317.51312255859375, 1026.7998046875), (334.5856628417969, 958.818359375), (355.8552551269531, 885.6932983398438), (378.1029357910156, 821.1693725585938), (395.4779968261719, 766.1033935546875), (413.2047424316406, 716.9195556640625), (427.1220397949219, 684.6768798828125), (458.8440856933594, 601.8633422851562), (467.20501708984375, 585.5763549804688), (480.2976379394531, 567.6182861328125), (488.1786804199219, 555.1384887695312), (493.3148193359375, 547.0725708007812), (497.5937805175781, 542.2914428710938), (498.5552673339844, 539.3309326171875), (498.30792236328125, 538.07958984375), (498.30792236328125, 537.5800170898438)], 0.033000)
        post_action(1.901760)
        perform_swipe_event([(274.61859130859375, 1100.1405029296875), (279.61163330078125, 1057.174072265625), (300.31768798828125, 990.2147216796875), (365.0689392089844, 811.1298828125), (416.6630859375, 676.202880859375), (449.7756652832031, 604.7268676757812), (495.047119140625, 523.2157592773438), (520.5633544921875, 478.43450927734375), (531.0628662109375, 463.837158203125), (538.3295288085938, 455.5668640136719), (540.6400756835938, 454.6448059082031), (542.2468872070312, 452.146728515625), (543.2454833984375, 451.64715576171875), (544.244140625, 450.6479187011719), (544.244140625, 449.6487121582031)], 0.034000)
        post_action(0.490690)
        perform_swipe_event([(509.29266357421875, 518.5948486328125), (485.7829895019531, 564.0154418945312), (432.3473205566406, 665.2426147460938), (393.8161315917969, 742.5726318359375), (356.71246337890625, 838.9190063476562), (337.7738952636719, 891.4934692382812), (322.407958984375, 937.230712890625), (310.0246276855469, 983.7926635742188), (299.7491455078125, 1009.9807739257812), (295.6145935058594, 1029.045166015625), (292.025634765625, 1041.6082763671875), (288.3885498046875, 1053.5986328125), (285.4815673828125, 1061.536376953125), (284.604736328125, 1065.62646484375), (282.78460693359375, 1068.9874267578125), (282.60748291015625, 1070.1639404296875)], 0.033000)
        post_action(0.484303)
        perform_click_event("Tap", 527.267700, 426.666656, 0.099000, "Activity")
        post_action(3.085812)
        perform_swipe_event([(279.6116638183594, 999.2193603515625), (287.73284912109375, 972.13232421875), (298.4796447753906, 939.4047241210938), (315.0623779296875, 889.30517578125), (330.7999267578125, 842.6068725585938), (339.0724182128906, 815.1896362304688), (349.3536376953125, 786.4046020507812), (354.5472106933594, 772.0858764648438), (366.4495544433594, 733.5513916015625), (376.6696472167969, 706.74658203125), (385.71441650390625, 677.8451538085938), (396.32989501953125, 650.9785766601562), (408.4327392578125, 621.0148315429688), (424.40301513671875, 593.5513305664062), (435.9606018066406, 573.7327880859375), (447.9462890625, 547.4354858398438), (460.31060791015625, 530.0660400390625), (464.7796325683594, 521.1976318359375), (471.01959228515625, 512.2522583007812), (473.45867919921875, 507.37109375), (482.0118713378906, 494.4213562011719), (486.0052795410156, 488.37811279296875), (490.9405212402344, 481.1905212402344), (493.7109680175781, 475.8349304199219), (494.757080078125, 475.62841796875), (494.3134765625, 474.6291809082031)], 0.033000)
        post_action(0.400373)
        perform_swipe_event([(238.66851806640625, 1011.2099609375), (251.15118408203125, 968.7431640625), (263.7057189941406, 930.6857299804688), (276.4053039550781, 891.2343139648438), (300.75396728515625, 820.148193359375), (321.62841796875, 762.9473876953125), (339.9212951660156, 716.1992797851562), (349.09417724609375, 695.0093994140625), (360.1854248046875, 662.2884521484375), (376.76690673828125, 630.397216796875), (388.2171936035156, 603.01611328125), (400.984619140625, 576.1585693359375), (415.0689697265625, 552.0336303710938), (429.3566589355469, 529.6614379882812), (439.5809326171875, 513.5137939453125), (446.8793640136719, 503.10693359375), (451.6553039550781, 496.1885070800781), (455.8626403808594, 489.8736267089844), (459.2117614746094, 483.92279052734375), (460.3606262207031, 482.4848327636719), (460.7761535644531, 481.62371826171875), (461.3592224121094, 480.1424865722656), (462.35784912109375, 479.62530517578125), (462.35784912109375, 478.6260681152344)], 0.033000)
        post_action(1.732404)
        perform_click_event("Tap", 30.957005, 868.321594, 0.111000, "Activity")
        post_action(1.330142)
        perform_click_event("Tap", 312.565887, 1201.061646, 0.082000, "Activity")
        post_action(3.402025)
        perform_click_event("Tap", 647.101257, 424.668213, 0.099000, "Activity")
        post_action(2.817095)
        perform_click_event("Tap", 41.941750, 118.907104, 0.128000, "Activity")
        post_action(1.369467)
        perform_swipe_event([(483.3287353515625, 711.4441528320312), (481.33148193359375, 687.0759887695312), (484.3273620605469, 653.9890747070312), (493.06427001953125, 610.0289916992188), (503.7602233886719, 565.6236572265625), (519.4043579101562, 511.294189453125), (525.8184204101562, 482.7892150878906), (534.94482421875, 435.3038635253906), (544.244140625, 393.19281005859375), (554.4246215820312, 358.0390625), (564.0187377929688, 325.9381408691406), (576.130126953125, 295.908203125), (585.4989013671875, 273.0065002441406), (590.1050415039062, 264.868408203125), (602.611083984375, 245.63607788085938), (613.4722290039062, 232.55894470214844), (622.63525390625, 221.82669067382812), (628.8626708984375, 214.22854614257812), (633.4390258789062, 209.1988983154297), (635.7933959960938, 206.16249084472656), (636.1165161132812, 205.8391876220703), (636.1165161132812, 204.358154296875), (637.1151123046875, 204.8399658203125)], 0.033000)
        post_action(4.571903)
        perform_click_event("Tap", 517.281555, 426.666656, 0.068000, "Activity")
        post_action(1.183677)
        perform_swipe_event([(240.66574096679688, 964.2467041015625), (255.1685028076172, 917.1918334960938), (266.84539794921875, 875.0350952148438), (298.7189636230469, 776.9913330078125), (325.74310302734375, 706.5201416015625), (347.01806640625, 653.9890747070312), (365.88372802734375, 611.2907104492188), (387.9553527832031, 554.4163208007812), (408.1610412597656, 513.2343139648438), (433.9522399902344, 469.82574462890625), (451.8453369140625, 437.7044677734375), (459.15899658203125, 424.51556396484375), (473.5869445800781, 402.34307861328125), (482.5321960449219, 391.0912780761719), (485.0133972167969, 388.0098571777344), (486.8238525390625, 387.6971130371094), (486.3245544433594, 387.6971130371094)], 0.033000)
        post_action(0.384035)
        perform_swipe_event([(227.68377685546875, 915.284912109375), (236.32443237304688, 890.7882690429688), (254.2092742919922, 844.1144409179688), (273.7438659667969, 796.0802612304688), (310.5686340332031, 717.9390869140625), (336.6145935058594, 663.1046752929688), (345.60174560546875, 640.4713745117188), (361.27880859375, 601.1885986328125), (386.1524353027344, 548.4853515625), (396.23809814453125, 528.8888549804688), (421.193603515625, 481.0227355957031), (428.3916320800781, 466.16094970703125), (448.0457458496094, 431.2855224609375), (468.3642883300781, 401.10809326171875), (485.80987548828125, 373.7388000488281), (489.5769958496094, 366.1999816894531), (495.9548034667969, 357.0774230957031), (496.68853759765625, 354.9659118652344), (498.8072509765625, 353.7236633300781), (498.30792236328125, 353.7236633300781)], 0.033000)
        post_action(0.567694)
        perform_click_event("Tap", 56.920944, 780.390320, 0.084000, "Activity")
        post_action(0.838142)
        perform_click_event("Tap", 358.502075, 1189.071045, 0.070000, "Activity")
        post_action(3.579786)
        perform_click_event("Tap", 44.937588, 128.899292, 0.055000, "Activity")
        post_action(1.084125)
        perform_swipe_event([(208.7101287841797, 270.7884521484375), (235.0970458984375, 269.32159423828125), (279.39691162109375, 264.05755615234375), (352.4297790527344, 250.82020568847656), (412.65411376953125, 239.3675537109375), (456.3695068359375, 236.05067443847656), (476.16546630859375, 233.83897399902344), (516.5210571289062, 228.9695281982422), (550.5552978515625, 227.02879333496094), (574.1002197265625, 225.8338165283203), (594.1747436523438, 224.32473754882812), (602.7398681640625, 224.82435607910156), (608.6557006835938, 224.82435607910156), (614.1470947265625, 224.82435607910156), (617.9701538085938, 224.82435607910156), (621.541748046875, 226.2282257080078), (624.1331176757812, 225.82357788085938), (623.134521484375, 225.82357788085938)], 0.033000)
        post_action(6.730775)
        perform_click_event("Tap", 49.930653, 123.903198, 0.111000, "Activity")
        post_action(1.130334)
        perform_click_event("Tap", 39.944523, 103.918816, 0.080000, "Activity")
        post_action(0.000000)

    except Exception as e:
        print(e)
        traceback_str = ''.join(traceback.format_tb(e.__traceback__))
        print(traceback_str)
    clean_up()
    