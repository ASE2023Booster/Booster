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



        perform_click_event("Tap", 134.812759, 324.746277, 0.069000, "Activity")
        post_action(1.552701)
        perform_click_event("Tap", 413.425812, 224.824356, 0.099000, "Activity")
        post_action(8.013680)
        set_text("ch.sbb.mobile.android.b2c:id/text", "[0,192][720,244]", "metalli")
        post_action(3.866995)
        perform_click_event("Tap", 667.761444, 1228.644806, 0.085000, "Activity")
        post_action(2.440554)
        perform_click_event("Tap", 164.771149, 452.646362, 0.139000, "Activity")
        post_action(2.790095)
        perform_click_event("Tap", 73.897369, 326.744720, 0.112000, "Activity")
        post_action(1.681235)
        set_text("ch.sbb.mobile.android.b2c:id/text", "[0,296][720,348]", "victor")
        post_action(1.275031)
        perform_click_event("Tap", 667.761444, 1228.644806, 0.085000, "Activity")
        post_action(5.096061)
        perform_click_event("Tap", 119.833565, 415.675262, 0.068000, "Activity")
        post_action(8.151690)
        perform_click_event("Tap", 287.600555, 418.672913, 0.139000, "Activity")
        post_action(3.341654)
        perform_click_event("Tap", 404.438293, 476.627625, 0.095000, "Dialog")
        post_action(0.849089)
        perform_click_event("Tap", 558.224670, 494.613586, 0.083000, "Dialog")
        post_action(1.485348)
        perform_click_event("Tap", 486.324554, 588.540222, 0.111000, "Dialog")
        post_action(1.570399)
        perform_click_event("Tap", 311.567261, 628.508972, 0.082000, "Dialog")
        post_action(0.913926)
        perform_click_event("Tap", 389.459106, 735.425476, 0.068000, "Dialog")
        post_action(6.291965)
        perform_swipe_event([(332.53814697265625, 1087.150634765625), (342.930908203125, 1048.958984375), (356.5048828125, 1012.708740234375), (366.0884704589844, 982.2000732421875), (376.8912353515625, 956.2576293945312), (389.7097473144531, 923.82568359375), (406.4921875, 877.5667724609375), (425.8740234375, 831.6749877929688), (438.1721496582031, 800.9444580078125), (455.4479675292969, 759.2457885742188), (477.83013916015625, 711.4566650390625), (497.4531555175781, 675.9698486328125), (511.90521240234375, 650.663330078125), (523.9564819335938, 632.1377563476562), (528.5864868164062, 625.5112915039062), (529.76416015625, 621.5144653320312), (534.6973266601562, 614.0802612304688), (536.5679321289062, 611.209228515625), (537.2538452148438, 608.620849609375), (538.4474487304688, 607.3302612304688), (539.267578125, 607.525390625)], 0.034000)
        post_action(3.663993)
        perform_swipe_event([(365.49237060546875, 1103.13818359375), (367.4458923339844, 1092.0616455078125), (377.14007568359375, 1057.182373046875), (386.2913818359375, 1022.3466796875), (398.1535339355469, 992.5875854492188), (422.50238037109375, 938.044189453125), (435.3975830078125, 904.8870849609375), (443.33953857421875, 878.4924926757812), (454.86822509765625, 846.3387451171875), (463.64398193359375, 815.0336303710938), (478.0662536621094, 775.780029296875), (506.6085510253906, 702.9411010742188), (518.9539794921875, 675.28564453125), (526.2224731445312, 657.92822265625), (533.6653442382812, 647.0879516601562), (539.1613159179688, 637.6815185546875), (542.9485473632812, 634.8014526367188), (543.2454833984375, 633.183837890625), (546.99169921875, 628.75732421875), (549.2159423828125, 623.5553588867188), (550.2357788085938, 621.231201171875), (551.2344360351562, 619.016357421875), (553.3491821289062, 618.5167846679688), (553.2316284179688, 618.5167846679688)], 0.033000)
        post_action(0.392785)
        perform_click_event("Tap", 449.375885, 848.337219, 0.097000, "Activity")
        post_action(3.068350)
        perform_click_event("Tap", 626.130371, 354.722870, 0.141000, "Activity")
        post_action(2.495448)
        perform_click_event("Tap", 645.104065, 344.730682, 0.112000, "Activity")
        post_action(0.864947)
        perform_swipe_event([(377.4757385253906, 960.2498168945312), (395.1412048339844, 916.1522827148438), (403.8891906738281, 888.47216796875), (411.7193603515625, 868.5934448242188), (428.96746826171875, 825.7816772460938), (440.6204528808594, 795.68115234375), (449.6710510253906, 769.68798828125), (462.4166259765625, 731.2521362304688), (469.60479736328125, 706.8053588867188), (483.61297607421875, 665.6260986328125), (493.3148498535156, 645.4956665039062), (495.69415283203125, 639.7349853515625), (501.76177978515625, 627.5923461914062), (502.65521240234375, 624.4521484375), (504.2995910644531, 620.065185546875), (505.2188415527344, 618.59619140625), (505.2982177734375, 618.5167846679688), (505.2982177734375, 617.4863891601562), (506.4599304199219, 617.517578125), (506.29681396484375, 616.5183715820312)], 0.033000)
        post_action(1.615867)
        perform_swipe_event([(392.4549255371094, 953.2552490234375), (515.9081420898438, 576.8316040039062), (522.8011474609375, 559.190673828125), (540.9682006835938, 529.1475830078125), (546.0267333984375, 521.8073120117188), (548.0072631835938, 519.8255004882812), (549.2371826171875, 518.5948486328125)], 0.033000)
        post_action(0.799531)
        perform_swipe_event([(333.5367736816406, 880.312255859375), (342.14654541015625, 855.5441284179688), (358.75701904296875, 822.2539672851562), (365.99371337890625, 800.4411010742188), (380.92041015625, 760.1494750976562), (401.6850280761719, 707.5200805664062), (418.42657470703125, 663.3201904296875), (434.9012145996094, 631.3548583984375), (447.729736328125, 602.825927734375), (460.5953369140625, 578.4896240234375), (475.4336853027344, 551.7456665039062), (493.4510803222656, 522.8869018554688), (501.3829040527344, 511.1616516113281), (516.3731079101562, 485.5303955078125), (519.7781372070312, 480.62451171875), (521.2760009765625, 478.3185119628906), (523.4581298828125, 474.4441833496094), (524.2718505859375, 472.3533935546875), (525.769775390625, 471.13189697265625), (525.2704467773438, 471.63153076171875), (526.2691040039062, 471.63153076171875)], 0.033000)
        post_action(0.401088)
        perform_swipe_event([(557.22607421875, 447.6502685546875), (537.3888549804688, 482.3526611328125), (524.045166015625, 512.0863647460938), (510.3954162597656, 552.7725830078125), (497.904052734375, 587.4564819335938), (488.2325134277344, 612.7448120117188), (483.35211181640625, 623.7913208007812), (479.8335876464844, 637.501953125), (479.3342590332031, 639.6300659179688), (479.3342590332031, 638.5011596679688), (481.17254638671875, 634.1412353515625), (485.67266845703125, 625.9034423828125), (500.30511474609375, 593.5362548828125), (509.0242614746094, 572.3162841796875), (528.770751953125, 524.2192993164062), (543.558349609375, 493.602294921875), (548.7818603515625, 482.5348815917969), (557.7964477539062, 465.4939880371094), (563.0701293945312, 452.5161437988281), (573.4356079101562, 432.5819396972656), (580.0628051757812, 419.9350891113281), (585.975830078125, 401.2474060058594), (589.7974243164062, 391.05029296875), (594.1747436523438, 378.7041015625), (595.8828735351562, 376.2850646972656), (598.3388671875, 372.5390930175781), (599.6609497070312, 371.7095947265625)], 0.033000)
        post_action(0.353033)
        perform_swipe_event([(343.52288818359375, 983.2318725585938), (352.15087890625, 941.5445556640625), (377.02978515625, 857.669677734375), (391.07806396484375, 808.5046997070312), (402.1864318847656, 768.517578125), (417.53460693359375, 723.1405639648438), (435.13714599609375, 675.2759399414062), (443.3757019042969, 648.9288940429688), (458.33013916015625, 609.0335693359375), (471.66778564453125, 577.9027099609375), (477.50439453125, 566.5834350585938), (494.4761962890625, 533.1380004882812), (500.7044677734375, 521.6925659179688), (514.2857055664062, 496.6120300292969), (517.2816162109375, 489.6174621582031), (525.2979125976562, 480.6039123535156), (529.9220581054688, 474.80645751953125), (539.218994140625, 463.1783142089844), (543.3851928710938, 457.78924560546875), (549.2515258789062, 452.6415710449219), (553.14599609375, 447.7359924316406), (554.06591796875, 444.8170166015625), (554.230224609375, 444.6526184082031), (555.2288818359375, 443.65338134765625), (556.2274780273438, 443.65338134765625)], 0.033000)
        post_action(0.331043)
        perform_swipe_event([(335.53399658203125, 973.2396850585938), (361.99725341796875, 909.7891845703125), (382.7709655761719, 846.2798461914062), (396.5654296875, 809.0194091796875), (403.09979248046875, 789.00048828125), (418.8821105957031, 742.2205810546875), (447.2260437011719, 665.3233642578125), (463.7931213378906, 619.0638427734375), (477.510009765625, 580.096435546875), (486.72943115234375, 563.1006469726562), (493.81414794921875, 550.56982421875), (505.0885314941406, 526.8108520507812), (510.8656921386719, 516.7609252929688), (521.0044555664062, 497.15545654296875), (525.7942504882812, 487.57012939453125), (534.9386596679688, 474.7770690917969), (538.7517700195312, 468.13427734375), (544.296875, 459.903564453125), (547.2700805664062, 455.5987243652344), (550.3903198242188, 451.4925231933594), (552.7373657226562, 449.14410400390625), (554.230224609375, 446.8785095214844), (555.2272338867188, 446.65106201171875), (555.2288818359375, 446.65106201171875)], 0.033000)
        post_action(0.000000)




    except Exception as e:

        print(e)

        traceback_str = ''.join(traceback.format_tb(e.__traceback__))

        print(traceback_str)

    os.system("adb shell am force-stop " + package_name)
    