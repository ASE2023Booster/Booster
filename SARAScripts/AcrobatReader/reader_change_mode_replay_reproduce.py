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



        perform_click_event("Tap", 203.717072, 233.817337, 0.143000, "Activity")
        post_action(1.563048)
        perform_click_event("Tap", 483.380035, 381.555054, 0.112000, "Activity")
        post_action(3.675155)
        perform_click_event("Tap", 87.894592, 1225.028931, 0.112000, "Activity")
        post_action(1.670267)
        perform_click_event("Tap", 174.757278, 590.538635, 0.095000, "Dialog")
        post_action(1.166608)
        perform_swipe_event([(700.0277709960938, 761.4051513671875), (670.9341430664062, 760.365478515625), (642.8280639648438, 761.8847045898438), (613.95703125, 762.4043579101562), (587.9008178710938, 764.424560546875), (571.5203857421875, 766.7614135742188), (543.7447509765625, 770.398193359375), (512.49267578125, 775.7203979492188), (497.2941589355469, 779.3177490234375), (468.9447326660156, 784.40234375), (451.9480895996094, 786.2731323242188), (420.82208251953125, 790.752685546875), (389.4590759277344, 794.37939453125), (371.0210266113281, 794.0772094726562), (336.20501708984375, 795.5447387695312), (320.7491455078125, 796.5780639648438), (282.8094177246094, 799.113037109375), (250.13087463378906, 801.4111328125), (200.29391479492188, 805.9009399414062), (154.26803588867188, 811.4131469726562), (129.2726287841797, 814.596435546875), (111.81835174560547, 817.2224731445312), (94.2317123413086, 820.6317749023438), (78.7579574584961, 823.0457763671875), (68.35376739501953, 825.2655029296875), (59.41748046875, 827.853271484375), (52.832115173339844, 830.0496826171875), (44.219547271728516, 832.5293579101562), (35.950069427490234, 833.3489379882812), (31.38799476623535, 835.1317749023438), (29.935577392578125, 835.347412109375), (25.021528244018555, 835.347412109375), (23.966712951660156, 836.3466186523438), (22.92391014099121, 836.3466186523438), (22.96809959411621, 836.3466186523438)])
        post_action(0.962465)
        perform_swipe_event([(712.0111083984375, 860.327880859375), (672.5724487304688, 863.2893676757812), (644.7552490234375, 865.4363403320312), (609.7761840820312, 868.6609497070312), (581.0421752929688, 871.2540283203125), (545.7394409179688, 876.1016235351562), (509.7651062011719, 879.8495483398438), (476.82818603515625, 881.27880859375), (457.4837951660156, 881.3114624023438), (426.40777587890625, 882.3106689453125), (390.2265319824219, 883.3099365234375), (361.5144348144531, 883.3099365234375), (327.2581787109375, 883.3099365234375), (313.0330810546875, 883.3099365234375), (275.2623596191406, 885.731689453125), (259.5289001464844, 885.75244140625), (213.229736328125, 890.1592407226562), (172.44912719726562, 895.4461059570312), (150.81582641601562, 898.170166015625), (127.09957122802734, 900.9982299804688), (114.77193450927734, 902.2020263671875), (90.49455261230469, 904.6687622070312), (78.18731689453125, 903.2943115234375), (67.16316223144531, 903.2943115234375), (57.41364288330078, 904.2935180664062), (50.192138671875, 906.786865234375), (41.16476821899414, 912.676025390625), (32.6444206237793, 916.8612670898438), (24.652080535888672, 920.1095581054688), (17.975034713745117, 923.7783203125), (14.130395889282227, 924.2778930664062), (13.980583190917969, 925.371826171875), (13.980583190917969, 925.277099609375)])
        post_action(1.816882)
        perform_click_event("Tap", 517.281555, 835.347412, 0.098000, "Activity")
        post_action(0.039814)
        perform_click_event("Tap", 520.277405, 833.348938, 0.098000, "Activity")
        post_action(2.124429)
        perform_click_event("DoubleTap", 498.307922, 800.374695, 0.124000, "Activity")
        post_action(0.069012)
        perform_swipe_event([(677.0596313476562, 839.34423828125), (661.8284301757812, 840.6143188476562), (637.4674072265625, 842.3419189453125), (607.9148559570312, 843.3411254882812), (577.0266723632812, 842.3419189453125), (557.4094848632812, 843.2622680664062), (524.7616577148438, 844.44091796875), (506.2954406738281, 845.7679443359375), (476.854248046875, 847.3380126953125), (461.1926574707031, 848.273193359375), (446.44024658203125, 849.6034545898438), (424.6173400878906, 850.6802368164062), (393.0442199707031, 854.2343139648438), (380.130615234375, 856.229736328125), (349.51458740234375, 859.8283081054688), (333.2970886230469, 860.916015625), (293.9356994628906, 865.5186767578125), (273.24530029296875, 869.0502319335938), (230.3412322998047, 871.9155883789062), (190.53546142578125, 875.151611328125), (152.81512451171875, 876.7416381835938), (129.3911590576172, 877.7666625976562), (99.88695526123047, 879.3941650390625), (73.49110412597656, 881.7117919921875), (56.92094421386719, 885.308349609375), (40.16632080078125, 886.5613403320312), (28.920846939086914, 888.6456298828125), (23.018638610839844, 891.2530517578125), (20.970874786376953, 891.3036499023438), (18.973648071289062, 892.802490234375), (17.87171173095703, 892.3028564453125), (17.975034713745117, 892.3028564453125), (15.977808952331543, 892.3028564453125)])
        post_action(0.784816)
        perform_click_event("Tap", 438.391144, 737.423889, 0.082000, "Activity")
        post_action(2.104612)
        perform_click_event("Tap", 88.898750, 1231.036743, 0.111000, "Activity")
        post_action(1.419573)
        perform_click_event("Tap", 427.811371, 647.434814, 0.112000, "Dialog")
        post_action(3.667011)
        perform_click_event("DoubleTap", 336.532593, 675.472290, 0.085000, "Activity")
        post_action(0.107482)
        perform_click_event("Tap", 88.869629, 1232.040649, 0.068000, "Activity")
        post_action(1.315424)
        perform_click_event("Tap", 542.278809, 395.633881, 0.080000, "Dialog")
        post_action(1.168495)
        perform_swipe_event([(454.3689270019531, 1033.19287109375), (456.5826110839844, 992.6237182617188), (466.0768737792969, 912.8037719726562), (478.43524169921875, 855.2833251953125), (490.001708984375, 798.5101318359375), (502.4719543457031, 705.2603149414062), (518.4306640625, 587.5865478515625), (542.704833984375, 485.5154724121094), (562.3089599609375, 425.0050048828125), (577.6263427734375, 388.3156433105469), (587.428955078125, 365.4697265625), (589.1817016601562, 363.7158508300781), (588.18310546875, 363.7158508300781)])
        post_action(0.515357)
        perform_swipe_event([(568.2108154296875, 345.7298889160156), (549.6019897460938, 387.6012268066406), (518.7567138671875, 493.1604919433594), (482.278564453125, 679.9067993164062), (467.502685546875, 798.32470703125), (455.05938720703125, 908.0308227539062), (445.92901611328125, 969.178466796875), (438.4431457519531, 1004.0073852539062), (435.3952941894531, 1010.71923828125), (435.3952941894531, 1011.7095947265625), (435.3952941894531, 1011.2099609375)])
        post_action(0.378104)
        perform_swipe_event([(546.2413330078125, 309.75799560546875), (528.4647827148438, 371.8349304199219), (505.6885070800781, 486.11712646484375), (477.67974853515625, 663.2392578125), (443.61138916015625, 835.9363403320312), (435.8744201660156, 907.5740966796875), (430.1597900390625, 977.8773803710938), (424.4105529785156, 1008.4857788085938), (420.959228515625, 1031.0189208984375), (417.3579406738281, 1046.36962890625), (416.421630859375, 1050.1795654296875)])
        post_action(0.346926)
        perform_swipe_event([(561.2205200195312, 312.7556457519531), (550.9573974609375, 336.2680969238281), (504.8279724121094, 468.9500427246094), (417.0030517578125, 947.6018676757812), (411.4285888671875, 995.3870239257812), (408.5684509277344, 1011.6660766601562), (405.4368896484375, 1029.256591796875), (403.4396667480469, 1037.5352783203125), (403.4396667480469, 1042.185791015625), (403.4396667480469, 1043.18505859375)])
        post_action(0.415662)
        perform_swipe_event([(551.2344360351562, 297.7673645019531), (539.1130981445312, 340.2406311035156), (520.9385375976562, 402.369873046875), (493.5936584472656, 515.3409423828125), (460.6053161621094, 664.40673828125), (450.3987121582031, 742.2503662109375), (440.91998291015625, 830.8331298828125), (433.85174560546875, 905.1126708984375), (428.41656494140625, 963.1433715820312), (423.79156494140625, 997.9393310546875), (419.41748046875, 1016.836669921875), (419.41748046875, 1018.2045288085938)])
        post_action(0.433850)
        perform_swipe_event([(527.2677001953125, 372.7088317871094), (515.4752197265625, 412.3897705078125), (487.68145751953125, 510.9203796386719), (457.4082946777344, 661.2131958007812), (441.5774230957031, 769.0797119140625), (432.10565185546875, 860.5637817382812), (428.7038269042969, 891.1068725585938), (422.19293212890625, 934.7628173828125), (418.205078125, 970.2054443359375), (412.5191650390625, 1007.6602172851562), (410.4299621582031, 1022.0287475585938), (410.4299621582031, 1025.1990966796875), (410.4299621582031, 1026.1982421875)])
        post_action(0.400149)
        perform_swipe_event([(545.2427368164062, 414.676025390625), (537.753173828125, 452.14678955078125), (525.452880859375, 492.2789306640625), (509.0010986328125, 557.405029296875), (496.0697326660156, 613.5662231445312), (478.2602844238281, 704.0537719726562), (471.1792297363281, 752.7427368164062), (467.51641845703125, 776.9015502929688), (465.35369873046875, 789.153564453125), (464.70361328125, 793.681884765625), (462.21966552734375, 800.6512451171875), (461.3592224121094, 804.8658447265625), (460.3606262207031, 808.3430786132812), (460.3606262207031, 809.527587890625), (460.3606262207031, 811.0615234375), (460.3606262207031, 811.3660888671875)])
        post_action(0.462659)
        perform_click_event("Tap", 92.868240, 1227.051514, 0.072000, "Activity")
        post_action(1.047186)
        perform_click_event("Tap", 567.196960, 837.335693, 0.072000, "Dialog")
        post_action(1.714921)
        perform_click_event("Tap", 92.868240, 1227.051514, 0.072000, "Activity")
        post_action(0.000000)




    except Exception as e:

        print(e)

        traceback_str = ''.join(traceback.format_tb(e.__traceback__))

        print(traceback_str)

    os.system("adb shell am force-stop " + package_name)
    