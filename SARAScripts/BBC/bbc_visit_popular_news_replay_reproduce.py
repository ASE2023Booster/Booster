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
        time.sleep(3)
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


        perform_click_event("Tap", 651.095703, 208.836853, 0.112000, "Activity")
        post_action(10.062730)
        perform_click_event("Tap", 566.213623, 403.684631, 0.111000, "Activity")
        post_action(6.374874)
        perform_swipe_event([(496.3106994628906, 1087.150634765625), (498.8921203613281, 1061.3023681640625), (512.2884521484375, 1002.217041015625), (521.7753295898438, 959.7501831054688), (529.6363525390625, 930.1575317382812), (537.5274658203125, 900.6246948242188), (540.7489624023438, 888.8056640625), (548.9880981445312, 864.0108642578125), (552.5449829101562, 853.3961791992188), (561.0877075195312, 830.68359375), (562.570068359375, 821.2769165039062), (569.0509643554688, 801.849609375), (574.34814453125, 788.5193481445312), (581.5806274414062, 770.2332763671875), (589.1578979492188, 749.4779663085938), (595.0924072265625, 733.2828979492188), (604.160888671875, 716.4402465820312), (611.4635009765625, 699.8277587890625), (616.7877197265625, 689.3875732421875), (621.7127075195312, 679.31689453125), (625.4620361328125, 669.8153076171875), (626.13037109375, 665.6377563476562), (627.1290283203125, 665.4801025390625), (627.1290283203125, 664.4808959960938), (628.626953125, 664.4808959960938), (629.3902587890625, 663.4816284179688), (629.126220703125, 663.4816284179688)], 0.033000)
        post_action(2.830844)
        perform_swipe_event([(500.3051452636719, 1130.1170654296875), (501.6871643066406, 1110.0655517578125), (513.556640625, 1063.6568603515625), (524.6148071289062, 1024.3411865234375), (541.74755859375, 979.2349853515625), (546.074951171875, 966.5780639648438), (554.1643676757812, 947.4356079101562), (561.687744140625, 931.336669921875), (563.90283203125, 924.9053955078125), (570.3884887695312, 910.9871215820312), (576.2947998046875, 900.47119140625), (578.6962890625, 892.3028564453125), (581.1087646484375, 888.558349609375), (582.19140625, 884.9234619140625), (582.19140625, 882.6990966796875), (584.1287231445312, 880.3722534179688), (584.1886596679688, 879.3588256835938), (584.1886596679688, 879.3130493164062)], 0.030000)
        post_action(3.069643)
        perform_swipe_event([(481.33148193359375, 1149.102294921875), (484.0577392578125, 1130.0068359375), (494.5330810546875, 1099.0914306640625), (510.92767333984375, 1049.268310546875), (520.841796875, 1017.6181640625), (528.3516845703125, 997.3262939453125), (532.59716796875, 988.219970703125), (543.9154663085938, 959.073486328125), (578.1853637695312, 890.8214111328125), (584.7499389648438, 877.4093017578125), (589.3151245117188, 869.12060546875), (591.6782836914062, 861.82666015625), (593.0964965820312, 859.4083862304688), (594.2523803710938, 857.1748046875), (595.5358276367188, 856.3309936523438), (595.1734008789062, 855.331787109375), (594.33349609375, 858.01171875), (586.4519653320312, 873.784423828125), (571.5552368164062, 906.3380737304688), (554.39013671875, 945.3012084960938), (534.3335571289062, 994.6878662109375), (522.3604736328125, 1027.667724609375), (518.0110473632812, 1046.7991943359375), (515.5065307617188, 1050.734130859375), (511.76568603515625, 1066.4991455078125), (509.3955993652344, 1073.8516845703125), (503.5706481933594, 1086.124755859375), (501.30377197265625, 1094.145263671875), (498.5547180175781, 1103.90185546875), (497.2298278808594, 1107.2940673828125), (496.0972900390625, 1110.7733154296875), (494.812744140625, 1115.12890625), (494.3134765625, 1116.906982421875), (494.3134765625, 1118.741943359375), (494.3134765625, 1120.1248779296875), (493.3148498535156, 1120.1248779296875), (493.3148498535156, 1121.623779296875), (494.1426086425781, 1119.296630859375), (499.18353271484375, 1103.799560546875), (512.7977294921875, 1064.282958984375), (527.5125732421875, 1019.593505859375), (548.8968505859375, 966.6393432617188), (577.8034057617188, 902.0833740234375), (583.7394409179688, 886.8766479492188), (600.3865966796875, 854.8912353515625), (615.4901123046875, 824.94140625), (628.212890625, 797.3923950195312), (638.9071044921875, 783.2346801757812), (646.9891967773438, 774.7294311523438), (651.9494018554688, 768.5809326171875), (658.888427734375, 760.6022338867188), (659.5838623046875, 758.4075317382812), (661.6766357421875, 756.8131103515625), (663.186279296875, 755.4098510742188), (663.0791015625, 755.4098510742188)], 0.033000)
        post_action(0.277222)
        perform_swipe_event([(463.3564453125, 1128.11865234375), (485.85595703125, 1086.4337158203125), (513.7243041992188, 1018.3964233398438), (544.0546264648438, 941.239013671875), (577.4486694335938, 866.9150390625), (593.9237060546875, 835.9432373046875), (613.3204956054688, 801.968505859375), (645.4698486328125, 760.0398559570312), (656.0946655273438, 735.1594848632812), (660.84716796875, 724.9036254882812), (662.9931030273438, 718.6968383789062), (665.0762939453125, 711.4442138671875), (668.0721435546875, 709.4456787109375), (667.0735473632812, 709.4457397460938), (667.0735473632812, 708.446533203125), (669.0707397460938, 708.446533203125), (670.0183715820312, 708.446533203125), (670.0693359375, 708.446533203125)], 0.033000)
        post_action(0.484458)
        perform_swipe_event([(494.3134765625, 1061.1708984375), (498.38653564453125, 997.4586181640625), (510.77252197265625, 948.491943359375), (524.2109375, 903.0538940429688), (557.1329345703125, 832.60888671875), (578.1427001953125, 790.5960693359375), (590.5386352539062, 765.6842041015625), (607.717529296875, 733.358642578125), (624.4512939453125, 702.2006225585938), (630.5328979492188, 689.3485107421875), (635.0076904296875, 687.490478515625), (652.5936279296875, 663.9813232421875), (661.4329223632812, 646.5755615234375), (664.3335571289062, 639.9876098632812), (664.0776977539062, 640.4996337890625), (665.0762939453125, 640.4996337890625), (665.0762939453125, 639.76318359375), (665.0762939453125, 639.5003662109375)], 0.033000)
        post_action(0.546886)
        perform_swipe_event([(451.37310791015625, 1131.1163330078125), (455.369384765625, 1098.1329345703125), (465.120849609375, 1056.9534912109375), (481.0544738769531, 1004.1170654296875), (503.35546875, 940.1018676757812), (521.736572265625, 887.76904296875), (542.4393920898438, 845.9535522460938), (552.1344604492188, 828.5254516601562), (564.5071411132812, 805.7881469726562), (571.7059936523438, 791.3817138671875), (575.3475952148438, 786.2390747070312), (575.2011108398438, 786.3856201171875), (576.19970703125, 786.3856201171875), (576.8444213867188, 785.3864135742188), (577.1983642578125, 785.3864135742188), (577.1983642578125, 784.38720703125)], 0.033000)
        post_action(2.718053)
        perform_swipe_event([(487.32318115234375, 1112.131103515625), (493.4930725097656, 1057.28173828125), (500.5592956542969, 1028.5511474609375), (515.9140625, 972.7177124023438), (536.3840942382812, 912.7514038085938), (559.9376831054688, 856.7362060546875), (580.4691162109375, 818.628662109375), (588.6693115234375, 803.3345336914062), (608.6546020507812, 765.4019775390625), (624.3514404296875, 738.6888427734375), (634.4542236328125, 721.8909912109375), (652.4949340820312, 698.5276489257812), (659.2674560546875, 685.5524291992188), (666.2822875976562, 666.0643920898438), (669.163818359375, 659.251953125), (675.0455932617188, 648.527099609375), (677.0596313476562, 642.7152709960938), (679.056884765625, 640.4365844726562), (679.056884765625, 639.000732421875), (681.0540771484375, 639.5003662109375)], 0.033000)
        post_action(0.668314)
        perform_swipe_event([(441.386962890625, 1163.09130859375), (439.21209716796875, 1125.4332275390625), (441.9792175292969, 1101.0986328125), (450.74456787109375, 1062.002685546875), (461.17791748046875, 1018.4752807617188), (467.1054992675781, 999.9561157226562), (485.82525634765625, 946.2607421875), (510.8890380859375, 892.3458251953125), (524.262451171875, 861.8502807617188), (529.23828125, 854.7748413085938), (549.692626953125, 822.6732177734375), (564.6100463867188, 796.5892944335938), (574.2532958984375, 783.02978515625), (584.8389282226562, 767.8651733398438), (586.9422607421875, 763.7671508789062), (592.5726318359375, 757.913330078125), (607.466796875, 735.79052734375), (612.684814453125, 729.8939819335938), (619.61328125, 721.7254028320312), (620.494140625, 721.080810546875), (622.8466796875, 719.4379272460938), (623.6337890625, 719.4379272460938), (623.134521484375, 719.4379272460938)], 0.033000)
        post_action(0.531883)
        perform_swipe_event([(450.3744812011719, 1077.158447265625), (454.804931640625, 1032.8271484375), (467.463623046875, 996.161376953125), (488.2196044921875, 942.525146484375), (510.994140625, 892.0723266601562), (520.3807373046875, 870.3775024414062), (536.9577026367188, 839.8522338867188), (544.848388671875, 826.6788940429688), (556.0697021484375, 808.4210815429688), (568.0526123046875, 788.6610717773438), (572.1483154296875, 784.4441528320312), (583.1900024414062, 767.4004516601562)], 0.033000)
        post_action(6.737009)
        perform_swipe_event([(572.2052612304688, 756.4090576171875), (558.4869995117188, 791.8391723632812), (547.6096801757812, 826.4011840820312), (535.4735717773438, 863.619140625), (522.77392578125, 899.29736328125), (517.0797119140625, 927.8177490234375), (513.1248779296875, 941.8057861328125), (508.9328918457031, 962.8690185546875), (505.5320129394531, 984.8258056640625), (503.70184326171875, 991.0215454101562), (500.93048095703125, 1004.0844116210938), (501.3037414550781, 1009.6101684570312), (497.4462585449219, 1020.5169067382812), (496.2718505859375, 1024.3165283203125), (495.31207275390625, 1032.2235107421875), (493.7149353027344, 1034.390625), (493.3148498535156, 1037.0311279296875), (493.3148498535156, 1038.361328125), (493.3148498535156, 1039.45654296875), (492.31622314453125, 1039.1881103515625), (492.31622314453125, 1040.1873779296875), (492.31622314453125, 1041.338134765625)], 0.034000)
        post_action(2.766608)
        perform_key_event(4)
        post_action(0.996777)
        perform_swipe_event([(456.3661804199219, 1156.0968017578125), (471.0769958496094, 1107.9405517578125), (497.5429992675781, 1023.939453125), (507.4561462402344, 991.6887817382812), (517.9465942382812, 961.9166259765625), (521.2760009765625, 952.0482177734375), (523.2732543945312, 945.4985961914062), (524.8217163085938, 944.2622680664062), (525.2704467773438, 943.220947265625), (525.2704467773438, 943.2630615234375), (525.2704467773438, 941.9837036132812)], 0.033500)
        post_action(0.447638)
        perform_click_event("Tap", 633.120667, 393.692413, 0.112000, "Activity")
        post_action(7.655042)
        perform_swipe_event([(512.2885131835938, 1022.201416015625), (513.786376953125, 995.2224731445312), (530.826171875, 931.300537109375), (542.9965209960938, 898.3585205078125), (553.0733032226562, 874.7130737304688), (561.4359741210938, 856.8991088867188), (571.9619750976562, 833.4216918945312), (584.2059936523438, 810.3322143554688), (596.6712646484375, 787.8843994140625), (607.975341796875, 768.3668823242188), (621.4170532226562, 745.8571166992188), (638.0628051757812, 723.6297607421875), (654.2427368164062, 703.5818481445312), (664.8740844726562, 685.7681274414062), (666.0748901367188, 680.968017578125), (671.9817504882812, 667.690673828125), (674.306640625, 662.9957885742188), (676.2857666015625, 660.146728515625), (678.4354248046875, 650.42529296875), (680.5285034179688, 647.2838134765625), (682.352294921875, 641.8986206054688), (682.052734375, 641.0809326171875), (684.0499267578125, 639.000732421875), (686.0471801757812, 638.5011596679688)], 0.033000)
        post_action(3.024335)
        perform_swipe_event([(476.33843994140625, 1113.13037109375), (479.7676696777344, 1089.1109619140625), (487.32318115234375, 1061.670654296875), (502.778076171875, 1012.5416870117188), (512.2884521484375, 980.234130859375), (521.4511108398438, 952.7297973632812), (535.4003295898438, 921.2986450195312), (550.7694702148438, 886.876220703125), (566.0900268554688, 857.5775756835938), (570.158203125, 848.449462890625), (580.3676147460938, 831.5464477539062), (586.5985717773438, 820.1416015625), (589.451904296875, 814.822265625), (591.4219970703125, 812.1221923828125), (592.1775512695312, 811.3660888671875), (593.1761474609375, 811.3660888671875), (593.1761474609375, 810.3746948242188), (593.1761474609375, 810.3668823242188)], 0.033000)
        post_action(0.753327)
        perform_swipe_event([(473.34259033203125, 1115.1287841796875), (473.34259033203125, 1098.5523681640625), (475.4119873046875, 1082.7928466796875), (483.0838623046875, 1048.9725341796875), (500.2804870605469, 987.5322265625), (506.2875671386719, 968.2713623046875), (521.2069091796875, 929.4469604492188), (532.9147338867188, 899.1029052734375), (541.747314453125, 879.613525390625), (556.8310546875, 853.383544921875), (564.574462890625, 836.808349609375), (581.9002685546875, 808.378662109375), (608.6820678710938, 767.6091918945312), (622.0343017578125, 746.2532958984375), (650.40576171875, 713.25927734375), (664.3046875, 690.251708984375), (671.5672607421875, 677.470703125), (677.324462890625, 663.0399780273438), (681.4766845703125, 655.6414184570312), (683.65771484375, 648.8858032226562), (686.2236328125, 644.3198852539062), (686.0471801757812, 641.9984130859375), (689.04296875, 641.4988403320312), (688.0443725585938, 641.4988403320312)], 0.033000)
        post_action(1.416342)
        perform_swipe_event([(638.11376953125, 643.4972534179688), (604.1450805664062, 706.9296875), (584.2562255859375, 745.4545288085938), (554.3373413085938, 809.1533203125), (540.40869140625, 840.193359375), (530.2635498046875, 865.8236083984375), (520.2803344726562, 897.2862548828125), (509.6581115722656, 923.7999267578125), (501.843994140625, 948.0953369140625), (496.3272399902344, 964.1970825195312), (491.4267578125, 977.4630737304688), (489.4950256347656, 982.057861328125), (489.3204040527344, 983.2318725585938), (490.81829833984375, 977.7362060546875), (499.367919921875, 944.8283081054688), (518.7765502929688, 881.8200073242188), (543.6400146484375, 816.4559326171875), (567.8740234375, 759.482421875), (596.1829833984375, 702.4292602539062), (619.376953125, 664.8773193359375), (632.6953125, 643.1790161132812), (649.86279296875, 617.2057495117188), (659.8290405273438, 594.3583984375), (664.0076904296875, 584.9506225585938), (675.2442626953125, 568.7825317382812), (678.2962036132812, 563.4959106445312), (683.6383666992188, 558.9754638671875), (687.958984375, 557.5857543945312), (688.0443725585938, 557.5643920898438)], 0.033000)
        post_action(0.247107)
        perform_swipe_event([(430.4022216796875, 1108.13427734375), (426.79974365234375, 1092.9947509765625), (432.3912353515625, 1048.2222900390625), (445.45855712890625, 995.5669555664062), (466.01190185546875, 920.4739379882812), (491.2236633300781, 856.0663452148438), (523.7725830078125, 786.88525390625), (555.44921875, 730.2932739257812), (572.9697875976562, 694.1472778320312), (591.4447631835938, 659.3745727539062), (611.7850341796875, 625.400634765625), (659.312255859375, 556.9949951171875), (664.7882080078125, 543.44091796875), (667.0735473632812, 538.7023315429688), (669.0707397460938, 535.2406005859375), (671.9734497070312, 533.5831298828125), (674.5598754882812, 533.5831298828125), (674.0638427734375, 533.5831298828125)], 0.033000)
        post_action(0.501065)
        perform_swipe_event([(644.1054077148438, 621.5144653320312), (612.8428955078125, 677.3140869140625), (602.457275390625, 697.8668212890625), (578.9087524414062, 745.9916381835938), (565.8912353515625, 778.198974609375), (543.223876953125, 833.0011596679688), (521.160888671875, 893.9552001953125), (507.6964111328125, 947.3734130859375), (501.67510986328125, 970.8283081054688), (495.6423645019531, 1006.5599975585938), (490.31903076171875, 1036.690185546875), (488.6139831542969, 1044.1361083984375), (488.32177734375, 1050.344970703125), (487.1224670410156, 1052.57958984375), (486.3245544433594, 1056.91845703125), (486.3245544433594, 1058.7828369140625), (486.3245544433594, 1060.1717529296875)], 0.031500)
        post_action(0.300826)
        perform_key_event(4)
        post_action(0.768656)
        perform_swipe_event([(499.3065185546875, 1144.106201171875), (501.9895935058594, 1085.657470703125), (517.8574829101562, 990.3427124023438), (563.9879760742188, 844.1809692382812), (576.2064819335938, 814.095458984375), (590.683837890625, 783.3794555664062), (600.813720703125, 765.6934204101562), (608.1823120117188, 752.3447265625), (612.4598999023438, 743.4873657226562), (614.6463623046875, 739.42236328125), (615.1456298828125, 737.6270751953125), (617.398193359375, 733.9152221679688), (618.1414794921875, 731.92822265625), (619.9638061523438, 729.6051025390625), (620.1387329101562, 728.430908203125), (621.1373291015625, 727.4317016601562), (621.1373291015625, 726.4324951171875), (621.1373291015625, 725.4332275390625)], 0.033000)
        post_action(0.316178)
        perform_click_event("Tap", 616.144287, 633.505066, 0.139000, "Activity")
        post_action(8.033817)
        perform_swipe_event([(459.36199951171875, 1131.1163330078125), (460.0039367675781, 1092.4326171875), (466.7438049316406, 1048.351318359375), (473.84185791015625, 1013.2083740234375), (485.78216552734375, 965.1901245117188), (538.0469970703125, 827.6619873046875), (564.6290283203125, 779.9609375), (582.9310302734375, 751.1787719726562), (588.0078125, 740.596923828125), (588.6596069335938, 739.9447631835938), (588.18310546875, 740.4215698242188), (589.1817016601562, 738.423095703125)], 0.050000)
        post_action(0.668959)
        perform_swipe_event([(460.3606262207031, 1125.1209716796875), (460.3606262207031, 1091.8218994140625), (470.0342712402344, 1057.967041015625), (493.6006774902344, 967.3856201171875), (514.7850341796875, 900.7962646484375), (531.277587890625, 857.0964965820312), (550.4075317382812, 822.8062744140625), (568.8521118164062, 788.9800415039062), (573.280029296875, 782.2744750976562), (578.07421875, 774.517822265625), (579.4916381835938, 773.3958129882812), (579.195556640625, 772.3965454101562)], 0.052000)
        post_action(2.753849)
        perform_swipe_event([(455.3675537109375, 1140.1092529296875), (453.86962890625, 1089.648681640625), (464.8937072753906, 1029.8580322265625), (476.5309753417969, 990.0515747070312), (505.5882263183594, 903.1393432617188), (528.6884765625, 845.887939453125), (542.7962036132812, 822.07421875), (558.9795532226562, 794.7859497070312), (580.7926025390625, 761.0059814453125), (584.9730834960938, 752.8408203125), (587.1845092773438, 750.3622436523438), (588.18310546875, 749.4144897460938), (588.18310546875, 748.415283203125), (590.1802978515625, 745.4176635742188), (590.9628295898438, 742.63623046875), (592.9754638671875, 738.0263671875), (597.3427734375, 733.1685180664062), (603.66162109375, 724.43408203125), (606.4437255859375, 718.5811157226562), (616.3496704101562, 706.1398315429688), (624.1665649414062, 693.7355346679688), (626.244140625, 690.3468017578125), (627.9403076171875, 688.462158203125), (631.7428588867188, 684.8447265625), (643.8908081054688, 668.0979614257812), (649.5982666015625, 661.6826782226562), (657.8497314453125, 651.8062133789062), (661.6759033203125, 646.7015991210938), (666.0748901367188, 637.501953125), (674.5316772460938, 630.2733154296875), (676.06103515625, 629.5081787109375)], 0.035000)
        post_action(0.369064)
        perform_swipe_event([(454.3689270019531, 1124.121826171875), (456.107177734375, 1078.8428955078125), (459.48858642578125, 1054.47900390625), (467.7792663574219, 1016.4900512695312), (478.71942138671875, 977.288818359375), (485.3454895019531, 953.5845947265625), (499.1199035644531, 918.1455078125), (517.571533203125, 868.917724609375), (524.7847900390625, 852.4456787109375), (544.7434692382812, 818.360595703125), (607.8463134765625, 711.6265869140625), (662.4672241210938, 639.1133422851562), (665.0762939453125, 636.8133544921875), (668.0721435546875, 636.5027465820312), (667.0735473632812, 635.5035400390625)], 0.033000)
        post_action(0.460366)
        perform_swipe_event([(452.3717041015625, 1131.1163330078125), (448.85101318359375, 1080.091064453125), (458.8221130371094, 1034.62451171875), (464.3512268066406, 1012.22265625), (541.5278930664062, 812.9876708984375), (562.6194458007812, 777.2413330078125), (608.6353149414062, 706.473876953125), (625.8780517578125, 680.3474731445312), (629.126220703125, 676.4714965820312), (629.126220703125, 675.4722900390625), (629.126220703125, 674.720703125), (630.1248168945312, 674.4730834960938)], 0.033000)
        post_action(1.270436)
        perform_swipe_event([(442.3855895996094, 1180.0780029296875), (434.9352722167969, 1154.731689453125), (440.0422058105469, 1123.3619384765625), (447.7982482910156, 1078.6363525390625), (455.7086486816406, 1049.8134765625), (459.4867248535156, 1035.39990234375), (477.7428894042969, 966.0260620117188), (488.2765197753906, 933.1978149414062), (502.2474670410156, 891.5014038085938), (519.778076171875, 852.833740234375), (539.6489868164062, 815.2102661132812), (550.474853515625, 795.0549926757812), (565.662841796875, 768.5026245117188), (573.0681762695312, 757.6119384765625), (590.1943359375, 730.962646484375), (605.8239135742188, 707.5328979492188), (613.4241943359375, 696.54150390625), (617.2532348632812, 691.2389526367188), (618.1414794921875, 691.4597778320312)], 0.033000)
        post_action(1.470186)
        perform_swipe_event([(623.134521484375, 702.4512329101562), (599.1678466796875, 733.9266357421875), (592.0960693359375, 750.8826904296875), (583.4785766601562, 768.49951171875), (574.3739624023438, 786.0853881835938), (567.053955078125, 800.6913452148438), (562.4464721679688, 812.4547119140625), (558.2574462890625, 822.2919311523438), (553.2315673828125, 830.850830078125), (552.2330322265625, 836.1180419921875), (548.7032470703125, 840.8778076171875), (547.9734497070312, 842.8724365234375), (545.6112060546875, 849.5983276367188), (544.3845825195312, 852.91162109375), (542.2468872070312, 861.7054443359375), (539.6242065429688, 865.576416015625), (538.3031616210938, 868.2200317382812), (537.2538452148438, 871.5262451171875), (537.2538452148438, 872.3184814453125)], 0.033000)
        post_action(0.453062)
        perform_key_event(4)
        post_action(0.821249)
        perform_swipe_event([(493.3148498535156, 1146.1046142578125), (495.1614685058594, 1103.19384765625), (496.39190673828125, 1084.8516845703125), (501.10894775390625, 1047.53466796875), (508.0408630371094, 1003.8566284179688), (516.0018920898438, 961.1776123046875), (522.1795043945312, 933.0487670898438), (534.818359375, 895.7044677734375), (545.1621704101562, 862.1089477539062), (552.6641845703125, 845.530517578125), (564.1670532226562, 817.771484375), (572.6242065429688, 801.5347290039062), (585.7212524414062, 772.0715942382812), (600.813720703125, 742.8980712890625), (612.35107421875, 722.0730590820312), (624.4719848632812, 703.175537109375), (636.328857421875, 692.0498046875), (637.1151123046875, 690.4580078125), (638.11376953125, 689.4613647460938), (639.031494140625, 688.462158203125), (639.1123657226562, 686.1719360351562), (640.1109619140625, 684.8098754882812), (641.0706787109375, 682.544677734375), (643.6060791015625, 672.474609375)], 0.033000)
        post_action(0.602189)
        perform_swipe_event([(466.352294921875, 1156.0968017578125), (468.4400939941406, 1123.124755859375), (475.8391418457031, 1081.655029296875), (489.6772155761719, 1007.123291015625), (501.2524719238281, 963.241455078125), (506.8528137207031, 941.85986328125), (517.1161499023438, 909.577880859375), (522.238525390625, 894.9996948242188), (530.896728515625, 869.598876953125), (538.614990234375, 854.666748046875), (549.1917114257812, 833.6307983398438), (555.1226806640625, 821.1498413085938), (564.4955444335938, 801.9943237304688), (578.809326171875, 776.0382690429688), (587.824951171875, 759.5341796875), (600.6844482421875, 736.56005859375), (610.6985473632812, 717.34619140625), (615.6560668945312, 710.3062133789062), (621.7573852539062, 700.9578247070312), (623.3280029296875, 698.067138671875), (623.134521484375, 695.180908203125), (624.6325073242188, 695.4566650390625), (623.134521484375, 695.4566650390625), (623.134521484375, 696.4558715820312), (621.310546875, 699.2802124023438), (610.2479248046875, 719.612060546875), (594.0262451171875, 756.0896606445312), (582.52978515625, 781.4576416015625), (565.71435546875, 819.35986328125), (551.9097290039062, 858.138916015625), (540.4623413085938, 893.8594970703125), (526.9865112304688, 932.1165161132812), (516.2716064453125, 975.2836303710938), (507.1544494628906, 1019.6699829101562), (500.0358581542969, 1043.8397216796875), (494.177490234375, 1072.661376953125), (486.2654724121094, 1097.0267333984375), (481.6773376464844, 1113.7056884765625), (479.1633605957031, 1128.9736328125), (477.0704040527344, 1135.91357421875), (475.3398132324219, 1140.9705810546875), (473.8630676269531, 1142.5860595703125), (474.3412170410156, 1143.3387451171875), (474.3412170410156, 1143.10693359375)], 0.033000)
        post_action(0.978291)
        perform_swipe_event([(623.134521484375, 687.462890625), (614.2796630859375, 706.7943115234375), (586.8604125976562, 770.8778076171875), (576.7714233398438, 801.263427734375), (571.427734375, 817.697021484375), (562.8069458007812, 843.5751342773438), (555.2103271484375, 871.72021484375), (552.0675048828125, 882.5296630859375), (545.6935424804688, 904.7617797851562), (541.8971557617188, 918.73388671875), (536.349853515625, 938.9347534179688), (531.755126953125, 954.7730102539062), (527.2677001953125, 968.2435302734375), (524.17626953125, 979.61767578125), (522.0652465820312, 984.650146484375), (521.2760009765625, 987.0263061523438), (521.2760009765625, 989.2999267578125), (521.2760009765625, 990.2263793945312), (520.2774047851562, 992.1332397460938), (520.2774047851562, 993.3016967773438), (518.779541015625, 993.2240600585938), (519.27880859375, 994.2232666015625), (519.27880859375, 995.4458618164062), (519.27880859375, 995.2224731445312), (519.27880859375, 996.2216796875), (519.27880859375, 997.4260864257812), (518.8064575195312, 997.220947265625), (518.2801513671875, 997.9186401367188), (518.2801513671875, 998.7197265625), (518.2801513671875, 998.2201538085938)], 0.033000)
        post_action(0.591544)
        perform_click_event("Tap", 628.127625, 630.507385, 0.156000, "Activity")
        post_action(8.629890)
        perform_swipe_event([(504.2995910644531, 1058.17333984375), (512.2885131835938, 1010.210693359375), (521.6015625, 965.1270141601562), (550.9398803710938, 876.5640869140625), (558.7630615234375, 855.48388671875), (568.2887573242188, 832.1937255859375), (582.1914672851562, 799.8751220703125), (622.47216796875, 722.7619018554688), (664.0776977539062, 670.341796875), (664.0776977539062, 669.4769897460938)], 0.049000)
        post_action(2.728665)
        perform_swipe_event([(453.3703308105469, 1125.1209716796875), (460.3606262207031, 1110.1326904296875), (465.2430114746094, 1095.5872802734375), (471.8167724609375, 1075.743408203125), (480.5345153808594, 1039.57958984375), (484.7194519042969, 1021.5004272460938), (491.9713134765625, 999.2554931640625), (498.74951171875, 976.724365234375), (500.9997253417969, 967.6140747070312), (510.070556640625, 940.3731689453125), (514.2857666015625, 928.7743530273438), (522.1237182617188, 901.8998413085938), (532.7486572265625, 877.23974609375), (550.3184204101562, 839.1788940429688), (562.027099609375, 814.84423828125), (573.3756713867188, 793.470458984375), (581.562255859375, 778.861572265625), (586.1602172851562, 771.435791015625), (593.0640258789062, 761.517333984375), (595.17333984375, 756.4090576171875), (597.1705932617188, 754.41064453125), (597.1705932617188, 753.333984375), (598.3733520507812, 753.411376953125), (598.1692504882812, 752.4121704101562), (598.1692504882812, 751.4129638671875), (599.1678466796875, 750.4818115234375), (599.1678466796875, 750.4137573242188)], 0.033000)
        post_action(3.369576)
        perform_swipe_event([(455.3675537109375, 1112.131103515625), (461.0216064453125, 1091.11767578125), (466.69775390625, 1073.123779296875), (470.31292724609375, 1057.34326171875), (474.1756286621094, 1039.1002197265625), (480.5830383300781, 1017.3701782226562), (487.5880432128906, 994.5294189453125), (493.11114501953125, 976.9507446289062), (507.18017578125, 930.5615234375), (510.7905578613281, 917.782958984375), (514.0482177734375, 910.0025024414062), (516.282958984375, 903.64599609375), (518.2801513671875, 898.7069702148438), (519.27880859375, 896.4852294921875), (520.7767333984375, 894.8009033203125), (521.2760009765625, 894.3013305664062)], 0.033000)
        post_action(0.746168)
        perform_swipe_event([(456.3661804199219, 1114.129638671875), (459.58343505859375, 1084.1551513671875), (467.3509521484375, 1045.6829833984375), (479.2945556640625, 1003.3552856445312), (500.3992919921875, 937.4268798828125), (516.2081909179688, 893.2298583984375), (536.0067138671875, 848.140869140625), (554.62060546875, 814.5333862304688), (575.175537109375, 779.4326782226562), (580.14892578125, 770.4796752929688), (599.6671752929688, 739.9219360351562), (621.1598510742188, 708.9179077148438), (635.2901611328125, 692.28662109375), (637.7490844726562, 690.1911010742188), (646.5711669921875, 675.533935546875), (660.0637817382812, 654.517822265625), (662.7587280273438, 648.8139038085938), (664.0776977539062, 646.3256225585938), (665.0762939453125, 646.4949340820312), (663.1815185546875, 647.4429321289062), (654.0469360351562, 659.3474731445312), (630.2496337890625, 694.2909545898438), (589.0953369140625, 755.7566528320312), (569.3203735351562, 788.939208984375), (552.2384643554688, 820.0990600585938), (532.3782958984375, 858.2537841796875), (527.0040893554688, 868.8492431640625), (520.3475341796875, 888.5599365234375), (518.2802124023438, 892.802490234375), (516.337890625, 898.1882934570312), (515.1509399414062, 901.6963500976562), (512.400146484375, 908.6224365234375), (510.9405212402344, 913.6607666015625), (505.4284973144531, 929.8821411132812), (500.125, 944.5081787109375), (494.9217224121094, 966.8809204101562), (487.4287414550781, 990.90869140625), (481.5107116699219, 1013.9429321289062), (475.839111328125, 1043.6845703125), (472.2488098144531, 1074.30419921875), (470.1476135253906, 1091.7423095703125), (467.5661926269531, 1102.491943359375), (466.2915954589844, 1106.1358642578125), (466.352294921875, 1108.13427734375)], 0.033000)
        post_action(0.000000)




    except Exception as e:

        print(e)

        traceback_str = ''.join(traceback.format_tb(e.__traceback__))

        print(traceback_str)

    os.system("adb shell am force-stop " + package_name)