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




        perform_swipe_event([(365.49237060546875, 1035.1912841796875), (415.28729248046875, 772.03759765625), (430.1166076660156, 717.74658203125), (460.09552001953125, 635.16748046875), (495.3902587890625, 560.4055786132812), (512.5686645507812, 525.0286865234375), (525.769775390625, 493.11474609375), (544.7623901367188, 459.6029052734375), (550.70703125, 449.8934631347656), (559.5697021484375, 432.51922607421875), (562.5410766601562, 426.3609313964844), (567.0805053710938, 417.93731689453125), (571.9934692382812, 411.89031982421875), (572.6582641601562, 411.22515869140625), (575.1676025390625, 407.7149963378906), (576.1773071289062, 406.7046813964844), (577.1983642578125, 404.1842346191406), (578.1969604492188, 404.683837890625)], 0.033000)
        post_action(0.361184)
        perform_swipe_event([(352.5104064941406, 1077.158447265625), (360.6365966796875, 1048.699462890625), (367.4895935058594, 1002.7166137695312), (402.1240234375, 817.1871948242188), (418.9181823730469, 761.9047241210938), (434.78741455078125, 718.1056518554688), (456.71484375, 661.3352661132812), (484.82666015625, 606.0265502929688), (508.5683288574219, 557.7991943359375), (524.0512084960938, 527.6740112304688), (531.504150390625, 511.7015380859375), (540.4293823242188, 501.33837890625), (554.4171752929688, 483.0709228515625), (564.7156982421875, 470.63232421875), (570.64697265625, 460.9806213378906), (574.8314819335938, 457.3277587890625), (575.2011108398438, 456.64324951171875)], 0.033000)
        post_action(0.333380)
        perform_swipe_event([(338.5298156738281, 1076.1593017578125), (347.4353942871094, 1026.6629638671875), (359.0013732910156, 972.240478515625), (375.0152893066406, 912.2767333984375), (380.96807861328125, 887.3237915039062), (386.1129455566406, 867.550048828125), (390.7247619628906, 848.1339111328125), (396.44940185546875, 829.8516845703125), (401.3491516113281, 813.5979614257812), (403.4396667480469, 805.973876953125), (404.43829345703125, 802.6654663085938), (405.4368896484375, 800.4017944335938), (405.4368896484375, 799.37548828125)], 0.033000)
        post_action(0.426402)
        perform_click_event("Tap", 487.323181, 582.544861, 0.099000, "Activity")
        post_action(4.201869)
        perform_swipe_event([(502.3023681640625, 720.4371337890625), (503.806884765625, 705.8847045898438), (505.2982177734375, 691.4597778320312), (513.7202758789062, 654.53662109375), (519.2787475585938, 634.5042724609375), (523.08837890625, 613.18701171875), (528.0541381835938, 594.7789306640625), (532.1300659179688, 579.5053100585938), (536.3369140625, 565.27197265625), (542.0084228515625, 547.9078369140625), (546.5897827148438, 533.5364379882812), (551.8163452148438, 520.427978515625), (556.8484497070312, 509.04779052734375), (562.0186767578125, 495.1151428222656), (565.5946655273438, 483.671630859375), (568.7100830078125, 474.6291809082031), (573.2741088867188, 466.5301208496094), (575.3927001953125, 462.255126953125), (576.19970703125, 457.8682861328125), (577.6803588867188, 457.6424560546875), (578.1969604492188, 457.6424560546875), (579.195556640625, 458.6416931152344)], 0.033000)
        post_action(0.490558)
        perform_swipe_event([(410.4299621582031, 1124.121826171875), (411.2250671386719, 1088.5950927734375), (414.41717529296875, 1066.25390625), (423.41192626953125, 1021.2021484375), (429.17047119140625, 990.0283203125), (433.9126892089844, 969.43896484375), (440.00201416015625, 940.8125), (444.5683898925781, 920.351806640625), (451.31878662109375, 901.51318359375), (457.2747802734375, 883.580078125), (460.3606262207031, 872.0305786132812), (464.03173828125, 862.9447021484375), (469.27056884765625, 849.5693359375), (472.76568603515625, 839.65478515625), (475.11395263671875, 834.5741577148438), (476.3153076171875, 831.3736572265625), (476.33843994140625, 831.3505249023438)], 0.033000)
        post_action(0.966706)
        perform_swipe_event([(393.45355224609375, 1121.1241455078125), (391.97076416015625, 1106.2872314453125), (394.8654479980469, 1080.0869140625), (401.1057434082031, 1048.866455078125), (410.5662841796875, 1018.578857421875), (418.59881591796875, 987.1146850585938), (427.09130859375, 962.19482421875), (433.51666259765625, 944.905517578125), (435.3952941894531, 936.1365966796875), (437.06976318359375, 934.2700805664062), (437.39251708984375, 932.0863647460938), (438.694580078125, 929.9695434570312), (439.2958679199219, 928.3687133789062), (440.5650939941406, 926.0995483398438)], 0.033000)
        post_action(0.469788)
        perform_swipe_event([(393.45355224609375, 1122.123291015625), (398.8534240722656, 1061.923583984375), (409.8014831542969, 1025.210693359375), (420.9154052734375, 994.7228393554688), (432.9479675292969, 956.6048583984375), (445.99029541015625, 912.055908203125), (456.21038818359375, 882.0679321289062), (468.8403015136719, 844.6115112304688), (482.6689147949219, 809.6863403320312), (500.07415771484375, 765.9633178710938), (510.4798278808594, 735.3345947265625), (518.7794799804688, 714.94140625), (526.7401123046875, 698.510986328125), (538.6236572265625, 676.9563598632812), (550.30078125, 657.6082153320312), (557.5447387695312, 644.96435546875), (561.2205810546875, 638.0015258789062), (562.2191772460938, 634.642822265625), (563.2994384765625, 633.5050659179688), (563.2177734375, 633.5050659179688), (563.2177734375, 632.5950317382812), (561.8565673828125, 632.505859375), (562.2191772460938, 632.505859375)], 0.033000)
        post_action(1.277585)
        perform_swipe_event([(445.3814392089844, 882.3106689453125), (448.1236267089844, 866.5335083007812), (454.15264892578125, 844.9896240234375), (461.5731201171875, 824.1183471679688), (466.6907043457031, 803.3557739257812), (474.2579650878906, 783.5546264648438), (482.82940673828125, 757.4082641601562), (491.4662170410156, 736.33984375), (500.0591125488281, 714.18115234375), (507.1233215332031, 694.97412109375), (515.6375732421875, 677.7630004882812), (523.5281982421875, 658.5565185546875), (529.0343017578125, 646.54638671875), (533.3406372070312, 638.3385620117188), (536.6599731445312, 632.6951293945312), (537.2538452148438, 630.0077514648438), (538.25244140625, 628.2957153320312), (539.54541015625, 628.5089721679688), (539.2510375976562, 628.5089721679688)], 0.033000)
        post_action(0.344116)
        perform_swipe_event([(348.5159606933594, 1104.137451171875), (349.73223876953125, 1097.2410888671875), (363.227294921875, 1027.7392578125), (382.16015625, 950.5701293945312), (398.959716796875, 888.9077758789062), (415.4808654785156, 840.9337158203125), (428.1702575683594, 804.4296875), (437.984619140625, 779.6122436523438), (449.539794921875, 745.9904174804688), (460.071044921875, 718.3347778320312), (467.3509521484375, 694.95703125), (478.0516357421875, 669.6878051757812), (483.8734436035156, 653.307861328125), (491.94537353515625, 636.2456665039062), (499.7843017578125, 621.5574951171875), (504.29962158203125, 607.5253295898438), (511.2507629394531, 596.5991821289062), (516.6716918945312, 585.8934936523438), (520.6888427734375, 576.1378173828125), (523.2299194335938, 570.5975952148438), (525.688232421875, 565.7213134765625), (527.2677001953125, 562.772705078125), (528.2662963867188, 559.56494140625), (529.264892578125, 556.0655517578125), (531.0632934570312, 551.967041015625), (532.2607421875, 548.0390014648438), (534.8804931640625, 544.3279418945312), (536.1139526367188, 540.718994140625), (537.7073974609375, 538.1254272460938), (538.25244140625, 535.9580688476562), (539.2510375976562, 533.4768676757812), (538.25244140625, 534.5823364257812), (536.9320068359375, 536.90283203125), (530.4083862304688, 549.3291015625), (523.5303344726562, 568.7833862304688), (515.2843017578125, 591.537841796875), (503.8763122558594, 623.6995849609375), (495.4863586425781, 650.9678955078125), (482.393798828125, 683.91259765625), (475.15179443359375, 706.0132446289062), (469.3567810058594, 722.9048461914062), (466.46588134765625, 730.2020263671875), (464.8544006347656, 733.427001953125), (465.35369873046875, 733.427001953125), (465.35369873046875, 732.4277954101562), (465.35369873046875, 728.7705078125), (468.0483093261719, 721.6427001953125), (471.25238037109375, 710.91015625), (474.84051513671875, 695.4566650390625), (480.7164306640625, 677.2424926757812), (489.00042724609375, 654.959228515625), (497.2844543457031, 631.5687866210938), (507.3750915527344, 599.29248046875), (519.9528198242188, 563.869384765625), (528.2359008789062, 537.8529663085938), (537.3072509765625, 515.503662109375), (543.2362670898438, 503.9549865722656), (546.2413330078125, 495.61279296875), (548.4025268554688, 489.2894287109375), (551.234375, 486.61981201171875), (551.2344360351562, 487.6190490722656)], 0.033000)
        post_action(0.322649)
        perform_swipe_event([(387.46185302734375, 1075.1600341796875), (394.3540344238281, 1027.7867431640625), (404.9560241699219, 971.35986328125), (417.5100402832031, 922.2831420898438), (432.083984375, 877.7251586914062), (443.4666442871094, 842.0531616210938), (454.26898193359375, 809.3080444335938), (470.6857604980469, 755.62841796875), (488.616455078125, 705.600341796875), (510.15985107421875, 649.3710327148438), (525.4815063476562, 611.7567138671875), (541.53662109375, 578.9701538085938), (552.2330322265625, 556.0655517578125), (557.0838623046875, 545.0013427734375), (560.5536499023438, 538.91455078125), (561.7198486328125, 538.5792236328125), (561.2205200195312, 538.5792236328125)], 0.033000)
        post_action(0.466618)
        perform_swipe_event([(409.4313659667969, 1017.205322265625), (419.3858337402344, 959.7896118164062), (442.6004638671875, 877.6688232421875), (460.7793884277344, 817.2083740234375), (476.8139953613281, 774.0523681640625), (486.3295593261719, 748.9024658203125), (492.24664306640625, 734.2556762695312), (496.2565002441406, 721.6533203125), (498.30792236328125, 714.708251953125), (499.3065185546875, 712.9429931640625), (500.3051452636719, 712.4434204101562)], 0.033000)
        post_action(0.399623)
        perform_swipe_event([(705.0208129882812, 791.3817138671875), (665.3693237304688, 789.38330078125), (616.8442993164062, 791.8013305664062), (394.9837341308594, 824.8023681640625), (370.85137939453125, 828.3121337890625), (346.85467529296875, 831.8828125), (281.99993896484375, 839.6048583984375), (263.52655029296875, 840.9814453125), (248.7893524169922, 843.1994018554688), (239.86785888671875, 844.4544067382812), (221.69210815429688, 845.339599609375), (205.8426055908203, 847.3197021484375), (189.05938720703125, 848.3372192382812), (178.42962646484375, 850.8099365234375), (156.9801025390625, 854.0885009765625), (146.9244384765625, 856.2988891601562), (132.5338897705078, 858.7854614257812), (127.91251373291016, 859.7103881835938), (116.90560913085938, 859.3286743164062), (112.9076156616211, 859.3286743164062), (102.85714721679688, 859.3286743164062), (100.3606185913086, 859.3286743164062), (94.72488403320312, 860.327880859375), (93.65504455566406, 860.327880859375), (91.37309265136719, 860.327880859375), (91.87239837646484, 860.327880859375)], 0.033000)
        post_action(0.430435)
        perform_click_event("Tap", 418.418884, 582.544861, 0.084000, "Activity")
        post_action(1.383214)
        perform_swipe_event([(701.0263671875, 563.5596923828125), (670.7034301757812, 566.78466796875), (637.47509765625, 574.1627197265625), (598.8119506835938, 583.0933227539062), (551.1491088867188, 599.3117065429688), (505.0331726074219, 614.8314208984375), (432.1636657714844, 637.0449829101562), (387.22216796875, 646.4371948242188), (365.9916687011719, 648.4933471679688), (345.3578186035156, 651.9747314453125), (310.40728759765625, 659.1173706054688), (276.11651611328125, 665.979736328125), (228.18785095214844, 680.34228515625), (161.2972412109375, 690.6694946289062), (117.49356842041016, 695.3465576171875), (84.16502380371094, 697.5269165039062), (73.72891235351562, 697.4551391601562), (46.934814453125, 702.4512329101562)], 0.033000)
        post_action(0.211165)
        perform_click_event("Tap", 417.420258, 806.369995, 0.055000, "Activity")
        post_action(1.130096)
        perform_click_event("Tap", 54.923717, 108.914909, 0.085000, "Activity")
        post_action(1.252256)
        perform_swipe_event([(443.3841857910156, 899.2974243164062), (450.6715393066406, 848.24658203125), (457.1014709472656, 824.901123046875), (463.02203369140625, 800.8812255859375), (468.7187194824219, 784.6475219726562), (474.84051513671875, 770.8977661132812), (482.43994140625, 749.7543334960938), (485.7582092285156, 739.6907348632812), (489.04046630859375, 733.2681274414062), (491.317626953125, 727.8864135742188), (492.709716796875, 725.64501953125), (493.1994323730469, 724.5494995117188), (493.3148498535156, 723.4533081054688), (493.3148498535156, 723.434814453125), (494.3134765625, 722.4356079101562), (494.3134765625, 721.4364013671875)], 0.033000)
        post_action(1.024853)
        perform_click_event("Tap", 505.298218, 748.415283, 0.081000, "Activity")
        post_action(1.528805)
        perform_swipe_event([(478.3356628417969, 960.2498168945312), (479.3342590332031, 935.2693481445312), (481.9390563964844, 910.8128662109375), (486.01708984375, 890.689697265625), (492.31622314453125, 856.3309936523438), (498.1587829589844, 836.0189208984375), (502.3963623046875, 818.607421875), (508.615966796875, 798.0870361328125), (514.15771484375, 778.9042358398438), (520.0562133789062, 758.2935791015625), (524.7711181640625, 740.421630859375), (530.203125, 723.6766967773438), (535.256591796875, 708.946044921875), (539.7915649414062, 697.6019287109375), (542.4689331054688, 687.5733032226562), (545.2427368164062, 682.263427734375), (546.2413330078125, 677.78466796875), (547.2399291992188, 674.0405883789062), (548.7379150390625, 674.4730834960938), (548.2385864257812, 673.473876953125)], 0.034000)
        post_action(0.520643)
        perform_swipe_event([(380.4715881347656, 1110.1326904296875), (386.4318542480469, 1082.248779296875), (410.4856262207031, 1007.65673828125), (422.8976745605469, 972.663818359375), (434.5931091308594, 942.1525268554688), (445.5647277832031, 911.0843505859375), (453.87542724609375, 888.041748046875), (460.85992431640625, 869.3209228515625), (464.32501220703125, 858.44970703125), (468.6048278808594, 848.8255004882812), (472.0489807128906, 840.2297973632812), (474.3220520019531, 835.3858032226562), (475.7897033691406, 832.8987426757812), (477.3370361328125, 831.3505249023438)], 0.033000)
        post_action(0.302753)
        perform_click_event("Tap", 629.126221, 575.550354, 0.099000, "Activity")
        post_action(1.070039)
        perform_swipe_event([(402.4410705566406, 1022.201416015625), (405.53802490234375, 1000.5093383789062), (420.3486022949219, 945.3047485351562), (440.1511535644531, 889.6785278320312), (454.92694091796875, 843.7611083984375), (470.5773010253906, 802.16796875), (484.532958984375, 769.5850219726562), (500.804443359375, 733.427001953125), (512.3148193359375, 708.3873901367188), (520.7703247070312, 692.3074340820312), (526.770751953125, 680.7123413085938), (529.2791748046875, 673.4310913085938), (530.2635498046875, 671.4754028320312), (531.1095581054688, 670.4761962890625), (531.2621459960938, 670.4761962890625), (531.2621459960938, 668.9774169921875), (532.2607421875, 669.4769897460938), (532.2607421875, 668.4777221679688)], 0.033000)
        post_action(0.586014)
        perform_swipe_event([(672.0665893554688, 462.6385498046875), (659.0845947265625, 481.62371826171875), (645.98193359375, 515.95947265625), (639.08251953125, 539.0117797851562), (632.621337890625, 559.063232421875), (627.82861328125, 583.7415161132812), (623.6286010742188, 601.5510864257812), (622.3070678710938, 616.6613159179688), (620.0347900390625, 626.926513671875), (619.1400756835938, 636.502685546875), (619.1400756835938, 638.4140625), (618.1414794921875, 638.5011596679688)], 0.033000)
        post_action(0.204526)
        perform_click_event("Tap", 637.115112, 427.665894, 0.067000, "Activity")
        post_action(0.667781)
        perform_swipe_event([(455.3675537109375, 982.2326049804688), (458.8660888671875, 945.9888916015625), (464.8543701171875, 908.7900390625), (475.77044677734375, 868.7041625976562), (482.95684814453125, 841.6227416992188), (493.589111328125, 815.1765747070312), (499.61224365234375, 799.660888671875), (502.80169677734375, 782.8883056640625), (511.10699462890625, 763.8916015625), (516.474365234375, 747.6492309570312), (522.6079711914062, 733.4255981445312), (526.126953125, 724.6473999023438), (530.0189208984375, 717.3069458007812), (531.0134887695312, 712.9409790039062), (532.2363891601562, 712.4434204101562), (532.2607421875, 710.9445190429688), (534.2579956054688, 709.4457397460938)], 0.033000)
        post_action(1.588490)
        perform_swipe_event([(427.4064025878906, 916.2841796875), (424.8202819824219, 895.5828857421875), (432.9595947265625, 862.8017578125), (449.8794860839844, 795.3648071289062), (469.36810302734375, 737.3789672851562), (494.3121337890625, 679.1088256835938), (521.38818359375, 614.3250122070312), (538.1040649414062, 576.8464965820312), (543.2454833984375, 561.0616455078125), (550.5363159179688, 545.44775390625), (559.3685913085938, 529.8677978515625), (564.1620483398438, 518.3524169921875), (569.85205078125, 510.07684326171875), (574.1756591796875, 501.14886474609375), (576.8552856445312, 496.29937744140625), (578.319091796875, 492.492919921875), (579.6781005859375, 491.1330871582031), (579.195556640625, 491.6159362792969)], 0.033000)
        post_action(0.410855)
        perform_swipe_event([(388.4604797363281, 247.806396484375), (384.46221923828125, 309.8382263183594), (379.8087158203125, 367.01080322265625), (377.8271484375, 415.3411560058594), (376.47711181640625, 455.0200500488281), (375.478515625, 473.7424011230469), (375.478515625, 484.0519714355469), (376.62261962890625, 494.3423767089844), (376.47711181640625, 503.6065673828125), (377.4757385253906, 505.60498046875)], 0.033000)
        post_action(0.841904)
        perform_click_event("Tap", 56.920944, 105.917252, 0.124000, "Activity")
        post_action(3.552559)
        perform_swipe_event([(520.2774047851562, 498.6104736328125), (517.3330078125, 521.1978149414062), (515.2843627929688, 564.65771484375), (515.2843627929688, 580.2954711914062), (515.2843627929688, 617.72900390625), (516.282958984375, 644.5698852539062), (517.2815551757812, 667.1369018554688), (517.2815551757812, 684.2625732421875), (518.2801513671875, 694.2439575195312), (518.2801513671875, 699.0509643554688), (518.2801513671875, 705.5226440429688), (517.2815551757812, 707.1712646484375), (517.2815551757812, 706.4480590820312)], 0.033000)
        post_action(0.282673)
        perform_click_event("Tap", 672.066589, 573.551941, 0.099000, "Activity")
        post_action(0.609472)
        record_popup_window()
        post_action(4.397668)
        perform_click_event("Tap", 578.196960, 561.561279, 0.124000, "None")
        post_action(0.077322)
        close_popup_window()
        post_action(1.713945)
        perform_click_event("Tap", 368.488220, 1164.090576, 0.080000, "Dialog")
        post_action(2.032959)
        perform_swipe_event([(433.3980712890625, 925.277099609375), (428.4049987792969, 898.2982177734375), (433.3980712890625, 868.3216552734375), (435.395263671875, 856.83056640625), (441.4490966796875, 831.0396118164062), (446.1305847167969, 819.4843139648438), (451.3628845214844, 797.922607421875), (457.69903564453125, 779.1654052734375), (460.3606262207031, 762.167724609375), (465.1998596191406, 749.8762817382812), (468.3904724121094, 736.2608032226562), (470.70648193359375, 726.351806640625), (471.3453674316406, 719.9376220703125), (474.5149230957031, 715.0933837890625), (477.0309143066406, 710.7512817382812), (479.2458801269531, 709.4457397460938), (479.3342590332031, 709.4457397460938)], 0.033000)
        post_action(0.616777)
        perform_click_event("Tap", 662.080444, 737.423889, 0.099000, "Activity")
        post_action(0.041083)
        record_popup_window()
        post_action(1.046307)
        perform_click_event("Tap", 570.208069, 740.421570, 0.080000, "None")
        post_action(0.095684)
        close_popup_window()
        post_action(1.449558)
        perform_click_event("Tap", 420.416107, 1150.101440, 0.112000, "Dialog")
        post_action(1.185139)
        perform_swipe_event([(529.264892578125, 300.7650146484375), (530.1251831054688, 325.7283630371094), (529.8043823242188, 372.4455261230469), (526.3071899414062, 435.1455383300781), (522.3300170898438, 475.0743713378906), (513.413818359375, 543.3130493164062), (500.3529052734375, 631.0126953125), (497.3290100097656, 655.3300170898438), (494.812744140625, 708.446533203125), (493.51446533203125, 738.224609375), (493.3148498535156, 750.5903930664062), (490.0804138183594, 772.7855224609375), (487.50390625, 795.7495727539062), (487.32318115234375, 805.1651000976562), (484.8450622558594, 822.7281494140625), (483.8280029296875, 828.352783203125), (482.35675048828125, 837.29248046875), (481.2036437988281, 841.4706420898438), (480.6355285644531, 844.34033203125), (480.3328857421875, 845.339599609375)], 0.033000)
        post_action(0.274782)
        perform_swipe_event([(517.2815551757812, 319.75018310546875), (509.3132019042969, 382.5672912597656), (481.2957763671875, 507.7718505859375), (469.1884460449219, 584.9344482421875), (459.1284484863281, 645.3245849609375), (448.45654296875, 701.9752197265625), (446.3800354003906, 748.9149169921875), (447.378662109375, 774.5580444335938), (448.37725830078125, 787.514404296875), (448.37725830078125, 794.9403076171875), (448.37725830078125, 802.8290405273438), (449.86297607421875, 809.34326171875), (450.3744812011719, 811.3660888671875)], 0.033000)
        post_action(0.321387)
        perform_swipe_event([(488.32177734375, 331.7408142089844), (481.166259765625, 370.6959228515625), (470.3403015136719, 413.4544677734375), (464.2933654785156, 447.9795227050781), (459.4507141113281, 487.3642272949219), (456.314208984375, 506.0728454589844), (451.34710693359375, 549.791748046875), (446.7523498535156, 587.5584106445312), (442.38555908203125, 617.0179443359375), (438.1201477050781, 649.9846801757812), (435.15118408203125, 673.9180908203125), (431.5626220703125, 695.3228149414062), (429.2825012207031, 713.4129028320312), (426.9071044921875, 732.4277954101562), (425.468017578125, 750.9417724609375), (424.3299255371094, 763.7262573242188), (421.04107666015625, 779.2008666992188), (419.4793701171875, 792.0712890625), (418.41888427734375, 800.635986328125), (416.421630859375, 808.53076171875), (415.42303466796875, 816.2994384765625), (413.88427734375, 828.5162963867188), (412.6436767578125, 837.6951904296875), (411.4285888671875, 847.3599243164062), (410.4299621582031, 852.5679321289062), (410.4299621582031, 856.3309936523438), (410.4299621582031, 857.3302001953125)], 0.033000)
        post_action(0.224157)
        perform_swipe_event([(507.2954406738281, 279.78143310546875), (498.0570983886719, 324.002685546875), (484.54071044921875, 375.4028015136719), (469.8474426269531, 436.15924072265625), (452.9546813964844, 530.083251953125), (446.03631591796875, 572.6342163085938), (441.5066833496094, 604.6883544921875), (439.00982666015625, 635.4493408203125), (436.6500244140625, 654.6931762695312), (434.44659423828125, 669.1771850585938), (431.900146484375, 689.4613647460938), (429.6795959472656, 709.9581298828125), (425.9665832519531, 729.1975708007812), (421.2911071777344, 742.7910766601562), (419.6032409667969, 756.4789428710938), (417.0257263183594, 765.1923828125), (415.9836120605469, 770.2754516601562), (415.42303466796875, 776.5838623046875), (415.42303466796875, 780.1287841796875), (413.92510986328125, 780.889892578125), (414.4244079589844, 781.3895263671875), (414.4244079589844, 779.504638671875), (414.4244079589844, 772.865478515625), (414.4244079589844, 762.9039916992188), (416.4303894042969, 741.3330078125), (420.7046813964844, 718.8489990234375), (426.5534973144531, 687.8789672851562), (434.3578186035156, 658.6409912109375), (439.6416931152344, 640.116943359375), (447.8369445800781, 617.14111328125), (452.5365295410156, 604.406494140625), (460.2641296386719, 586.73486328125), (465.8529968261719, 570.5543212890625), (467.50677490234375, 564.0910034179688), (473.4788513183594, 549.1615600585938), (478.7248840332031, 537.4108276367188), (480.8855895996094, 529.2656860351562), (485.7044982910156, 516.8380737304688), (489.3896484375, 509.46331787109375), (496.6796569824219, 492.4198303222656), (502.138671875, 480.2804260253906), (507.30718994140625, 469.6037292480469), (512.2885131835938, 459.6408996582031), (515.8958740234375, 453.0336608886719), (518.5534057617188, 449.101806640625), (519.8943481445312, 446.0351257324219), (520.2774047851562, 443.7998962402344), (521.3809204101562, 443.65338134765625), (521.2760009765625, 442.6541748046875), (521.2760009765625, 443.5733947753906), (521.2760009765625, 443.65338134765625)], 0.033000)
        post_action(1.177676)
        perform_click_event("Tap", 399.445221, 1240.031250, 0.072000, "Activity")
        post_action(1.016848)
        perform_click_event("Tap", 479.334259, 273.786102, 0.080000, "Activity")
        post_action(0.000000)




    except Exception as e:

        print(e)

        traceback_str = ''.join(traceback.format_tb(e.__traceback__))

        print(traceback_str)

    os.system("adb shell am force-stop " + package_name)
    