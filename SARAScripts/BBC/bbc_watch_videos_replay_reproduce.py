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


        perform_click_event("Tap", 296.588074, 216.830597, 0.155000, "Activity")
        post_action(1.770675)
        perform_click_event("Tap", 329.542297, 602.529297, 0.111000, "Activity")
        post_action(5.388512)
        perform_click_event("Tap", 57.919556, 488.618256, 0.112000, "Activity")
        post_action(12.138586)
        perform_swipe_event([(715.0069580078125, 781.3895263671875), (695.03466796875, 784.38720703125), (661.0819091796875, 791.3817138671875), (631.4239501953125, 798.3011474609375), (616.381103515625, 800.6456909179688), (586.2994995117188, 806.275634765625), (554.4046020507812, 811.8773193359375), (518.4669189453125, 818.002685546875), (491.24237060546875, 823.1377563476562), (461.47369384765625, 827.3421630859375), (436.816162109375, 832.0004272460938), (416.23651123046875, 834.5173950195312), (384.6105651855469, 840.037353515625), (367.1437072753906, 843.8822021484375), (344.9555969238281, 847.8506469726562), (323.54718017578125, 851.39794921875), (280.306396484375, 859.0611572265625), (258.3968505859375, 861.70849609375), (224.68792724609375, 864.8244018554688), (210.57276916503906, 867.0360717773438), (189.385986328125, 869.5137329101562), (180.1890869140625, 870.4933471679688), (155.90386962890625, 874.8453369140625), (146.38868713378906, 876.9610595703125), (127.08641815185547, 881.0936889648438), (117.88265991210938, 883.2982788085938), (101.90644836425781, 886.1766357421875), (85.47577667236328, 888.356689453125), (68.904296875, 890.8040771484375), (57.40937805175781, 893.179931640625), (47.227561950683594, 894.3013305664062), (37.789894104003906, 896.0191650390625), (30.15745735168457, 896.2997436523438), (27.527036666870117, 896.2997436523438), (22.96809959411621, 896.2997436523438), (22.483806610107422, 896.2997436523438), (20.970874786376953, 896.2997436523438)], 0.033000)
        post_action(1.015716)
        perform_click_event("Tap", 54.923717, 506.604218, 0.085000, "Activity")
        post_action(1.247771)
        perform_swipe_event([(193.73092651367188, 1126.1202392578125), (188.99436950683594, 1091.073974609375), (183.63206481933594, 1056.572509765625), (175.256591796875, 1023.7002563476562), (168.20433044433594, 1000.5321655273438), (160.84481811523438, 983.0578002929688), (156.4355010986328, 971.8726196289062), (153.98838806152344, 962.6524047851562), (151.28988647460938, 956.2529296875), (150.291259765625, 952.7557373046875), (147.80772399902344, 948.28515625), (147.79473876953125, 947.11474609375), (147.79473876953125, 947.2599487304688), (147.79473876953125, 946.2607421875), (146.79612731933594, 946.2607421875), (146.79612731933594, 945.2615356445312), (145.29818725585938, 943.7626342773438), (145.79750061035156, 943.2630615234375), (144.29959106445312, 943.2630615234375), (144.79888916015625, 942.2638549804688), (143.80027770996094, 942.2638549804688), (143.80027770996094, 940.7650146484375), (143.80027770996094, 940.2654418945312), (142.80166625976562, 940.2654418945312), (142.80166625976562, 939.2661743164062), (141.96820068359375, 938.2669677734375), (141.30374145507812, 938.2669677734375), (141.8030548095703, 937.2677612304688), (140.72586059570312, 936.2685546875), (140.804443359375, 935.2693481445312), (139.5989990234375, 934.2700805664062), (139.8058319091797, 934.2700805664062), (138.80722045898438, 934.2700805664062)], 0.033000)
        post_action(1.922949)
        perform_swipe_event([(183.7447967529297, 1092.146728515625), (176.34239196777344, 1055.1121826171875), (169.29930114746094, 1029.1556396484375), (164.5568084716797, 1008.3536376953125), (158.28018188476562, 991.2255859375), (152.07955932617188, 969.8965454101562), (142.88389587402344, 940.5945434570312), (138.39854431152344, 926.3439331054688), (135.97598266601562, 917.85986328125), (133.0647735595703, 904.4173583984375), (129.31765747070312, 891.546630859375), (126.8629150390625, 882.4669799804688), (124.32731628417969, 874.8165283203125), (122.09938049316406, 868.859130859375), (120.83218383789062, 865.0999145507812), (119.26089477539062, 860.7540893554688), (117.83634185791016, 858.6824951171875), (116.43170166015625, 855.9247436523438), (116.83773040771484, 856.3309936523438), (116.83773040771484, 854.3325805664062), (115.76778411865234, 854.3325805664062), (115.839111328125, 852.8336791992188), (115.14625549316406, 852.6400756835938), (114.84049987792969, 851.1160278320312), (114.84049987792969, 851.3348999023438), (114.84049987792969, 849.8360595703125), (113.84188842773438, 849.33642578125), (112.84327697753906, 847.837646484375)], 0.033000)
        post_action(1.248477)
        perform_swipe_event([(131.81692504882812, 952.2560424804688), (127.82247161865234, 930.273193359375), (123.24351501464844, 908.2418212890625), (119.93824005126953, 888.1446533203125), (116.47042083740234, 872.0313720703125), (113.16675567626953, 852.9533081054688), (110.69947052001953, 842.7544555664062), (108.39112854003906, 834.9727172851562), (107.11286163330078, 830.8740844726562), (105.85298156738281, 827.0733032226562), (105.85298156738281, 824.01220703125), (105.85298156738281, 824.35595703125), (104.8543701171875, 824.35595703125), (103.85575866699219, 824.35595703125)], 0.033000)
        post_action(1.322766)
        perform_swipe_event([(127.82247161865234, 937.2677612304688), (118.33564758300781, 893.3021240234375), (112.73330688476562, 859.0748901367188), (105.3413314819336, 816.458740234375), (102.40404510498047, 802.1046752929688), (93.43621826171875, 766.0804443359375), (84.94430541992188, 737.6261596679688), (74.67160034179688, 706.6637573242188), (69.27517700195312, 689.946533203125), (61.86566925048828, 669.3802490234375), (59.274269104003906, 660.2322998046875), (56.42163848876953, 646.494873046875), (54.9237174987793, 636.0184326171875), (53.925106048583984, 627.41845703125), (51.927879333496094, 623.49267578125), (49.9306526184082, 618.7158813476562), (49.9306526184082, 616.1694946289062), (49.9306526184082, 611.022705078125), (49.9306526184082, 607.5029296875), (49.9306526184082, 604.1995239257812), (48.93204116821289, 601.77734375), (48.93204116821289, 601.0303955078125), (48.93204116821289, 599.15966796875), (46.934814453125, 599.5316162109375)], 0.033000)
        post_action(1.700583)
        perform_swipe_event([(65.90846252441406, 592.537109375), (74.89598083496094, 627.0101318359375), (82.57695007324219, 672.2787475585938), (85.31978607177734, 695.2779541015625), (89.9620132446289, 730.0383911132812), (90.91393280029297, 742.9421997070312), (93.37033081054688, 777.3927001953125), (95.69541931152344, 816.272216796875), (97.14395141601562, 861.62548828125), (96.24183654785156, 891.1731567382812), (95.01885986328125, 913.77783203125), (94.86824035644531, 938.0632934570312), (93.86962890625, 953.7487182617188), (93.86962890625, 964.5167846679688), (92.87101745605469, 970.9791259765625), (92.87101745605469, 973.7393188476562), (92.87101745605469, 974.1033325195312), (92.87101745605469, 975.5516357421875), (92.87101745605469, 976.2373046875)], 0.033000)
        post_action(0.595607)
        perform_swipe_event([(679.056884765625, 837.3458251953125), (655.0308227539062, 836.4554443359375), (614.3780517578125, 831.1968994140625), (557.7254638671875, 818.8602905273438), (515.4850463867188, 819.23046875), (468.30560302734375, 823.0614013671875), (414.1889343261719, 824.35595703125), (360.9763488769531, 821.4867553710938), (308.5714111328125, 818.8602294921875), (270.2859802246094, 816.9102172851562), (228.10830688476562, 811.9451293945312), (191.4058074951172, 805.1500854492188), (159.4650115966797, 795.1463623046875), (124.6880111694336, 782.4122924804688), (95.6864242553711, 769.0278930664062), (70.35942077636719, 758.13623046875), (62.36421585083008, 754.1362915039062), (47.44395446777344, 743.8530883789062), (7.066636085510254, 702.4512329101562), (6.990291595458984, 700.3359985351562), (6.990291595458984, 699.4535522460938)], 0.033000)
        post_action(2.833157)
        perform_swipe_event([(169.76422119140625, 1047.181884765625), (163.77252197265625, 997.220947265625), (161.96353149414062, 973.1244506835938), (158.3810577392578, 944.8731079101562), (152.92173767089844, 915.2239379882812), (147.24014282226562, 893.080810546875), (140.64590454101562, 861.5331420898438), (133.81414794921875, 827.3536376953125), (129.10919189453125, 813.2301635742188), (120.00955200195312, 785.1212158203125), (114.1824722290039, 774.0773315429688), (106.80415344238281, 752.2697143554688), (103.2322769165039, 743.2958374023438), (99.69868469238281, 732.776123046875), (98.3723373413086, 727.4674682617188), (96.20952606201172, 724.7769165039062), (95.86685180664062, 723.4530639648438), (95.86685180664062, 723.434814453125), (95.86685180664062, 722.4356079101562), (94.86824035644531, 722.4356079101562), (94.86824035644531, 721.4364013671875), (94.1396255493164, 720.4371337890625), (93.37032318115234, 720.4371337890625), (93.86962890625, 720.4371337890625), (92.87101745605469, 720.4371337890625), (92.09017181396484, 720.4371337890625), (91.87239837646484, 720.4371337890625)], 0.031000)
        post_action(0.969410)
        perform_swipe_event([(201.71983337402344, 1049.1802978515625), (195.87310791015625, 1002.3780517578125), (195.63194274902344, 994.4522094726562), (188.8124542236328, 953.67822265625), (185.8284912109375, 936.7587280273438), (176.63909912109375, 894.7808837890625), (167.63267517089844, 855.2265625), (156.71034240722656, 807.0094604492188), (155.2922821044922, 789.9546508789062), (149.2750244140625, 747.3101806640625), (97.11552429199219, 508.8533935546875), (94.4554443359375, 492.13531494140625), (89.95475769042969, 475.8673095703125), (87.37864685058594, 471.13189697265625), (85.19532775878906, 464.5780029296875), (81.80168914794922, 460.5555114746094), (75.40523529052734, 456.3168029785156), (69.41197967529297, 451.9011535644531), (64.85883331298828, 448.59844970703125), (62.437862396240234, 446.176025390625), (61.36942672729492, 445.1069030761719), (58.87009811401367, 443.60528564453125), (58.91817092895508, 443.65338134765625), (65.18017578125, 444.6526184082031), (67.93531799316406, 445.6814880371094), (69.95252227783203, 445.6518249511719), (72.39944458007812, 445.6518249511719), (73.8218002319336, 447.57464599609375), (73.89736938476562, 447.6502685546875), (74.89598083496094, 448.6495056152344), (74.89598083496094, 449.6487121582031), (76.33164978027344, 452.08447265625), (75.89459228515625, 452.6463623046875), (75.89459228515625, 454.7330322265625), (76.97154998779297, 455.722412109375), (76.89320373535156, 458.1420593261719), (76.89320373535156, 460.32489013671875), (76.89320373535156, 462.84381103515625), (75.3952865600586, 462.6385498046875), (74.89598083496094, 463.6377868652344), (75.79525756835938, 466.4366455078125), (75.89459228515625, 471.2801208496094), (76.89320373535156, 473.495849609375), (76.89320373535156, 476.2889404296875), (77.86931610107422, 478.5810241699219), (77.89181518554688, 480.7438659667969), (79.33454132080078, 480.62451171875), (78.89043426513672, 482.4776611328125), (78.89043426513672, 482.6229553222656), (78.89043426513672, 483.6221618652344), (78.89043426513672, 484.62139892578125), (78.89043426513672, 485.62060546875), (78.89043426513672, 487.9078369140625), (79.49678802490234, 495.04205322265625), (83.0963134765625, 507.1330871582031), (84.09722137451172, 516.2387084960938), (85.67768096923828, 527.7743530273438), (86.87933349609375, 537.8840942382812), (88.28079986572266, 543.1892700195312), (89.36590576171875, 547.5323486328125), (91.75020599365234, 564.5800170898438), (95.94452667236328, 584.9319458007812), (101.59772491455078, 608.1324462890625), (113.84188842773438, 651.9906616210938), (120.97998046875, 680.0607299804688), (131.96669006347656, 724.3214721679688), (134.58302307128906, 738.27294921875), (138.6525115966797, 766.8515625), (141.94142150878906, 790.62939453125), (144.7239532470703, 805.4579467773438), (147.07533264160156, 825.7528686523438), (148.7623748779297, 837.097900390625), (152.02183532714844, 854.1480712890625), (153.22970581054688, 863.4231567382812), (155.78363037109375, 877.70556640625), (156.73643493652344, 884.0798950195312), (159.35853576660156, 889.46484375), (161.13731384277344, 897.7430419921875), (163.32748413085938, 903.4028930664062), (164.73138427734375, 908.1312866210938), (168.2938690185547, 916.3392944335938), (169.26492309570312, 921.2802734375), (172.52572631835938, 931.099365234375), (174.94488525390625, 936.6439819335938), (175.9854736328125, 942.4131469726562), (180.74896240234375, 953.7548828125), (185.38401794433594, 965.1704711914062), (186.8036346435547, 971.5563354492188), (190.23577880859375, 983.7314453125), (192.88186645507812, 988.6768798828125), (196.78585815429688, 1005.6284790039062), (199.89892578125, 1011.5628051757812), (204.7156982421875, 1027.197509765625), (208.07614135742188, 1035.2864990234375), (214.11582946777344, 1052.623779296875), (217.69415283203125, 1059.16552734375), (216.69903564453125, 1064.9183349609375), (221.5853271484375, 1080.6212158203125), (223.5131378173828, 1087.5328369140625), (224.8592987060547, 1095.173828125), (229.68099975585938, 1108.6339111328125), (233.67445373535156, 1120.122802734375), (234.82420349121094, 1123.5732421875), (237.13351440429688, 1130.50537109375), (236.67129516601562, 1132.115478515625), (237.62240600585938, 1133.0672607421875), (237.66990661621094, 1134.3963623046875), (239.01913452148438, 1136.4632568359375), (238.66851806640625, 1137.8743896484375), (239.66712951660156, 1139.110107421875)], 0.033000)
        post_action(0.684945)
        perform_swipe_event([(159.77809143066406, 629.5081787109375), (165.44151306152344, 673.4264526367188), (173.69337463378906, 702.61572265625), (182.6732635498047, 739.1304321289062), (193.73092651367188, 778.8914794921875), (200.0859375, 808.6115112304688), (206.39923095703125, 834.8626708984375), (209.708740234375, 849.8360595703125), (211.55767822265625, 862.5836791992188), (214.14601135253906, 876.5322875976562), (216.31558227539062, 886.1557006835938), (216.69903564453125, 891.0601196289062), (217.80499267578125, 894.62353515625), (219.123291015625, 899.15283203125)], 0.033000)
        post_action(0.382403)
        perform_click_event("Tap", 78.890434, 503.606567, 0.069000, "Activity")
        post_action(0.237388)
        perform_swipe_event([(181.74757385253906, 818.3606567382812), (189.73648071289062, 856.3309936523438), (193.4976806640625, 873.3834228515625), (198.11581420898438, 897.64453125), (201.7217559814453, 909.2992553710938), (202.71844482421875, 917.5178833007812), (203.71707153320312, 923.7783203125), (205.71429443359375, 929.5440673828125), (206.71290588378906, 935.5598754882812), (206.71290588378906, 939.0191650390625), (206.71290588378906, 942.763427734375), (206.71290588378906, 945.2615356445312)], 0.033000)
        post_action(17.798632)
        perform_swipe_event([(575.2011108398438, 881.3114624023438), (547.6682739257812, 878.0055541992188), (532.2725830078125, 874.4630737304688), (511.9100341796875, 870.8438720703125), (485.0709228515625, 866.73095703125), (472.751220703125, 865.9060668945312), (443.3365478515625, 858.7832641601562), (416.52471923828125, 853.35205078125), (402.23089599609375, 852.04248046875), (378.9736633300781, 852.3341064453125), (361.5186767578125, 851.2125854492188), (353.6611328125, 851.3348999023438), (330.88189697265625, 847.1275024414062), (305.2867126464844, 843.6260375976562), (290.22796630859375, 840.0015258789062), (259.14007568359375, 833.8486328125), (244.89230346679688, 830.8458862304688), (214.55665588378906, 821.97607421875), (202.4095458984375, 819.0327758789062), (175.66151428222656, 812.0112915039062), (156.2165985107422, 805.5332641601562), (135.6385040283203, 800.5812377929688), (122.17839813232422, 796.8268432617188), (109.9993667602539, 791.4425048828125), (102.359619140625, 787.6355590820312), (90.37448120117188, 783.3880004882812), (80.50579833984375, 778.3162841796875), (65.40794372558594, 769.3981323242188), (56.09011459350586, 763.1824340820312), (50.80801773071289, 760.757080078125), (39.364501953125, 756.1769409179688), (35.577030181884766, 753.4956665039062), (27.41748809814453, 749.7781372070312), (22.83597183227539, 747.2838745117188), (22.96809959411621, 747.4160766601562), (19.567031860351562, 745.7145385742188), (18.22563934326172, 744.669189453125), (15.350093841552734, 743.1051635742188), (15.977808952331543, 741.9873046875), (11.983356475830078, 740.5960083007812), (10.979304313659668, 740.4215698242188), (8.349027633666992, 739.1028442382812), (7.832400798797607, 737.84521484375), (6.990291595458984, 737.4238891601562)], 0.033000)
        post_action(2.017070)
        perform_swipe_event([(208.7101287841797, 1085.1522216796875), (200.82821655273438, 1056.9854736328125), (195.0269775390625, 1021.754638671875), (180.54222106933594, 960.62841796875), (166.1411895751953, 912.9645385742188), (153.34512329101562, 876.7683715820312), (144.62783813476562, 849.7366943359375), (140.9534454345703, 835.2205200195312), (136.39715576171875, 818.706787109375), (129.0605926513672, 796.0975952148438), (125.75633239746094, 786.1787719726562), (119.37415313720703, 765.8314208984375), (114.97109985351562, 751.8049926757812), (110.84605407714844, 738.9227294921875), (110.30460357666016, 735.798583984375), (107.82788848876953, 729.3854370117188), (106.68003845214844, 727.08837890625), (105.85298156738281, 723.9400024414062), (105.13151550292969, 723.434814453125), (104.8543701171875, 721.4505615234375), (104.8543701171875, 720.936767578125), (103.85575866699219, 719.6669311523438), (101.87915802001953, 718.438720703125), (101.85853576660156, 718.438720703125)], 0.033000)
        post_action(0.869406)
        perform_swipe_event([(81.88626861572266, 613.5206909179688), (87.5709228515625, 647.6104736328125), (92.51143646240234, 670.995361328125), (95.77592468261719, 701.3594970703125), (99.25483703613281, 726.788330078125), (106.35228729248047, 758.407470703125), (112.87010192871094, 786.5198364257812), (115.98918914794922, 804.57373046875), (117.83241271972656, 812.3574829101562), (120.59489440917969, 822.1696166992188), (124.50111389160156, 837.367919921875), (125.27159118652344, 841.1251220703125), (129.4834442138672, 853.65966796875), (131.82513427734375, 861.343505859375), (132.81553649902344, 868.3215942382812), (134.4487762451172, 870.5908813476562), (135.96209716796875, 873.4685668945312), (135.81137084960938, 874.5728759765625)], 0.033000)
        post_action(0.422320)
        perform_click_event("Tap", 51.927879, 438.657288, 0.099000, "Activity")
        post_action(0.206183)
        perform_swipe_event([(112.84327697753906, 830.3512573242188), (116.83773040771484, 854.3325805664062), (119.83356475830078, 864.3247680664062), (120.83218383789062, 872.3184814453125), (123.62480163574219, 886.8826293945312), (124.82662963867188, 895.2675170898438), (127.32316589355469, 905.292724609375), (127.82247161865234, 911.6373291015625), (128.8210906982422, 919.0032958984375), (130.41517639160156, 924.4703369140625), (130.8183135986328, 928.9547729492188), (130.8183135986328, 934.0911865234375), (131.81692504882812, 935.718994140625), (131.81692504882812, 939.3367919921875), (131.81692504882812, 941.637451171875), (132.81553649902344, 942.763427734375), (131.81692504882812, 945.2615356445312)], 0.033000)
        post_action(2.970911)
        perform_click_event("Tap", 94.868240, 329.742401, 0.099000, "Activity")
        post_action(2.132945)
        perform_click_event("Tap", 55.922333, 235.815765, 0.111000, "Activity")
        post_action(2.300319)
        perform_swipe_event([(646.1026611328125, 928.2747802734375), (614.52001953125, 921.8731689453125), (590.8125, 915.5746459960938), (567.7062377929688, 909.3335571289062), (551.2959594726562, 907.0567626953125), (526.553955078125, 903.3201904296875), (496.80999755859375, 898.2982177734375), (466.5767822265625, 891.994140625), (429.7030029296875, 885.568115234375), (397.447998046875, 883.8095703125), (368.50653076171875, 882.4658203125), (349.9738464355469, 880.1070556640625), (310.5087890625, 870.437255859375), (232.8308868408203, 844.100830078125), (179.695068359375, 828.7919311523438), (134.7962646484375, 820.3557739257812), (111.42909240722656, 815.5088500976562), (87.92984771728516, 808.1842041015625), (76.845703125, 802.1246948242188), (56.166873931884766, 790.5223388671875), (50.04924011230469, 786.4647216796875), (28.460472106933594, 779.8906860351562), (23.167179107666016, 776.7918701171875), (20.70461082458496, 775.260986328125), (16.703872680664062, 772.0785522460938), (11.138042449951172, 768.5530395507812), (10.98474407196045, 768.399658203125)], 0.033000)
        post_action(0.000000)




    except Exception as e:

        print(e)

        traceback_str = ''.join(traceback.format_tb(e.__traceback__))

        print(traceback_str)

    os.system("adb shell am force-stop " + package_name)
    