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

        perform_click_event("Tap", 385.464630, 1236.034302, 0.098000, "Activity")
        post_action(1.900604)
        perform_swipe_event([(467.3509216308594, 1044.1842041015625), (466.352294921875, 999.888671875), (468.7070007324219, 965.5179443359375), (473.1571960449219, 940.774169921875), (479.0673828125, 901.30029296875), (481.7319641113281, 881.3036499023438), (483.9236755371094, 867.4497680664062), (490.0347900390625, 840.5183715820312), (494.005615234375, 826.4846801757812), (500.79937744140625, 801.7239990234375), (503.30096435546875, 786.8851928710938), (511.3544616699219, 765.5197143554688), (516.4129638671875, 750.0235595703125), (523.7050170898438, 723.7051391601562), (526.776123046875, 711.9153442382812), (534.3840942382812, 681.7437744140625), (539.3063354492188, 664.2871704101562), (546.6044921875, 639.9545288085938), (548.753662109375, 634.8934326171875), (552.2442626953125, 620.4590454101562), (554.5443725585938, 616.2039794921875), (554.230224609375, 614.8907470703125), (555.372314453125, 613.5206909179688), (555.2288818359375, 611.2747802734375), (555.2288818359375, 611.522216796875), (555.2288818359375, 610.6574096679688), (555.2288818359375, 610.5230102539062)], 0.033000)
        post_action(0.519743)
        perform_swipe_event([(437.39251708984375, 910.288818359375), (434.39666748046875, 878.3184814453125), (440.3527526855469, 795.19921875), (446.8793640136719, 737.423828125), (452.8734436035156, 690.4365234375), (458.7673034667969, 647.2586669921875), (460.78289794921875, 634.7554321289062), (467.7239990234375, 595.6666870117188), (475.6340026855469, 562.4557495117188), (482.3544616699219, 538.2916870117188), (490.6331787109375, 503.9264831542969), (501.5030517578125, 468.9350891113281), (503.4078674316406, 457.0008850097656), (510.79058837890625, 431.1631774902344), (514.6566772460938, 420.1859436035156), (521.8807983398438, 397.872314453125), (525.3782958984375, 390.1100158691406), (530.7152709960938, 380.0721130371094), (533.06884765625, 372.37689208984375), (537.4158325195312, 363.22955322265625), (540.2496337890625, 360.71820068359375), (541.248291015625, 358.9873962402344), (542.3025512695312, 357.6648254394531), (542.2468872070312, 355.53582763671875), (542.7852783203125, 355.7220764160156), (543.2454833984375, 355.7220764160156), (544.2860717773438, 355.7220764160156), (544.244140625, 355.7220764160156)], 0.032500)
        post_action(1.338032)
        perform_swipe_event([(538.25244140625, 834.34814453125), (529.5737915039062, 799.715576171875), (526.9171752929688, 759.43896484375), (531.1393432617188, 733.124267578125), (546.9249267578125, 655.5784301757812), (550.7146606445312, 633.1215209960938), (557.1934814453125, 608.655029296875), (562.1350708007812, 592.7894897460938), (572.766845703125, 564.0972290039062), (582.9718627929688, 529.5463256835938), (587.1150512695312, 516.8048706054688), (596.9744873046875, 487.6725769042969), (604.17333984375, 467.2601318359375), (608.1570434570312, 455.6406555175781), (614.9566650390625, 438.1622314453125), (621.1373291015625, 420.1717529296875), (623.6788940429688, 416.9488220214844), (627.17431640625, 407.6135559082031), (628.2732543945312, 402.3938903808594), (629.126220703125, 398.9842224121094), (630.1248168945312, 398.68853759765625)], 0.033000)
        post_action(0.477725)
        perform_click_event("Tap", 472.343964, 640.499634, 0.096000, "Activity")
        post_action(5.493273)
        perform_swipe_event([(488.32177734375, 635.5035400390625), (498.2171630859375, 584.5796508789062), (516.2942504882812, 532.5523071289062), (523.7725219726562, 511.6003112792969), (539.5211791992188, 475.43341064453125), (548.8468017578125, 453.5252990722656), (558.3223266601562, 434.7329406738281), (566.1591796875, 417.2557373046875), (573.0328979492188, 403.0276794433594), (576.8853149414062, 395.3179931640625), (582.6907348632812, 383.20062255859375), (585.2095947265625, 376.6833190917969), (585.187255859375, 375.2068786621094), (585.187255859375, 374.8450622558594), (585.187255859375, 374.7072448730469)], 0.033000)
        post_action(2.002411)
        perform_swipe_event([(586.1858520507812, 845.339599609375), (586.1858520507812, 816.1962280273438), (588.4886474609375, 785.103271484375), (596.7020874023438, 724.2490844726562), (603.5941162109375, 687.30078125), (607.6105346679688, 656.69970703125), (614.0289916992188, 623.34033203125), (618.305908203125, 594.5476684570312), (623.134521484375, 568.5558471679688), (627.7891235351562, 542.81884765625), (632.97802734375, 525.8035888671875), (638.0296020507812, 509.16021728515625), (641.9033813476562, 494.2291564941406), (651.6666259765625, 472.40185546875), (656.849365234375, 462.1157531738281), (662.5797729492188, 447.6502685546875), (663.4661254882812, 441.18634033203125), (665.0762939453125, 432.1496887207031), (667.384033203125, 430.3529052734375), (668.536376953125, 425.2029113769531), (669.0707397460938, 423.12567138671875), (669.0707397460938, 420.3382263183594), (669.0707397460938, 419.223388671875), (669.0707397460938, 416.8454895019531), (669.0707397460938, 416.17486572265625), (669.0707397460938, 415.6752624511719), (669.0707397460938, 414.676025390625), (670.0693359375, 414.676025390625), (670.0693359375, 413.8331298828125), (670.0693359375, 413.67681884765625)], 0.033000)
        post_action(1.336606)
        perform_swipe_event([(291.5950012207031, 1018.2045288085938), (305.5196533203125, 982.419189453125), (317.2316589355469, 941.5753173828125), (334.97216796875, 872.5687255859375), (349.564697265625, 817.5272216796875), (361.93817138671875, 784.5526123046875), (377.5275573730469, 745.2991943359375), (390.7834777832031, 710.1281127929688), (403.439697265625, 674.9727172851562), (424.4434814453125, 634.4384155273438), (442.37451171875, 603.0482788085938), (457.39031982421875, 575.012451171875), (463.496826171875, 564.1348876953125), (485.1642150878906, 533.785400390625), (489.7386169433594, 527.2017822265625), (500.20452880859375, 512.767333984375), (504.5271911621094, 505.26336669921875), (506.740966796875, 502.71771240234375), (510.0200500488281, 499.1532287597656), (511.24432373046875, 496.70318603515625), (512.2885131835938, 491.8566589355469), (514.2857055664062, 489.8407897949219), (515.2454223632812, 488.6572570800781), (516.552978515625, 486.34967041015625), (517.7808837890625, 485.62060546875), (518.3776245117188, 484.62139892578125), (518.2801513671875, 483.3796081542969), (518.2801513671875, 483.6221618652344), (517.691162109375, 483.6221618652344), (516.220947265625, 483.6221618652344), (516.282958984375, 485.7437438964844), (514.8812866210938, 489.8283386230469), (507.2954406738281, 507.10382080078125), (498.8943176269531, 530.8236694335938), (477.086669921875, 582.4912109375), (469.0967102050781, 604.06396484375), (452.0101318359375, 654.7569580078125), (440.3756408691406, 694.9003295898438), (433.8973693847656, 726.9320068359375), (426.2992248535156, 751.7388305664062), (421.0804443359375, 765.239013671875), (419.6695251464844, 777.383056640625), (417.4104309082031, 782.408447265625), (417.4202575683594, 783.3880004882812)], 0.033000)
        post_action(0.331376)
        perform_swipe_event([(379.47296142578125, 929.2739868164062), (389.9583740234375, 881.3114624023438), (402.9736633300781, 837.0792846679688), (415.85693359375, 803.3079833984375), (439.62640380859375, 734.7149658203125), (467.7388610839844, 661.9581909179688), (500.8044738769531, 592.5370483398438), (520.6351928710938, 551.659912109375), (533.3707275390625, 529.666259765625), (560.215576171875, 487.7124328613281), (580.1942138671875, 457.142822265625), (583.398193359375, 450.4396057128906), (591.44189453125, 435.1333923339844), (598.3442993164062, 424.31787109375), (601.1650390625, 420.710693359375), (601.1650390625, 420.6713562011719), (602.1636962890625, 419.672119140625), (603.1622924804688, 416.6131286621094)], 0.033000)
        post_action(0.399439)
        perform_swipe_event([(299.58392333984375, 982.2326049804688), (314.3307800292969, 928.9722290039062), (346.2690124511719, 843.2913208007812), (365.59124755859375, 795.081787109375), (378.9915771484375, 759.8524169921875), (393.5836181640625, 715.0505981445312), (403.2340393066406, 687.8157348632812), (415.279541015625, 664.9391479492188), (439.7322692871094, 616.1640014648438), (452.98541259765625, 591.631591796875), (465.2418518066406, 567.55859375), (478.4904479980469, 546.8402709960938), (492.1912841796875, 528.420654296875), (503.8002624511719, 513.5987548828125), (510.2250061035156, 502.71783447265625), (515.5237426757812, 494.1345520019531), (518.972900390625, 488.2312316894531), (520.2774047851562, 484.6608581542969), (521.2760009765625, 484.62139892578125)], 0.033000)
        post_action(0.412273)
        perform_swipe_event([(535.256591796875, 466.63543701171875), (523.4710693359375, 493.0205993652344), (507.8835144042969, 535.814697265625), (487.93896484375, 603.2084350585938), (480.4087829589844, 632.720703125), (461.47509765625, 726.5502319335938), (451.0022888183594, 798.2542724609375), (443.883544921875, 855.831298828125), (442.1859130859375, 870.119873046875), (440.38836669921875, 891.828125), (438.23388671875, 901.0047607421875), (434.7640686035156, 923.9671020507812), (432.4950256347656, 940.5952758789062), (429.0429992675781, 955.0595092773438), (427.4064025878906, 962.4479370117188), (426.40777587890625, 969.1192016601562), (425.4091491699219, 975.2381591796875), (424.4105529785156, 978.2357788085938)], 0.033000)
        post_action(0.284847)
        perform_swipe_event([(551.2344360351562, 497.6112365722656), (544.7416381835938, 513.4921264648438), (524.123046875, 581.8507080078125), (496.3106689453125, 703.450439453125), (487.92572021484375, 793.51904296875), (484.1458740234375, 863.8675537109375), (481.33148193359375, 921.599365234375), (477.7756042480469, 966.5117797851562), (473.6329650878906, 999.1201782226562), (471.93768310546875, 1011.6507568359375), (470.33978271484375, 1018.2184448242188), (470.34674072265625, 1019.2037353515625), (470.34674072265625, 1020.2029418945312), (470.34674072265625, 1019.2037353515625)], 0.033000)
        post_action(0.218913)
        perform_swipe_event([(547.2399291992188, 514.5979614257812), (538.1452026367188, 536.6987915039062), (507.7607116699219, 629.802001953125), (484.53167724609375, 770.6354370117188), (482.5740966796875, 869.1616821289062), (483.3287353515625, 905.292724609375), (484.32733154296875, 910.359619140625), (484.32733154296875, 911.5108642578125), (484.32733154296875, 914.7852783203125), (485.3259582519531, 917.2833862304688)], 0.033000)
        post_action(0.526924)
        perform_click_event("Tap", 48.932041, 277.782990, 0.111000, "Activity")
        post_action(1.086806)
        perform_swipe_event([(505.2982177734375, 881.3114624023438), (506.9873962402344, 853.1842651367188), (514.3824462890625, 806.764404296875), (526.7683715820312, 730.928955078125), (535.56884765625, 677.90673828125), (546.4157104492188, 633.2196044921875), (552.7177734375, 616.0625), (564.556884765625, 564.6890258789062), (567.8075561523438, 547.7257690429688), (575.1234741210938, 514.0650024414062), (577.1983032226562, 506.1046142578125), (582.0935668945312, 486.0611267089844), (585.5303955078125, 475.5976257324219), (589.5797729492188, 457.85205078125), (591.178955078125, 453.6186828613281), (592.1775512695312, 447.7718505859375), (593.3988647460938, 445.2060852050781), (593.1761474609375, 445.6518249511719), (593.1761474609375, 444.6526184082031)], 0.033000)
        post_action(1.209264)
        perform_click_event("Tap", 527.267700, 608.524597, 0.126000, "Activity")
        post_action(0.974458)
        perform_click_event("Tap", 372.482666, 467.634674, 0.111000, "Activity")
        post_action(14.419968)
        perform_swipe_event([(307.57281494140625, 1078.15771484375), (316.12060546875, 1046.7967529296875), (319.55615234375, 1023.7002563476562), (330.26007080078125, 981.3997192382812), (337.5633544921875, 953.7819213867188), (348.2535400390625, 914.1792602539062), (359.6101989746094, 880.9827270507812), (368.987548828125, 850.8352661132812), (377.7532958984375, 828.7965698242188), (381.8608703613281, 812.9955444335938), (388.8597106933594, 795.9786987304688), (396.6907958984375, 774.7299194335938), (403.9389953613281, 747.9156494140625), (414.0135192871094, 719.5076904296875), (425.7815856933594, 690.4163208007812), (437.891845703125, 657.486328125), (448.9765930175781, 634.3041381835938), (458.7899475097656, 609.95556640625), (463.54180908203125, 593.4365844726562), (469.1495056152344, 580.044189453125), (475.33984375, 564.059326171875), (483.4826965332031, 547.2640380859375), (489.6875915527344, 534.8467407226562), (493.81414794921875, 525.58935546875), (496.0950927734375, 520.0255737304688), (497.6602478027344, 517.2444458007812), (498.70953369140625, 516.596435546875), (498.30792236328125, 516.596435546875)], 0.033000)
        post_action(0.510738)
        perform_swipe_event([(271.62274169921875, 1020.2029418945312), (280.2257995605469, 985.0272216796875), (292.5567626953125, 941.893310546875), (308.0721435546875, 885.308349609375), (323.5334777832031, 841.3912963867188), (335.4826965332031, 807.839111328125), (351.6531677246094, 758.717041015625), (364.50885009765625, 718.3873901367188), (379.1878662109375, 686.5821533203125), (387.76214599609375, 666.0531005859375), (397.4921875, 643.39111328125), (411.9278869628906, 613.0210571289062), (426.0079650878906, 587.7413940429688), (439.7724304199219, 561.518310546875), (448.8648376464844, 544.4642944335938), (455.8902282714844, 533.3776245117188), (462.19598388671875, 520.4985961914062), (467.5927429199219, 513.3568115234375), (472.52728271484375, 507.4200134277344), (475.7653503417969, 504.1799621582031), (478.05706787109375, 501.8868713378906), (478.8157653808594, 501.12774658203125), (477.3370361328125, 501.6081237792969), (471.5024719238281, 509.33990478515625), (459.3944396972656, 532.71240234375), (410.42999267578125, 631.506591796875), (377.0308837890625, 723.280517578125), (365.5455322265625, 769.1862182617188), (359.5007019042969, 793.7723999023438), (355.4072265625, 814.8592529296875), (349.51458740234375, 840.343505859375), (344.7621154785156, 862.2421264648438), (340.4352722167969, 881.724609375), (338.030517578125, 905.292724609375), (334.67218017578125, 925.1813354492188), (333.5367736816406, 940.85888671875), (331.8590087890625, 951.9765625), (330.5409240722656, 957.04833984375), (329.54229736328125, 958.2513427734375)], 0.033000)
        post_action(0.300140)
        perform_swipe_event([(447.378662109375, 592.537109375), (440.9521789550781, 632.8275756835938), (426.9070739746094, 683.9656372070312), (404.9361267089844, 746.9761962890625), (390.78167724609375, 795.7428588867188), (381.3761291503906, 837.8165283203125), (376.5819396972656, 872.5310668945312), (373.0627746582031, 908.1581420898438), (370.7049865722656, 934.07177734375), (369.4868469238281, 955.15087890625), (369.4868469238281, 978.23583984375), (369.4868469238281, 994.7599487304688), (369.4868469238281, 1009.5061645507812), (370.0899658203125, 1022.2211303710938), (370.4854431152344, 1030.569580078125), (370.4854431152344, 1035.0367431640625), (371.48406982421875, 1037.64111328125), (371.48406982421875, 1038.18896484375)], 0.033000)
        post_action(1.730636)
        perform_click_event("Tap", 48.932041, 292.771271, 0.112000, "Activity")
        post_action(0.403094)
        perform_swipe_event([(527.2677001953125, 1052.177978515625), (519.3782348632812, 1026.2301025390625), (516.3770751953125, 1008.8716430664062), (515.1666870117188, 986.9904174804688), (515.2843627929688, 964.0242919921875), (516.6290893554688, 875.9576416015625), (527.9761352539062, 784.130859375), (535.33984375, 754.0774536132812), (547.7392578125, 703.9500122070312), (549.9476928710938, 691.6331787109375), (552.4247436523438, 667.5587768554688), (554.5746459960938, 656.5899047851562), (564.2106323242188, 612.5502319335938), (577.2997436523438, 571.2491455078125), (584.0449829101562, 550.2391357421875), (596.6073608398438, 523.71875), (600.7169189453125, 517.4932250976562), (601.1650390625, 514.6224975585938), (602.1636962890625, 514.0657958984375), (602.1636962890625, 512.8096923828125), (603.4146118164062, 511.6003112792969), (603.1622924804688, 509.60186767578125)], 0.024000)
        post_action(0.733520)
        perform_swipe_event([(561.2205200195312, 952.2560424804688), (553.5330200195312, 884.3460083007812), (554.4578247070312, 850.0933227539062), (555.5626220703125, 823.336669921875), (560.7354125976562, 774.785888671875), (564.8790283203125, 746.5474243164062), (568.8243408203125, 729.9722900390625), (574.2025146484375, 699.4535522460938), (576.19970703125, 689.4613647460938), (579.212158203125, 679.4359741210938), (583.4830932617188, 666.4520874023438), (587.6314697265625, 656.109619140625), (596.2405395507812, 634.5997924804688), (609.734375, 603.0501098632812), (617.5796508789062, 588.0252685546875), (619.7310180664062, 582.361572265625), (622.1359252929688, 576.591064453125), (623.3929443359375, 576.549560546875), (623.134521484375, 575.05078125), (623.134521484375, 575.5503540039062)], 0.032000)
        post_action(1.029783)
        perform_swipe_event([(555.2288818359375, 943.2630615234375), (547.9059448242188, 915.1748046875), (541.6329956054688, 875.1691284179688), (536.3551635742188, 819.3622436523438), (539.6209106445312, 773.5067749023438), (554.0060424804688, 699.5762939453125), (563.7318115234375, 654.400390625), (575.5958862304688, 621.2869873046875), (585.9613647460938, 595.984130859375), (597.3967895507812, 578.7081909179688), (600.5299072265625, 572.4608154296875), (603.1134643554688, 569.5550537109375), (603.1622924804688, 569.5550537109375)], 0.033000)
        post_action(0.325172)
        perform_click_event("Tap", 473.342590, 723.434814, 0.055000, "Activity")
        post_action(1.271446)
        perform_swipe_event([(310.56866455078125, 1040.1873779296875), (320.5549011230469, 988.2274780273438), (329.10821533203125, 953.8522338867188), (348.2941589355469, 898.5755004882812), (356.6280822753906, 880.300048828125), (373.83135986328125, 842.9761352539062), (383.064453125, 817.1729736328125), (405.62506103515625, 763.9425659179688), (426.20526123046875, 719.1444091796875), (441.0243835449219, 687.211669921875), (455.4820556640625, 658.4420166015625), (460.6943664550781, 647.825439453125), (477.4740905761719, 615.244873046875), (485.583740234375, 598.1400146484375), (499.146484375, 575.0392456054688), (504.29962158203125, 558.0640258789062), (505.2982177734375, 554.5648803710938), (505.2982177734375, 551.4317016601562), (506.29681396484375, 549.87451171875), (507.27130126953125, 548.5714111328125), (507.2954406738281, 547.5722045898438)], 0.033000)
        post_action(0.453816)
        perform_swipe_event([(502.3023681640625, 973.2396850585938), (496.3106994628906, 946.2607421875), (491.4567565917969, 839.492919921875), (511.265869140625, 744.2586669921875), (553.9177856445312, 640.9510498046875), (572.659423828125, 593.3994140625), (596.1719970703125, 546.572998046875), (616.7847290039062, 508.20074462890625), (622.6227416992188, 498.83026123046875), (632.3594970703125, 479.15008544921875), (637.1151123046875, 468.13427734375), (639.0049438476562, 463.96026611328125), (640.4494018554688, 458.9636535644531), (640.1109619140625, 458.3470153808594), (641.1095581054688, 458.6416931152344)], 0.033000)
        post_action(0.264013)
        perform_swipe_event([(518.2801513671875, 900.296630859375), (512.4762573242188, 854.46875), (517.4935913085938, 760.2421264648438), (542.2454833984375, 638.8805541992188), (568.3053588867188, 579.3582153320312), (579.6949462890625, 563.5596923828125), (582.3744506835938, 549.8372192382812), (584.4608154296875, 545.0292358398438), (585.187255859375, 544.5745239257812), (583.3001708984375, 546.4627685546875), (564.2164306640625, 587.0413818359375), (519.5438232421875, 682.71875), (487.40399169921875, 790.4425659179688), (476.33843994140625, 871.3192138671875), (473.34259033203125, 929.7843017578125), (473.34259033203125, 972.3353881835938), (473.34259033203125, 988.0863037109375), (473.34259033203125, 1001.2907104492188), (472.3439636230469, 1006.8302001953125), (473.34259033203125, 1007.213134765625)], 0.033000)
        post_action(0.416392)
        perform_swipe_event([(542.2468872070312, 500.60888671875), (517.0117797851562, 560.0265502929688), (483.61572265625, 661.7472534179688), (468.554443359375, 763.6674194335938), (468.4385681152344, 834.844482421875), (472.343994140625, 882.3107299804688), (473.34259033203125, 912.4116821289062), (473.34259033203125, 927.9829711914062), (472.3439636230469, 938.775146484375), (471.3453674316406, 946.939697265625), (471.3453674316406, 953.7548828125), (471.3453674316406, 955.9212646484375), (471.3453674316406, 956.2529296875)], 0.033000)
        post_action(0.500768)
        perform_click_event("Tap", 653.092957, 294.769714, 0.082000, "Activity")
        post_action(0.750103)
        record_popup_window()
        post_action(4.735974)
        perform_click_event("Tap", 548.238586, 312.755646, 0.142000, "None")
        post_action(0.157626)
        close_popup_window()
        post_action(0.000000)

    except Exception as e:
        print(e)
        traceback_str = ''.join(traceback.format_tb(e.__traceback__))
        print(traceback_str)
    clean_up()
    