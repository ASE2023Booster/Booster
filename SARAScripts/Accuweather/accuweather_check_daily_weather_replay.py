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
        time.sleep(1)
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
        code = code = util.instrument_view([candidate['classname'] for candidate in candidates], [candidate['address'] for candidate in candidates], action_count)
        instrument_script = frida_session.create_script(code)
        instrument_script.on('message', get_instrument_view_message)
        instrument_script.load()
        if tap_type == 'LongTap':
            d.long_click(x, y, duration)
        elif tap_type == 'Tap':
            d.long_click(x, y, duration)
        elif tap_type == 'DoubleTap':
            d.double_click(x, y, 0.1)

        time.sleep(1)
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

        perform_click_event("Tap", 368.488220, 223.825134, 0.249000, "Activity")
        post_action(2.620469)
        perform_swipe_event([(550.2357788085938, 452.6463623046875), (526.2691040039062, 453.6455993652344), (487.2326965332031, 459.48944091796875), (457.6671447753906, 462.25506591796875), (428.8291015625, 462.6385498046875), (406.8578186035156, 464.5766296386719), (384.9989929199219, 464.6369934082031), (361.6631774902344, 466.63543701171875), (311.4593505859375, 469.6330871582031), (295.90924072265625, 469.7689514160156), (276.6898193359375, 471.6068420410156), (261.74932861328125, 470.63232421875), (252.68521118164062, 471.63153076171875), (245.877685546875, 473.0208740234375), (242.66297912597656, 472.6307678222656), (241.66436767578125, 473.6299743652344)])
        post_action(2.345165)
        perform_click_event("Tap", 359.500702, 616.518372, 0.199000, "Activity")
        post_action(2.859198)
        perform_click_event("Tap", 360.499329, 617.517578, 0.267000, "Activity")
        post_action(1.232219)
        perform_swipe_event([(433.3980712890625, 767.4004516601562), (434.13134765625, 754.9269409179688), (438.79779052734375, 728.394775390625), (440.38836669921875, 703.450439453125), (445.17523193359375, 679.533935546875), (448.7404479980469, 657.5767822265625), (450.3744812011719, 637.7776489257812), (454.3503112792969, 609.6356201171875), (458.9482116699219, 585.3218994140625), (461.8585205078125, 562.5604858398438), (468.6288146972656, 538.4605712890625), (472.8291015625, 519.4080810546875), (476.1776123046875, 504.4112548828125), (479.4620666503906, 494.10205078125), (480.83221435546875, 488.6182861328125), (481.8307800292969, 487.11944580078125), (481.33148193359375, 489.9945068359375), (481.33148193359375, 496.443603515625), (478.9628601074219, 516.82763671875), (475.384033203125, 536.40380859375), (473.0598449707031, 552.5501708984375), (470.8460693359375, 567.0569458007812), (468.23980712890625, 584.3126220703125), (466.13525390625, 602.26806640625), (464.55621337890625, 622.9019775390625), (462.20318603515625, 639.9646606445312), (459.861328125, 659.4848022460938), (459.4489440917969, 680.59765625), (457.2915344238281, 698.04150390625), (453.86962890625, 716.93994140625), (452.3717041015625, 735.7864990234375), (451.37310791015625, 750.5851440429688), (449.3758850097656, 763.3049926757812), (449.3758850097656, 775.0470581054688), (448.89239501953125, 786.3223266601562), (448.37725830078125, 801.6060180664062), (447.378662109375, 810.0966186523438), (447.378662109375, 817.7055053710938), (447.378662109375, 823.4721069335938), (447.378662109375, 828.347900390625), (446.4801025390625, 832.2495727539062), (446.3800354003906, 835.4183959960938), (446.3800354003906, 837.1495971679688), (446.3800354003906, 838.3450317382812)])
        post_action(1.058559)
        perform_click_event("Tap", 364.493774, 610.523010, 0.211000, "Activity")
        post_action(4.394075)
        perform_swipe_event([(468.3495178222656, 831.3505249023438), (467.3509216308594, 810.3668823242188), (469.1822509765625, 782.3854370117188), (471.3453674316406, 762.0258178710938), (472.3439636230469, 744.97705078125), (476.4623718261719, 705.8280639648438), (480.0383605957031, 687.6425170898438), (481.33148193359375, 673.6123046875), (484.1154479980469, 662.9064331054688), (485.3259582519531, 657.52197265625), (486.3245544433594, 652.4324951171875), (487.8030090332031, 650.01171875), (487.32318115234375, 648.2611083984375), (488.32177734375, 647.494140625), (488.32177734375, 646.4949340820312), (488.32177734375, 645.4957275390625)])
        post_action(1.044085)
        perform_click_event("Tap", 516.282959, 605.526917, 0.225000, "Activity")
        post_action(4.064493)
        perform_swipe_event([(460.3606262207031, 820.3590698242188), (461.4914245605469, 786.9288330078125), (461.3592224121094, 778.3919067382812), (462.33294677734375, 757.5327758789062), (464.1470031738281, 725.8912963867188), (467.632568359375, 699.1973876953125), (476.8399353027344, 660.2286987304688), (481.1805114746094, 638.8032836914062), (481.71923828125, 625.1818237304688), (489.4276428222656, 592.892578125), (495.7599792480469, 572.2073974609375), (502.8749694824219, 538.4325561523438), (509.42236328125, 522.4619750976562), (511.2898864746094, 518.7536010742188), (512.2885131835938, 516.0968017578125), (513.287109375, 515.59716796875), (514.2857055664062, 514.1122436523438), (514.2857055664062, 514.5979614257812)])
        post_action(0.564052)
        perform_swipe_event([(427.4064025878906, 847.3380126953125), (432.3994445800781, 822.3575439453125), (436.0982360839844, 800.1513671875), (439.2460021972656, 784.8186645507812), (442.9338073730469, 760.6608276367188), (447.7802734375, 737.0166015625), (453.91253662109375, 713.8134155273438), (459.70916748046875, 692.373291015625), (464.1329040527344, 669.2557983398438), (467.4366760253906, 657.9706420898438), (472.6900939941406, 638.4812622070312), (479.9280090332031, 615.7352294921875), (484.2297668457031, 598.9229125976562), (488.7381591796875, 587.4986572265625), (495.7567443847656, 569.219482421875), (501.67169189453125, 549.6494750976562), (506.1092224121094, 536.1447143554688), (509.29266357421875, 529.894287109375), (510.291259765625, 525.6917114257812), (512.6787109375, 522.2013549804688), (513.287109375, 518.6873168945312), (514.2857055664062, 517.27734375), (515.2843627929688, 515.59716796875), (515.2843627929688, 514.5979614257812), (516.282958984375, 514.5979614257812), (516.1748657226562, 514.5979614257812)])
        post_action(0.536680)
        perform_swipe_event([(516.282958984375, 940.2654418945312), (517.3843383789062, 908.3638916015625), (522.0018920898438, 864.6022338867188), (527.0800170898438, 828.6985473632812), (527.2677001953125, 811.6422729492188), (528.2662963867188, 785.3069458007812), (529.264892578125, 759.756103515625), (530.5048828125, 738.7313232421875), (534.1063842773438, 710.5076904296875), (539.0676879882812, 682.7927856445312), (544.2186889648438, 654.6925659179688), (548.70166015625, 634.6495361328125), (553.19970703125, 614.6795043945312), (556.595947265625, 606.419189453125), (559.21923828125, 597.5413818359375), (561.2205200195312, 591.4285888671875), (562.0278930664062, 588.7315673828125), (563.5439453125, 582.218505859375), (566.0841064453125, 576.8087158203125), (567.623779296875, 573.7275390625), (570.2080688476562, 568.5760498046875), (572.2052612304688, 565.0803833007812), (573.6886596679688, 562.0755004882812), (573.8634643554688, 560.9013671875), (574.2025146484375, 560.5620727539062), (575.2011108398438, 559.5628662109375), (575.2011108398438, 560.5620727539062), (575.2011108398438, 562.044921875), (575.2011108398438, 565.8035888671875), (574.5046997070312, 572.342529296875), (571.6618041992188, 591.7147216796875), (565.5887451171875, 620.8306274414062), (561.2149047851562, 639.5283813476562), (553.3405151367188, 671.51806640625), (546.657958984375, 699.4931640625), (542.9267578125, 718.3750610351562), (539.0797119140625, 747.7882690429688), (535.5738525390625, 775.852294921875), (533.1109619140625, 794.5681762695312), (529.5240478515625, 817.803955078125), (526.9554443359375, 835.2855834960938), (526.2691040039062, 845.0802001953125), (525.2704467773438, 849.7066650390625), (525.2704467773438, 851.3003540039062), (525.2704467773438, 851.3348999023438)])
        post_action(0.985287)
        perform_click_event("Tap", 641.109558, 269.789215, 0.151000, "Activity")
        post_action(2.036440)
        perform_swipe_event([(475.3398132324219, 548.5714111328125), (473.34259033203125, 572.5526733398438), (469.2139892578125, 600.6056518554688), (465.35369873046875, 626.5105590820312), (463.4035339355469, 642.2623901367188), (460.3606262207031, 661.795654296875), (459.36199951171875, 674.45947265625), (458.3634033203125, 691.2945556640625), (457.54119873046875, 701.5685424804688), (456.3661804199219, 715.2412109375), (454.5040588378906, 726.8908081054688), (453.94287109375, 738.7028198242188), (453.3703308105469, 746.4168701171875), (453.3703308105469, 755.8713989257812), (453.3703308105469, 765.3207397460938), (453.3703308105469, 767.4004516601562)])
        post_action(0.408575)
        perform_swipe_event([(423.41192626953125, 277.7829895019531), (410.3917541503906, 365.9054260253906), (402.802734375, 404.14910888671875), (401.1822204589844, 426.4909973144531), (398.2805480957031, 459.4725341796875), (396.4493713378906, 483.561279296875), (396.4493713378906, 494.5895690917969), (396.4493713378906, 502.5404052734375), (397.447998046875, 518.0206298828125), (397.447998046875, 528.5341796875), (397.447998046875, 533.5831298828125)])
        post_action(0.593966)
        perform_click_event("Tap", 61.914009, 274.785309, 0.126000, "Activity")
        post_action(1.502011)
        perform_click_event("Tap", 54.923717, 79.937546, 0.080000, "Activity")
        post_action(2.189914)
        perform_click_event("Tap", 623.134521, 324.746277, 0.197000, "Activity")
        post_action(2.346169)
        perform_click_event("Tap", 54.923717, 47.962528, 0.098000, "Activity")
        post_action(1.670369)
        perform_swipe_event([(450.3744812011719, 501.6081237792969), (446.47137451171875, 533.8511352539062), (445.0281677246094, 558.1018676757812), (442.65655517578125, 582.831298828125), (440.4552917480469, 602.9257202148438), (437.891845703125, 625.01171875), (436.6680908203125, 640.8519287109375), (433.2225646972656, 666.70947265625), (431.4008483886719, 683.9881591796875), (430.4022216796875, 701.3501586914062), (428.9847106933594, 709.1240844726562), (428.4049987792969, 724.7317504882812), (428.4049987792969, 735.9201049804688), (428.4049987792969, 803.2566528320312), (428.4049987792969, 803.3723754882812), (428.4049987792969, 804.37158203125)])
        post_action(0.939372)
        perform_click_event("Tap", 630.124817, 321.748627, 0.197000, "Activity")
        post_action(1.504366)
        perform_click_event("Tap", 626.130371, 315.753326, 0.237000, "Activity")
        post_action(4.177049)
        perform_click_event("Tap", 51.927879, 218.829041, 0.224000, "Activity")
        post_action(0.000000)

    except Exception as e:
        print(e)
        traceback_str = ''.join(traceback.format_tb(e.__traceback__))
        print(traceback_str)
    clean_up()
    