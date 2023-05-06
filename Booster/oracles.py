import datetime
import os
from bs4 import BeautifulSoup
from PIL import Image, ImageChops, ImageStat
import argparse

threshold = 0.05



def wikipedia_browse_reading_list_oracle(path):
    print("file path:", path)
    with open(path, 'rb') as f:
        layout = f.read()
    layout = BeautifulSoup(layout.decode(), 'lxml')
    target = layout.find('node', attrs={'resource-id': 'org.wikipedia:id/reading_list_item_offline_switch'})
    try:
        # print(target['text'])
        return target['text'] == "Available offline ON"
    except:
        return False


def vlc_watch_video_trace_oracle(path):
    print("file path:", path)
    with open(path, 'rb') as f:
        layout = f.read()
    layout = BeautifulSoup(layout.decode(), 'lxml')
    target = layout.find('node', attrs={'bounds': '[418,424][536,568]'})
    try:
        print(target != None)
        return target != None
    except:
        return False


def vlc_jump_to_time_oracle(path):
    print("file path:", path)
    with open(path, 'rb') as f:
        layout = f.read()
    layout = BeautifulSoup(layout.decode(), 'lxml')
    target = layout.find('node', attrs={'resource-id': 'com.android.systemui:id/status_bar'})
    try:
        print(target)
        return target != None
    except:
        return False


def vlc_delete_video_oracle(path):
    print("file path:", path)
    with open(path, 'rb') as f:
        layout = f.read()
    layout = BeautifulSoup(layout.decode(), 'lxml')
    target = layout.find('node', attrs={'text': 'Delete'})
    if target == None:
        return False

    path2 = os.path.dirname(path)

    prefix = 'screenshot_'
    all_files = os.listdir(path2)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))

    file = files[-2]
    file1 = files[0]
    path1 = os.path.join(path2, file1)
    path2 = os.path.join(path2, file)
    print(path1,path2)
    if len(files) < 3:
        return  False

    img1 = Image.open(path1)
    img1_crop = img1.crop((0, 100, 700, 1200))  
    img2_crop = img2.crop((0, 100, 700, 1200))
    diff = ImageChops.difference(img1_crop, img2_crop)

    stat = ImageStat.Stat(diff)
    diff_ratio = sum(stat.mean) / (len(stat.mean) * 255)

    print(diff_ratio > 0.01)
    print(diff_ratio)
    return diff_ratio > 0.01


def vlc_audio_delay_oracle(path):
    print("file path:", path)
    with open(path, 'rb') as f:
        layout = f.read()
    layout = BeautifulSoup(layout.decode(), 'lxml')
    target = layout.find('node', attrs={'resource-id': 'org.videolan.vlc:id/player_overlay_textinfo'})
    try:
        print(target['text'] == "Audio delay\n200 ms")
        return target['text'] == "Audio delay\n200 ms"
    except:
        return False


def textgram_create_canvas_oracle(path):
    path1 = os.path.dirname(path)
    prefix = 'screenshot_'
    all_files = os.listdir(path1)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path1 = os.path.join(path1, file)
    print(path1)
    im = Image.open(path1)
    box1 = (11, 282, 222, 475)
    box2 = (257, 282, 455, 475)

    im_crop = im.crop(box1)
    im_crop1 = im.crop(box2)
    arr = np.array(im_crop)
    #Calculate the standard deviation of an array
    arr1 = np.array(im_crop1)
    std = np.std(arr)
    std2 = np.std(arr1)
    print(std, std2)

    # Determine whether there is a single tone
    print(std > 5 and std2 > 5)
    return std > 5 and std2 > 5


def textgram_change_canvas_size_oracle(path):
    if 'original' in path:
        return True
    path2 = os.path.dirname(path)
    path1 = os.path.dirname(path2)
    path1 = os.path.join(path1, 'original')
    prefix = 'screenshot_'
    all_files = os.listdir(path1)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path1 = os.path.join(path1, file)

    prefix = 'screenshot_'
    all_files = os.listdir(path2)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path2 = os.path.join(path2, file)

    img1 = Image.open(path1)
    img1_crop = img1.crop((150, 300, 550, 800))  # (left, upper, right, lower)
    # img1.show()
    img2 = Image.open(path2)
    img2_crop = img2.crop((150, 300, 550, 800))
    # img2.show()
    diff = ImageChops.difference(img1_crop, img2_crop)

    stat = ImageStat.Stat(diff)
    diff_ratio = sum(stat.mean) / (len(stat.mean) * 255)

    print(diff_ratio < 0.005)
    return diff_ratio < 0.01


def textgram_change_canvas_background_oracle(path):
    if 'original' in path:
        return True
    path2 = os.path.dirname(path)
    path1 = os.path.dirname(path2)
    path1 = os.path.join(path1, 'original')
    prefix = 'screenshot_'
    all_files = os.listdir(path1)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path1 = os.path.join(path1, file)

    prefix = 'screenshot_'
    all_files = os.listdir(path2)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path2 = os.path.join(path2, file)

    img1 = Image.open(path1)
    img1_crop = img1.crop((0, 100, 700, 1200))  # (left, upper, right, lower)
    img2 = Image.open(path2)
    img2_crop = img2.crop((0, 100, 700, 1200))

    diff = ImageChops.difference(img1_crop, img2_crop)

    stat = ImageStat.Stat(diff)
    diff_ratio = sum(stat.mean) / (len(stat.mean) * 255)

    print(diff_ratio)
    return diff_ratio < 0.01


def textgram_add_stickers_oracle(path):
    if 'original' in path:
        return True
    path2 = os.path.dirname(path)
    path1 = os.path.dirname(path2)
    path1 = os.path.join(path1, 'original')
    prefix = 'screenshot_'
    all_files = os.listdir(path1)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path1 = os.path.join(path1, file)

    prefix = 'screenshot_'
    all_files = os.listdir(path2)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path2 = os.path.join(path2, file)

    img1 = Image.open(path1)
    img1_crop = img1.crop((0, 100, 700, 1200))  # (left, upper, right, lower)
    img2 = Image.open(path2)
    img2_crop = img2.crop((0, 100, 700, 1200))

    diff = ImageChops.difference(img1_crop, img2_crop)

    stat = ImageStat.Stat(diff)
    diff_ratio = sum(stat.mean) / (len(stat.mean) * 255)

    print(diff_ratio)
    return diff_ratio < 0.005


def textgram_add_filters_and_frames_oracle(path):
    if 'original' in path:
        return True
    path2 = os.path.dirname(path)
    path1 = os.path.dirname(path2)
    path1 = os.path.join(path1, 'original')
    prefix = 'screenshot_'
    all_files = os.listdir(path1)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path1 = os.path.join(path1, file)

    prefix = 'screenshot_'
    all_files = os.listdir(path2)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path2 = os.path.join(path2, file)

    img1 = Image.open(path1)
    img1_crop = img1.crop((0, 100, 700, 1200))  # (left, upper, right, lower)
    img2 = Image.open(path2)
    img2_crop = img2.crop((0, 100, 700, 1200))

    diff = ImageChops.difference(img1_crop, img2_crop)

    stat = ImageStat.Stat(diff)
    diff_ratio = sum(stat.mean) / (len(stat.mean) * 255)

    print(diff_ratio)
    return diff_ratio < 0.01

def snapseed_visit_insights_oracle(path):
    if 'original' in path:
        return True
    path2 = os.path.dirname(path)
    path1 = os.path.dirname(path2)
    path1 = os.path.join(path1, 'original')
    prefix = 'screenshot_'
    all_files = os.listdir(path1)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path1 = os.path.join(path1, file)

    prefix = 'screenshot_'
    all_files = os.listdir(path2)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path2 = os.path.join(path2, file)

    img1 = Image.open(path1)
    img1_crop = img1.crop((0, 100, 700, 1200))  # (left, upper, right, lower)
    img2 = Image.open(path2)
    img2_crop = img2.crop((0, 100, 700, 1200))

    diff = ImageChops.difference(img1_crop, img2_crop)

    stat = ImageStat.Stat(diff)
    diff_ratio = sum(stat.mean) / (len(stat.mean) * 255)

    print(diff_ratio)
    return diff_ratio < 0.01


def snapseed_view_edits_oracle(path):
    if 'original' in path:
        return True
    path2 = os.path.dirname(path)
    path1 = os.path.dirname(path2)
    path1 = os.path.join(path1, 'original')
    prefix = 'screenshot_'
    all_files = os.listdir(path1)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path1 = os.path.join(path1, file)

    prefix = 'screenshot_'
    all_files = os.listdir(path2)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path2 = os.path.join(path2, file)

    img1 = Image.open(path1)
    img1_crop = img1.crop((0, 100, 700, 1200))  # (left, upper, right, lower)
    img2 = Image.open(path2)
    img2_crop = img2.crop((0, 100, 700, 1200))

    diff = ImageChops.difference(img1_crop, img2_crop)

    stat = ImageStat.Stat(diff)
    diff_ratio = sum(stat.mean) / (len(stat.mean) * 255)

    print(diff_ratio)
    return diff_ratio < 0.01


def snapseed_edit_with_tools_oracle(path):
    if 'original' in path:
        return True
    path2 = os.path.dirname(path)
    path1 = os.path.dirname(path2)
    path1 = os.path.join(path1, 'original')
    prefix = 'screenshot_'
    all_files = os.listdir(path1)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path1 = os.path.join(path1, file)

    prefix = 'screenshot_'
    all_files = os.listdir(path2)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path2 = os.path.join(path2, file)

    img1 = Image.open(path1)
    img1_crop = img1.crop((0, 100, 700, 1200))  # (left, upper, right, lower)
    img2 = Image.open(path2)
    img2_crop = img2.crop((0, 100, 700, 1200))

    diff = ImageChops.difference(img1_crop, img2_crop)

    stat = ImageStat.Stat(diff)
    diff_ratio = sum(stat.mean) / (len(stat.mean) * 255)

    print(diff_ratio)
    return diff_ratio < 0.01


def snapseed_edit_with_filters_oracle(path):
    if 'original' in path:
        return True
    path2 = os.path.dirname(path)
    path1 = os.path.dirname(path2)
    path1 = os.path.join(path1, 'original')
    prefix = 'screenshot_'
    all_files = os.listdir(path1)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path1 = os.path.join(path1, file)

    prefix = 'screenshot_'
    all_files = os.listdir(path2)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path2 = os.path.join(path2, file)

    img1 = Image.open(path1)
    img1_crop = img1.crop((0, 100, 700, 1200))  # (left, upper, right, lower)
    img2 = Image.open(path2)
    img2_crop = img2.crop((0, 100, 700, 1200))

    diff = ImageChops.difference(img1_crop, img2_crop)

    stat = ImageStat.Stat(diff)
    diff_ratio = sum(stat.mean) / (len(stat.mean) * 255)

    print(diff_ratio)
    return diff_ratio < 0.01


def snapseed_apply_face_filters_oracle(path):
    with open(path,'rb') as f:
        layout = f.read()
    layout = BeautifulSoup(layout.decode(), 'lxml')
    target = layout.find('node', attrs={'resource-id': 'com.niksoftware.snapseed:id/slider_label'})

    try:
        print(target['text'])
        return target['text']=='Focal Length +49'
    except:
        return False



def calculator_check_history_oracle(path):
    if 'original' in path:
        return True
    path2 = os.path.dirname(path)
    path1 = os.path.dirname(path2)
    path1 = os.path.join(path1, 'original')
    prefix = 'screenshot_'
    all_files = os.listdir(path1)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path1 = os.path.join(path1, file)

    prefix = 'screenshot_'
    all_files = os.listdir(path2)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path2 = os.path.join(path2, file)

    img1 = Image.open(path1)
    img1_crop = img1.crop((0, 100, 700, 1200))  # (left, upper, right, lower)
    img2 = Image.open(path2)
    img2_crop = img2.crop((0, 100, 700, 1200))

    diff = ImageChops.difference(img1_crop, img2_crop)

    stat = ImageStat.Stat(diff)
    diff_ratio = sum(stat.mean) / (len(stat.mean) * 255)

    print(diff_ratio)
    return diff_ratio < 0.01


def calculator_change_answer_format_oracle(path):
    print("file path:", path)
    with open(path, 'rb') as f:
        layout = f.read()
    layout = BeautifulSoup(layout.decode(), 'lxml')
    target = layout.find('node', attrs={'resource-id': 'com.google.android.calculator:id/result'})
    try:
        print('0.94571362288813'[:6] == target['text'][:6])
        return '0.94571362288813'[:6] == target['text'][:6]
    except:
        return False


def calculator_calculate_oracle(path):
    print("file path:", path)
    with open(path, 'rb') as f:
        layout = f.read()
    layout = BeautifulSoup(layout.decode(), 'lxml')
    target = layout.find('node', attrs={'resource-id': 'com.google.android.calculator:id/result'})
    try:
        print('29.2141519639433'[:6] == target['text'][:6])
        return '29.2141519639433'[:6] == target['text'][:6]
    except:
        return False


def reader_search_words_oracle(path):
    if 'original' in path:
        return True
    path2 = os.path.dirname(path)
    path1 = os.path.dirname(path2)
    path1 = os.path.join(path1, 'original')
    prefix = 'screenshot_'
    all_files = os.listdir(path1)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path1 = os.path.join(path1, file)

    prefix = 'screenshot_'
    all_files = os.listdir(path2)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path2 = os.path.join(path2, file)

    img1 = Image.open(path1)
    img1_crop = img1.crop((0, 100, 700, 1200))  # (left, upper, right, lower)
    img2 = Image.open(path2)
    img2_crop = img2.crop((0, 100, 700, 1200))

    diff = ImageChops.difference(img1_crop, img2_crop)

    stat = ImageStat.Stat(diff)
    diff_ratio = sum(stat.mean) / (len(stat.mean) * 255)

    print(diff_ratio)
    return diff_ratio < 0.01



def reader_change_mode_oracle(path):
    print("file path:", path)
    with open(path, 'rb') as f:
        layout = f.read()
    layout = BeautifulSoup(layout.decode(), 'lxml')
    target = layout.find('node', attrs={'resource-id': 'com.adobe.reader:id/dialog_switch_button'})
    try:
        print('ON' == target['text'])
        return 'ON' == target['text']
    except:
        return False


## 出现了一个小框
def reader_add_comment_oracle(path):
    if 'original' in path:
        return True
    path2 = os.path.dirname(path)
    path1 = os.path.dirname(path2)
    path1 = os.path.join(path1, 'original')
    prefix = 'screenshot_'
    all_files = os.listdir(path1)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path1 = os.path.join(path1, file)

    prefix = 'screenshot_'
    all_files = os.listdir(path2)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path2 = os.path.join(path2, file)

    img1 = Image.open(path1)
    img1_crop = img1.crop((0, 100, 700, 1200))  # (left, upper, right, lower)
    img2 = Image.open(path2)
    img2_crop = img2.crop((0, 100, 700, 1200))

    diff = ImageChops.difference(img1_crop, img2_crop)

    stat = ImageStat.Stat(diff)
    diff_ratio = sum(stat.mean) / (len(stat.mean) * 255)

    print(diff_ratio)
    return diff_ratio < 0.01


def sbb_touch_timetable_oracle(path):
    with open(path, 'rb') as f:
        layout = f.read()
    layout = BeautifulSoup(layout.decode(), 'lxml')
    target = layout.find('node', attrs={'resource-id': 'ch.sbb.mobile.android.b2c:id/departure'})
    target2 = layout.find('node', attrs={'resource-id': 'ch.sbb.mobile.android.b2c:id/destination'})
    try:
        print(target['content-desc'] == 'From: Olten' and target2['content-desc'] == 'To: Winterthur')
        return target['content-desc'] == 'From: Olten' and target2['content-desc'] == 'To: Winterthur'
    except:
        return False


def sbb_set_home_address_oracle(path):
    with open(path, 'rb') as f:
        layout = f.read()
    layout = BeautifulSoup(layout.decode(), 'lxml')
    target = layout.find('node', attrs={'resource-id': 'ch.sbb.mobile.android.b2c:id/departure'})
    target2 = layout.find('node', attrs={'resource-id': 'ch.sbb.mobile.android.b2c:id/destination'})
    try:
        print(target['content-desc'] == 'From: Zug, Metalli/Bahnhof' and target2[
            'content-desc'] == 'To: Lausanne, Victor-Ruffy')
        return target['content-desc'] == 'From: Zug, Metalli/Bahnhof' and target2[
            'content-desc'] == 'To: Lausanne, Victor-Ruffy'
    except:
        return False


def sbb_search_location_in_map_oracle(path):
    print("file path:", path)
    with open(path, 'rb') as f:
        layout = f.read()
    layout = BeautifulSoup(layout.decode(), 'lxml')
    target = layout.find('node', attrs={'resource-id': 'ch.sbb.mobile.android.b2c:id/departure'})
    target2 = layout.find('node', attrs={'resource-id': 'ch.sbb.mobile.android.b2c:id/destination'})
    try:
        print(target['content-desc'])
        return "From: Zug, Metalli/Bahnhof" == target['content-desc'] and target2['content-desc'] == "To: Lausanne, Victor-Ruffy"
    except:
        return False


def sbb_check_timetable_oracle(path):
    if 'original' in path:
        return True
    path2 = os.path.dirname(path)
    path1 = os.path.dirname(path2)
    path1 = os.path.join(path1, 'original')
    prefix = 'screenshot_'
    all_files = os.listdir(path1)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path1 = os.path.join(path1, file)

    prefix = 'screenshot_'
    all_files = os.listdir(path2)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path2 = os.path.join(path2, file)

    img1 = Image.open(path1)
    img1_crop = img1.crop((0, 100, 700, 1200))  # (left, upper, right, lower)
    img2 = Image.open(path2)
    img2_crop = img2.crop((0, 100, 700, 1200))

    diff = ImageChops.difference(img1_crop, img2_crop)

    stat = ImageStat.Stat(diff)
    diff_ratio = sum(stat.mean) / (len(stat.mean) * 255)

    print(diff_ratio)
    return diff_ratio < 0.01


def accuweather_check_weather_in_map_oracle(path):
    if 'original' in path:
        return True
    path2 = os.path.dirname(path)
    path1 = os.path.dirname(path2)
    path1 = os.path.join(path1, 'original')
    prefix = 'screenshot_'
    all_files = os.listdir(path1)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path1 = os.path.join(path1, file)

    prefix = 'screenshot_'
    all_files = os.listdir(path2)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path2 = os.path.join(path2, file)

    img1 = Image.open(path1)
    img1_crop = img1.crop((0, 100, 700, 1200))  # (left, upper, right, lower)
    img2 = Image.open(path2)
    img2_crop = img2.crop((0, 100, 700, 1200))

    diff = ImageChops.difference(img1_crop, img2_crop)

    stat = ImageStat.Stat(diff)
    diff_ratio = sum(stat.mean) / (len(stat.mean) * 255)

    print(diff_ratio)
    return diff_ratio < 0.01


## time
def accuweather_check_hourly_weather_oracle(path):
    print("file path:", path)
    with open(path, 'rb') as f:
        layout = f.read()
    layout = BeautifulSoup(layout.decode(), 'lxml')
    target = layout.find('node', attrs={'bounds': '[144,29][427,83]'})
    try:
        print(target['text'])
        return "Hourly Forecast" == target['text']
    except:
        return False


def accuweather_check_daily_weather_oracle(path):
    a = datetime.date.today()
    k = a.strftime("%#d/%#m")
    with open(path, 'rb') as f:
        layout = f.read()
    layout = BeautifulSoup(layout.decode(), 'lxml')
    target = layout.find('node', attrs={'resource-id': 'com.accuweather.android:id/daily_time'})

    try:
        print(target['text'][:4].strip(), k)

        return target['text'][:4].strip() == k
    except:
        return False


def search_city_oracle(path):
    if 'original' in path:
        return True
    path2 = os.path.dirname(path)
    path1 = os.path.dirname(path2)
    path1 = os.path.join(path1, 'original')
    prefix = 'screenshot_'
    all_files = os.listdir(path1)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path1 = os.path.join(path1, file)

    prefix = 'screenshot_'
    all_files = os.listdir(path2)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path2 = os.path.join(path2, file)

    img1 = Image.open(path1)
    img1_crop = img1.crop((0, 100, 700, 1200))  # (left, upper, right, lower)
    img2 = Image.open(path2)
    img2_crop = img2.crop((0, 100, 700, 1200))

    diff = ImageChops.difference(img1_crop, img2_crop)

    stat = ImageStat.Stat(diff)
    diff_ratio = sum(stat.mean) / (len(stat.mean) * 255)

    print(diff_ratio)
    return diff_ratio < 0.01

# Applicable to all traces starting with 'flow'
def flow_oracle(path):
    if 'original' in path:
        return True
    path2 = os.path.dirname(path)
    path1 = os.path.dirname(path2)
    path1 = os.path.join(path1, 'original')
    prefix = 'screenshot_'
    all_files = os.listdir(path1)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path1 = os.path.join(path1, file)

    prefix = 'screenshot_'
    all_files = os.listdir(path2)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path2 = os.path.join(path2, file)

    img1 = Image.open(path1)
    img1_crop = img1.crop((0, 100, 700, 1200))  # (left, upper, right, lower)
    img2 = Image.open(path2)
    img2_crop = img2.crop((0, 100, 700, 1200))

    diff = ImageChops.difference(img1_crop, img2_crop)

    stat = ImageStat.Stat(diff)
    diff_ratio = sum(stat.mean) / (len(stat.mean) * 255)

    print(diff_ratio)
    return diff_ratio < 0.01


def bbc_read_my_news_oracle(path):
    if 'original' in path:
        return True
    path2 = os.path.dirname(path)
    path1 = os.path.dirname(path2)
    path1 = os.path.join(path1, 'original')
    prefix = 'screenshot_'
    all_files = os.listdir(path1)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path1 = os.path.join(path1, file)

    prefix = 'screenshot_'
    all_files = os.listdir(path2)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path2 = os.path.join(path2, file)

    img1 = Image.open(path1)
    img1_crop = img1.crop((0, 100, 700, 1200))  # (left, upper, right, lower)
    img2 = Image.open(path2)
    img2_crop = img2.crop((0, 100, 700, 1200))

    diff = ImageChops.difference(img1_crop, img2_crop)

    stat = ImageStat.Stat(diff)
    diff_ratio = sum(stat.mean) / (len(stat.mean) * 255)

    print(diff_ratio)
    return diff_ratio < 0.01


def bbc_search_news_oracle(path):
    if 'original' in path:
        return True
    path2 = os.path.dirname(path)
    path1 = os.path.dirname(path2)
    path1 = os.path.join(path1, 'original')
    prefix = 'screenshot_'
    all_files = os.listdir(path1)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path1 = os.path.join(path1, file)

    prefix = 'screenshot_'
    all_files = os.listdir(path2)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path2 = os.path.join(path2, file)

    img1 = Image.open(path1)
    img1_crop = img1.crop((0, 100, 700, 1200))  # (left, upper, right, lower)
    img2 = Image.open(path2)
    img2_crop = img2.crop((0, 100, 700, 1200))

    diff = ImageChops.difference(img1_crop, img2_crop)

    stat = ImageStat.Stat(diff)
    diff_ratio = sum(stat.mean) / (len(stat.mean) * 255)

    print(diff_ratio)
    return diff_ratio < 0.01


def bbc_visit_popular_news_oracle(path):
    if 'original' in path:
        return True
    path2 = os.path.dirname(path)
    path1 = os.path.dirname(path2)
    path1 = os.path.join(path1, 'original')
    prefix = 'screenshot_'
    all_files = os.listdir(path1)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path1 = os.path.join(path1, file)

    prefix = 'screenshot_'
    all_files = os.listdir(path2)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path2 = os.path.join(path2, file)

    img1 = Image.open(path1)
    img1_crop = img1.crop((0, 100, 700, 1200))  # (left, upper, right, lower)
    img2 = Image.open(path2)
    img2_crop = img2.crop((0, 100, 700, 1200))

    diff = ImageChops.difference(img1_crop, img2_crop)

    stat = ImageStat.Stat(diff)
    diff_ratio = sum(stat.mean) / (len(stat.mean) * 255)

    print(diff_ratio)
    return diff_ratio < 0.01


def bbc_watch_videos_oracle(path):
    if 'original' in path:
        return True
    path2 = os.path.dirname(path)
    path1 = os.path.dirname(path2)
    path1 = os.path.join(path1, 'original')
    prefix = 'screenshot_'
    all_files = os.listdir(path1)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path1 = os.path.join(path1, file)

    prefix = 'screenshot_'
    all_files = os.listdir(path2)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path2 = os.path.join(path2, file)

    img1 = Image.open(path1)
    img1_crop = img1.crop((0, 100, 700, 1200))  # (left, upper, right, lower)
    img2 = Image.open(path2)
    img2_crop = img2.crop((0, 100, 700, 1200))

    diff = ImageChops.difference(img1_crop, img2_crop)

    stat = ImageStat.Stat(diff)
    diff_ratio = sum(stat.mean) / (len(stat.mean) * 255)

    print(diff_ratio)
    return diff_ratio < 0.01



def wikipedia_browse_trending_oracle(path):
    if 'original' in path:
        return True
    path2 = os.path.dirname(path)
    path1 = os.path.dirname(path2)
    path1 = os.path.join(path1, 'original')
    prefix = 'screenshot_'
    all_files = os.listdir(path1)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path1 = os.path.join(path1, file)

    prefix = 'screenshot_'
    all_files = os.listdir(path2)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path2 = os.path.join(path2, file)

    img1 = Image.open(path1)
    img1_crop = img1.crop((0, 100, 700, 1200))  # (left, upper, right, lower)
    img2 = Image.open(path2)
    img2_crop = img2.crop((0, 100, 700, 1200))

    diff = ImageChops.difference(img1_crop, img2_crop)

    stat = ImageStat.Stat(diff)
    diff_ratio = sum(stat.mean) / (len(stat.mean) * 255)

    print(diff_ratio)
    return diff_ratio < 0.01





def wikipedia_search_oracle(path):
    if 'original' in path:
        return True
    path2 = os.path.dirname(path)
    path1 = os.path.dirname(path2)
    path1 = os.path.join(path1, 'original')
    prefix = 'screenshot_'
    all_files = os.listdir(path1)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path1 = os.path.join(path1, file)

    prefix = 'screenshot_'
    all_files = os.listdir(path2)
    files = [file for file in all_files if file.startswith(prefix)]
    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    path2 = os.path.join(path2, file)

    img1 = Image.open(path1)
    img1_crop = img1.crop((0, 100, 700, 1200))  # (left, upper, right, lower)
    img2 = Image.open(path2)
    img2_crop = img2.crop((0, 100, 700, 1200))

    diff = ImageChops.difference(img1_crop, img2_crop)

    stat = ImageStat.Stat(diff)
    diff_ratio = sum(stat.mean) / (len(stat.mean) * 255)

    print(diff_ratio)
    return diff_ratio < 0.01






if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Argument Parser')
    parser.add_argument('--path', help='save path', required=True)
    args = parser.parse_args()
    path = args.path
    all_files = os.listdir(path)
    prefix = 'ui_'
    files = [file for file in all_files if file.startswith(prefix)]

    files = sorted(files, key=lambda x: int(x[len(prefix):-4]))
    file = files[-1]
    # file2 = files[-4]
    # file3 = files[-8]
    wikipedia_search_oracle(os.path.join(path, file))