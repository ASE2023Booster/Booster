'''
package and main activity

config = {
    'accuweather': ['com.accuweather.android','com.accuweather.app.MainActivity'],
    'adobe': ['com.adobe.reader','.AdobeReader'],
    'BBC': ['bbc.mobile.news.ww','bbc.mobile.news.v3.app.TopLevelActivity'],
    'calculator': ['com.google.android.calculator','com.android.calculator2.Calculator'],
    'Flow': ['com.bigduckgames.flow','.flow'],
    'sbb': ['ch.sbb.mobile.android.b2c','ch.sbb.mobile.android.vnext.splashscreen.SplashScreenActivity'],
    'snapseed': ['com.niksoftware.snapseed','com.google.android.apps.snapseed.MainActivity'],
    'VLC': ['org.videolan.vlc', '.StartActivity'],
    'textgram': ['codeadore.textgram', '.MainActivity'],
    'wikipedia': ['org.wikipedia','.main.MainActivity'],
}

'''

import oracles

class Config:
    def __init__(self):
        self.package = r"com.accuweather.android"
        self.main_activity = r"com.accuweather.app.MainActivity"
        self.script_path = r".\input\accuweather\accuweather_check_daily_weather_replay_reproduce.py"
        self.restore=r'.\input\accuweather\accuweather_check_daily_weather_restore.py'

    def oracle(path):
        return oracles.accuweather_check_daily_weather_oracle(path)