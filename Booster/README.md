# Booster

This folder contains the source code of Booster, implemented using Python and work with SARA on Android platform.

## Environment

- Python 3.7/3.8;
- Manually install necessary libraries, or run the following command:

```
pip install -r requirements.txt
```

- Connect an Android Emulator or physical device through ADB;
  - In our experiment, we configured an emulator with Android 9.0 x86 image, 4 cores, and 2GB RAM;
- Necessary environments required by SARA.

## Usage

- Change the app package name, app main activity, script path, recover script path (leave it empty if the trace subject does not need recovery), and oracle to be used in config.py. The package name and main activity name of our app subjects are provided in config.py;
- Change the "level" attribute in main.py to change the state abstract function (SAF) used for constructing state machine graph. Level 2 is our default SAF, while level 1, 3, and 4 are for the comparison in RQ2. The users can also implement their own SAF in the state_abstraction.py;
- Start your emulator or physical device. For example, run the following command:

```
emulator -avd [EmulatorName] -gpu swiftshader_indirect
```

- Run main.py

```
python main.py
```

## Oracles

We use screenshots as oracle for the image-related traces and the traces with unstable running results, comparing the last step of original execution with the last step of each trials.

For those traces that are more stable, we query the UI layout xml file to check whether the oracle passed.

All oracles are written in the oracle.py, with each oracle corresponding to a trace, and sharing the same name with the corresponding trace. Note that the flow_oracle(path) is for all the 5 traces of FlowFree.
