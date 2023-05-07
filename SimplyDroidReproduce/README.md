# SimplyDroid
This project is forked from this Github repo: https://github.com/gongbell/SimplyDroid ; of paper: SimplyDroid: Efficient Event Sequence Simplification for Android Application (Hierarchical Delta Debugging for Monkey input events), published in ASE 2017. For detailed usage, please refer to the original repo.

## Changes

In our evaluation, we adopt the trace reduction part of SimplyDroid, while using the DD and LHDD algorithms as baselines for comparison.

We make minor changes to the inputs and outputs of SimplyDroid to apply SimplyDroid to RPA traces. The main changes are as follows:

- Delete several unnecessary attributes in src.cn.edu.buaa.state.EventState.java;

- Add "readSARAFile" function in src.cn.edu.buaa.state.EventQueueOperation.java to read SARA traces;

- Add "generatePackage", "generateMainActivity", "getOracleFile" functions in src.cn.edu.buaa.ReductionRunner.java as global configuration; Modify "main" function to let the program run with SARA;

- Add GenerateScript.java in src.cn.edu.buaa.util package to generate SARA scripts;

- Modify the "reduce" and "executeEventList" functions in the JAVA file for each algorithm in the src.cn.edu.buaa.reduction package to let these algorithms generate and trial with SARA scripts.

  

## Usage

#### Environment

- JAVA 8
- Python environment required by SARA
- ADB, connected with Android Emulators or physical devices

#### Configuration

- Change the LOCAL_PATH attribute and paths and file names in "generatePackage", "generateMainActivity", "getOracleFile" functions of cn.edu.buaa.ReductionRunner.java;
- Change the reduction type and trace name in the main function of cn.edu.buaa.ReductionRunner.java;
- Change the source script path of SARA in cn.edu.buaa.util.GenerateScript.java

#### Run

- Run the main function in cn.edu.buaa.ReductionRunner.java



## Common Error

1. We use a subprocess, calling Python to run each trial and return results. Therefore, the return value is passed back and checked in the string type. If the trial result is always False, please check whether the checking result is printed to the console.
2. The subprocess of JAVA has a buffer limit. If the whole process is stuck while executing a trial, please remove the console logs or outputs in SARA scripts.



