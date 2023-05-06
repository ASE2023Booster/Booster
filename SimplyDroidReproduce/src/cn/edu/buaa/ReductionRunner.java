package cn.edu.buaa;

import cn.edu.buaa.reduction.DeltaDebugging;
import cn.edu.buaa.reduction.HierarchicalDeltaDebugging;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import cn.edu.buaa.reduction.BalancedHierarchicalDeltaDebugging;
import cn.edu.buaa.reduction.LocalHierarchicalDeltaDebugging;

public class ReductionRunner {

	//The root path of test case files within testing host
	public final static String LOCAL_PATH = "C:\\Users\\Administrator\\Desktop\\simplydroid\\SimpliDroidReproduce\\";

	//The directory of monkey files within testing phone
	public final static String DEVICE_MONKEY_PATH = "/data/local/";

	//The root directory of external storage within testing phone
	public final static String DEVICE_TMP_PATH = "/storage/emulated/0/";

	//The ID to distinguish testing phones used by ADB Shell
	public final static String DEVICE_ID = "";

	//The package name of the application to run test case on
	public final static String PACKAGE_NAME = "";

	//The time interval between events in test case while executed
	public final static int THROTTLE_TIME_MS = 800;

	//The number of crash traces to run reduction on
	public final static int TRACE_NUMBER = 1;

	//Choice for algorithm to run the reduction
	public final static boolean DO_DD = true;
	public final static boolean DO_HDD = true;
	public final static boolean DO_IHDD = true;
	public final static boolean DO_LHDD = true;

	//Choice for whether utilize extra check in LHDD
	public final static boolean NEED_EXTRACHECK = false;

	public static String outputFolderName = "";


	//The method to convert time(ms) into minutes and seconds
	public static void calculateTime(long ms){
		long day = ms / (24 * 60 * 60 * 1000);
		ms %= 24 * 60 * 60 * 1000;
		long hour = ms / (60 * 60 * 1000);
		ms %= 60 * 60 * 1000;
		long minute = ms / (60 * 1000);
		ms %= 60 * 1000;
		long second = ms / 1000;
		System.out.println(day + " d " + hour + " h " + minute + " m " + second + " s.");
	}

	public static String generateOutputFolderPath(String index) {
		return LOCAL_PATH + "output\\" + index;
	}

	//The method to get the path of folder origin
	public static String generateOriginPath(String index) {
		return index + "\\original";
	}

	public static String generateTrialFilePath(String path) {
		for (int i=0;i<500;i++){
			File f = new File(path + "\\trial"+Integer.toString(i)+".py");
			if (!f.exists()){
				return path + "\\trial"+Integer.toString(i)+".py";
			}
		}
		return null;
	}

	public static String getLatestTrialFilePath(String path) {
		for (int i=0;i<500;i++){
			File f = new File(path + "\\trial"+Integer.toString(i)+".py");
			if (!f.exists()){
				if (i==0) return null;
				return path + "\\trial"+Integer.toString(i-1)+".py";
			}
		}
		return null;
	}

	public static String generatePackage(){
		return "com.niksoftware.snapseed";
	}

	public static String generateMainActivity(){
		return "com.google.android.apps.snapseed.MainActivity";
	}

	public static String getOracleFile(){
		return "C:\\Users\\Administrator\\Desktop\\simplydroid\\SimpliDroidReproduce\\oracles.py";
	}


	//The method to start the reduction
	public static void main(String[] args) {

		String reductionType = "DD";

		// Make output dir
		String traceName = "snapseed_apply_face_filters_replay_reproduce";

		LocalDateTime myDateObj = LocalDateTime.now();
		DateTimeFormatter myFormatObj = DateTimeFormatter.ofPattern("YYYY_MM_dd_HH_mm_ss");
		String formattedDate = myDateObj.format(myFormatObj);

		outputFolderName = reductionType+"_"+traceName+"_"+formattedDate;
//		System.out.println(outputFolderName);


		String outputFolderPath = generateOutputFolderPath(outputFolderName);
//		System.out.println(outputFolderPath);


		File outputFolder = new File(outputFolderPath);
		if(outputFolder.exists()){
			outputFolder.delete();
		}
		outputFolder.mkdirs();

		// Copy essential files
		String SARAPath = outputFolderPath+"\\sara_script";
		File SARAScripts = new File(SARAPath);
		SARAScripts.mkdirs();

		File saraUtil1 = new File(LOCAL_PATH+"sara_script\\parse_view_hierarchy.py");
		File saraUtil2 = new File(LOCAL_PATH+"sara_script\\util.py");
		File saraOutUtil1 = new File(outputFolderPath+"\\sara_script\\parse_view_hierarchy.py");
		File saraOutUtil2 = new File(outputFolderPath+"\\sara_script\\util.py");
		File originalScript = new File(LOCAL_PATH+"input\\"+traceName+".py");
		File outputOriginalScript = new File(outputFolderPath+"\\original.py");
		try {
			Files.copy(saraUtil1.toPath(), saraOutUtil1.toPath());
			Files.copy(saraUtil2.toPath(), saraOutUtil2.toPath());
			Files.copy(originalScript.toPath(), outputOriginalScript.toPath());
		} catch (Exception e) {
			e.printStackTrace();
		}

		// Execute origin script for original data
		String trialFilePath = outputFolderPath+"\\original.py";
		System.out.println("python "+trialFilePath+" --path "+trialFilePath.replace(".py","")+" --package "+ReductionRunner.generatePackage()+" --main_activity "+ReductionRunner.generateMainActivity());
        try {
            Process process = Runtime.getRuntime().exec("python "+trialFilePath+" --path "+trialFilePath.replace(".py","")+" --package "+ReductionRunner.generatePackage()+" --main_activity "+ReductionRunner.generateMainActivity());
			process.waitFor();

		} catch (Exception e) {
            e.printStackTrace();
        }




		switch(reductionType) {
				case "DD":
					DeltaDebugging dd = new DeltaDebugging(outputFolderPath);
					dd.reduce();
					break;
				case "HDD":
					HierarchicalDeltaDebugging hdd = new HierarchicalDeltaDebugging(outputFolderPath);
					hdd.reduce();
					break;
				case "BHDD":
					BalancedHierarchicalDeltaDebugging ihdd = new BalancedHierarchicalDeltaDebugging(outputFolderPath);
					ihdd.reduce();
					break;
				case "LHDD":
					LocalHierarchicalDeltaDebugging lhdd = new LocalHierarchicalDeltaDebugging(outputFolderPath);
					lhdd.reduce();
					break;
			}
		}

}
