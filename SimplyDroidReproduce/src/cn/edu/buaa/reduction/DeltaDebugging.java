package cn.edu.buaa.reduction;

import java.io.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import cn.edu.buaa.ReductionRunner;
// import cn.edu.buaa.command.AdbOperation;
import cn.edu.buaa.state.EventQueueOperation;
import cn.edu.buaa.state.EventState;
import cn.edu.buaa.util.GenerateScript;
import cn.edu.buaa.util.MD5;

public class DeltaDebugging {
	private static final int TESTCASE_DELTA = 0;
	private static final int TESTCASE_GRADIENT = 1;
	private List<EventState> eQueue = new ArrayList<EventState>();
	// private String crash = null;

	private Set<String> failedSet = new HashSet<String>();

	String index;

	public DeltaDebugging() {
		index = "";
	}

	public DeltaDebugging(String idx) {
		index = idx;
	}

	//The method of DD reduction entrance
	public void reduce(){
		System.out.println("Trace " + index + " DD. Start.");
		long startTime = System.currentTimeMillis();

		//read the log files and extract crash information
		EventQueueOperation eopt = new EventQueueOperation();
		eQueue = eopt.readLog(ReductionRunner.generateOriginPath(index));
		// crash = eopt.getCrash(ReductionRunner.generateOriginPath(index) + "execute.log");

		// if(crash != null && !crash.equals("")){
		// List<EventState> ddList = new ArrayList<EventState>(eQueue);
		// 	ddList.remove(0);
		// 	// run the DD reduction
		// 	ddmin(ddList, 2);
		// }
		// else
		// 	System.out.println("Something wrong while getting crash info.");
		List<EventState> ddList = new ArrayList<EventState>(eQueue);
		ddmin(ddList, 2);

		long endTime = System.currentTimeMillis();
		//calculate the time used while reduction completed
		System.out.println("Trace " + index + " DD. Time used : " + (endTime - startTime) + "ms");
		ReductionRunner.calculateTime(endTime - startTime);
		System.out.println("------------------------------------------------");
	}

	//The method to do reduction on a given event sequence
	private void ddmin(List<EventState> tmpQueue, int partition){
		System.out.println("Current queue len: " + tmpQueue.size() + ", partition: " + partition);

		//while there is only 1 event in the sequence, stop the reduction
		if(tmpQueue.size() == 1)
			return;
		boolean succ = false;

		//first attempt each partition of the sequence
		succ = execDeltaOrGrad(tmpQueue, partition, TESTCASE_DELTA);
		if(succ) return;

			//if every attempt failed, then attempt each complement
		else succ = execDeltaOrGrad(tmpQueue, partition, TESTCASE_GRADIENT);
		if(succ) return;

		//if still failed, attempt finer partition
		if(!succ && partition < tmpQueue.size()) {
			ddmin(tmpQueue, Math.min(tmpQueue.size(), 2 * partition));
		}
		return;
	}

	//The method to attempt reduction on a partition or complement
	private boolean execDeltaOrGrad(List<EventState> tmpQueue, int partition, int type){
		List<EventState> currList = tmpQueue;
		int partsize = (currList.size() + 1) / partition;
		boolean succ = false, isCrash = false;
		String sign = null;

		for(int i = 0; i < partition; i++){
			//generate the event sequence for reduction attempt
			List<EventState> tmp = createNewEventList(currList, i, partsize, type);

			//skip those event sequences that have been executed and verified as failed attempt
			sign = MD5.getMD5(tmp);
			if(failedSet.contains(sign)) continue;

			//execute the event sequence on testing phone and check whether same crash is reproduced
			isCrash = executeEventList(tmp);
			if(isCrash){
				succ = true;
				//if reduction attempt succeed, call the method of reduction recursively
				if(type == TESTCASE_DELTA) {
					ddmin(tmp, 2);
				} else {
					ddmin(tmp, Math.max(partition - 1, 2));
				}
				break;
			} else {
				if(!failedSet.contains(sign))
					failedSet.add(sign);
			}
		}
		return succ;
	}

	//The method to call the conversion from event sequence to script file
	// private void printResult(List<EventState> list){
	// 	List<EventState> tmp = new ArrayList<EventState>(list);
	// 	// tmp.add(0, eQueue.get(0));
	// 	EventQueueOperation eqo = new EventQueueOperation();
	// 	eqo.printScript(tmp, ReductionRunner.generateResultPath(index, 1));
	// }

	//The method to execute a event sequence on testing phone and check whether same crash is reproduced
	private boolean executeEventList(List<EventState> list){
//		try {
//			System.out.println("python C:\\Users\\Administrator\\Desktop\\simplydroid\\SimpliDroidReproduce\\input\\accuweather_check_hourly_weather_restore.py"+" --package "+ReductionRunner.generatePackage()+" --main_activity "+ReductionRunner.generateMainActivity());
//			Process process = Runtime.getRuntime().exec("python C:\\Users\\Administrator\\Desktop\\simplydroid\\SimpliDroidReproduce\\input\\accuweather_check_hourly_weather_restore.py"+" --package "+ReductionRunner.generatePackage()+" --main_activity "+ReductionRunner.generateMainActivity());
//			process.waitFor();
//
//		} catch (Exception e) {
//			e.printStackTrace();
//		}


		System.out.println("===========================Starting a new trial=================================");
		// printResult(list);

		// Generate RPA script
		String trialFilePath = ReductionRunner.generateTrialFilePath(index);
		GenerateScript.generateScript(list, trialFilePath);

		// Run the generated script
		String result = "";
        try {
            Process process = Runtime.getRuntime().exec("python "+trialFilePath+" --path "+trialFilePath.replace(".py","")+" --package "+ReductionRunner.generatePackage()+" --main_activity "+ReductionRunner.generateMainActivity());
            InputStreamReader ir = new InputStreamReader(process.getInputStream());
            LineNumberReader input = new LineNumberReader(ir);
            String line;
			while ((line = input.readLine()) != null) {
                result = result+line+"\n";
            }
            input.close();
            ir.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

		// Check whether the script satisfies the RPA requirement
		result = "";
        try {
            Process process = Runtime.getRuntime().exec("python "+ReductionRunner.getOracleFile()+" --path "+trialFilePath.replace(".py",""));
			System.out.println("python "+ReductionRunner.getOracleFile()+" --path "+trialFilePath.replace(".py",""));
			process.waitFor();
			BufferedReader input = new BufferedReader(new InputStreamReader(process.getInputStream()));
			String line;
			while ((line = input.readLine()) != null) {
                result = result+line+"\n";
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
			throw new RuntimeException(e);
		}
		System.out.println(result);
		if (result.contains("True")){
			System.out.println("Oracle passed");

			File fp = new File(trialFilePath.split("trial")[0]+"oracle_passed.txt");
			try {
				if(!fp.exists()){
					fp.createNewFile();
				}
				FileWriter fpWriter = new FileWriter(fp, true);
				fpWriter.write("File name: "+trialFilePath+" length: "+list.size()+"\n");
				fpWriter.close();
			} catch (IOException e) {
				e.printStackTrace();
			}

			return true;
		}
		System.out.println("Oracle failed");
		return false;
	}

	//The method to generate event sequence through given original sequence and parameters
	private List<EventState> createNewEventList(List<EventState> queue, int idx, int size, int type){
		List<EventState> res = new ArrayList<EventState>();
		//for the partition, add all events within the given partition to attempt event sequence
		if(type == TESTCASE_DELTA){
			for(int i = idx * size; i < Math.min(queue.size(), (idx+1) * size); i++){
				res.add(queue.get(i));
			}
		}
		//for the complement, add all events except the given partition to attempt event sequence
		if(type == TESTCASE_GRADIENT){
			for(int i = 0; i < queue.size(); i++){
				if(i < idx * size || i >= (idx+1) * size){
					res.add(queue.get(i));
				}
			}
		}
		return res;
	}


}
