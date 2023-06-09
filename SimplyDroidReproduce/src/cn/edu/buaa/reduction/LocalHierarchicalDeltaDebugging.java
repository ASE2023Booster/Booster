package cn.edu.buaa.reduction;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.LineNumberReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

//import org.w3c.dom.Node;

import cn.edu.buaa.ReductionRunner;
// import cn.edu.buaa.command.AdbOperation;
import cn.edu.buaa.state.EventQueueOperation;
import cn.edu.buaa.state.EventState;
import cn.edu.buaa.util.GenerateScript;
import cn.edu.buaa.util.MD5;

public class LocalHierarchicalDeltaDebugging {
	private static final int TESTCASE_DELTA = 0;
	private static final int TESTCASE_GRADIENT = 1;
	private Set<String> failedSet = new HashSet<String>();
	private List<Integer> minConfig = new ArrayList<Integer>();
	private List<EventState> upSubList = new ArrayList<EventState>();
	private HashMap<Integer, ArrayList<EventState>> downSubListMap = new HashMap<Integer, ArrayList<EventState>>();
	private List<EventState> lastSubList = new ArrayList<EventState>();
	private List<Integer> downSubListGroup = new ArrayList<Integer>();

	private List<EventState> eQueue = new ArrayList<EventState>();
	// private String crash = null;
	private String targetActivity = null;
	private HddTreeNode root = null;
	private ArrayList<HddTreeNode> nodeList = new ArrayList<HddTreeNode>();

	int level;
	int maxlevel;
	int sublistsize;
	String index;
	boolean includecheck = false;
	boolean needBHDD = false;

	public LocalHierarchicalDeltaDebugging() {
		index = "";
	}

	public LocalHierarchicalDeltaDebugging(String idx) {
		index = idx;
	}

	//The method of LHDD reduction entrance
	public void reduce(){
		System.out.println("Trace " + index + " LHDD. Start.");
		long startTime = System.currentTimeMillis();

		//read the log files and extract crash information
		EventQueueOperation eopt = new EventQueueOperation();
		eQueue = eopt.readLog(ReductionRunner.generateOriginPath(index));
		// crash = eopt.getCrash(ReductionRunner.generateOriginPath(index) + "execute.log");
		// if(crash != null && !crash.equals(""))
		// {
		// 	root = new HddTreeNode();
		// 	//build the hierarchy tree
		// 	createHddTree(root, eQueue);
		// 	//record the level of the last node within hierarchy tree
		// 	maxlevel = nodeList.get(nodeList.size() - 1).getLevel();
		// 	//run the LHDD reduction
		// 	hdd(root);
		// }
		// else
		// 	System.out.println("Something wrong while getting crash info.");

		// for (int i=0;i<eQueue.size();i=i+1){
		// 	System.out.println(eQueue.get(i).getIndex());
		// 	System.out.println(eQueue.get(i).getActivity());
		// 	System.out.println();
		// }

		root = new HddTreeNode();
		//build the hierarchy tree
		createHddTree(root, eQueue);
		//record the level of the last node within hierarchy tree
		maxlevel = nodeList.get(nodeList.size() - 1).getLevel();
		System.out.println("Maxlevel: "+maxlevel);
		//run the LHDD reduction
		hdd(root);

		long endTime = System.currentTimeMillis();
		//calculate the time used while reduction completed
		System.out.println("Trace " + index + " LHDD. Time used : " + (endTime - startTime) + "ms");
		ReductionRunner.calculateTime(endTime - startTime);
		System.out.println("------------------------------------------------");
	}

	//The method to build the hierarchy tree
	private void createHddTree(HddTreeNode root, List<EventState> list){
		root.setIdx(1);
		root.setLevel(0);
		root.setEvent(list.get(0).getEvent());
		root.setState(list.get(0).getActivity());
		root.setParentNode(null);
		nodeList.add(null);
		nodeList.add(root);

		maxlevel = 0;

		int i;
		HddTreeNode thisNode,lastNode,seekNode;
		lastNode=root;
		for(i=1; i<list.size(); i++) {
			//establish new node for each element in event sequence
			thisNode = new HddTreeNode(i+1, -1, list.get(i).getEvent(), list.get(i).getActivity(), null, new ArrayList<HddTreeNode>());
			//search a node having same state information within the route from last node to root node
			for(seekNode=lastNode; ; seekNode=seekNode.getParentNode()) {
				//searching failed, set new node as a child node of last node
				if(seekNode.getIdx() == 1) {
					thisNode.setParentNode(lastNode);
					lastNode.addChildNode(thisNode);
					thisNode.setLevel(lastNode.getLevel() + 1);
					break;
				}
				//searching succeed, set new node as a sibling node of target node
				if(seekNode.getState().equals(thisNode.getState())) {
					thisNode.setParentNode(seekNode.getParentNode());
					seekNode.getParentNode().addChildNode(thisNode);
					thisNode.setLevel(seekNode.getLevel());
					break;
				}
			}
			nodeList.add(thisNode);
			lastNode = thisNode;
		}
	}

	//The method to manage the reduction within hierarchy tree
	private void hdd(HddTreeNode root){
		level = 1;

		//tag nodes within level 1
		List<Integer> curNodes = new ArrayList<Integer>();
		curNodes.add(root.getIdx());
		List<Integer> nodes = tagNodes(curNodes);
		List<Integer> nodesincluded = null;

		//do reduction level by level until there is no node in next level
		while(nodes.size() != 0){
			needBHDD = false;
			//generate event sequence of nodes above the level doing reduction on now
			upSubList = createUpSubList();
			//generate event sequences matching to the subtree of each node except the last node within the
			//level doing reduction on now
			downSubListMap.clear();
			int i = 0;
			for(i = 0; i<nodes.size()-1; i++){
				sublistsize=0;
				downSubListMap.put(nodes.get(i), createDownSubList(nodes.get(i)));
				nodeList.get(nodes.get(i)).setSubtreenodes(sublistsize);
			}
			//for the last node within the level, the subtree is not considered at first
			downSubListMap.put(nodes.get(i), new ArrayList<EventState>(eQueue.subList(nodes.get(i) - 1, nodes.get(i))));
			sublistsize = 0;
			lastSubList = createDownSubList(nodes.get(i));
			nodeList.get(nodes.get(i)).setSubtreenodes(sublistsize);

			//record target activity while the level now is above the level of last node
			if(level < maxlevel)
				targetActivity = nodeList.get(nodes.get(nodes.size() - 1) + 1).getState();
			else
				targetActivity = null;
			System.out.println("level: " + level + "  Target: " + targetActivity);

			if(level <= maxlevel)
				//begin preselecting while the level now is not under the level of last node
				nodesincluded = includeNodes(nodes);
			else {
				//use BHDD to do reduction within this level while the level now is under the level of last node
				nodesincluded = new ArrayList<Integer>(nodes);
				needBHDD = true;
				downSubListMap.remove(nodes.get(nodes.size() - 1));
				downSubListMap.put(nodes.get(nodes.size() - 1), (ArrayList<EventState>) lastSubList);
			}

			//do reduction on nodes within this level
			ddmin(nodesincluded);
			//after reduction eliminate useless nodes from hierarchy tree
			pruneHddTree(nodes);
			level++;
			//tag nodes in next level
			nodes = tagNodes(minConfig);    //����²�������ڵ�
		}
		executeEventList(null);
	}

	//The method to return node index sequence of all the child nodes of given nodes
	private List<Integer> tagNodes(List<Integer> config){
		List<Integer> nodes = new ArrayList<Integer>();
		int i,j;
		for(i=0; i<config.size();i++)
			for(j=0; j<nodeList.get(config.get(i)).getChildNodes().size(); j++)
				nodes.add(nodeList.get(config.get(i)).getChildNodes().get(j).getIdx());
		return nodes;
	}

	//The method to preselect nodes
	private List<Integer> includeNodes(List<Integer> nodes){
		List<Integer> nodesNeed = new ArrayList<Integer>();
		nodesNeed.add(nodes.get(nodes.size() - 1));
		List<EventState> nodesTry = null;
		//set default preselecting length as 1
		int length = 1;
		String sign = null;

		do{
			System.out.println("Pretreatment, length: " + length);
			//orderly insert to the event sequence all events within each event sequence matching to the
			//preselected nodes to generate the attempt event sequence
			nodesTry = new ArrayList<EventState>(upSubList);
			for(int i = 0, j = 0; i < nodesNeed.size(); i++) {
				int idx = downSubListMap.get(nodesNeed.get(i)).get(0).getIndex();
				while(j<nodesTry.size() && nodesTry.get(j).getIndex() < idx)
					j++;
				nodesTry.addAll(j, downSubListMap.get(nodesNeed.get(i)));
				j+=downSubListMap.get(nodesNeed.get(i)).size();
			}
			sign = MD5.getMD5(nodesTry);

			//execute the event sequence on testing phone and check whether target activity is arrived
			if(executeEventList(nodesTry)) {
				//if preselection succeed and there is need for extra check
				if(ReductionRunner.NEED_EXTRACHECK) {
					System.out.println("Check pretreatment result");
					//do extra check
					if(CheckIncludeResult(nodesTry))
						break;
					else {
						//use BHDD to do reduction within this level while extra check is not passed
						System.out.println("Pretreatment failed, start BHDD");
						needBHDD = true;
						downSubListMap.remove(nodes.get(nodes.size() - 1));
						downSubListMap.put(nodes.get(nodes.size() - 1), (ArrayList<EventState>) lastSubList);
						return nodes;
					}
				} else
					//return the preselecting result nodes
					break;
			}

			if(!failedSet.contains(sign))
				failedSet.add(sign);

			//if preselection failed then double the preselecting length
			length = length * 2;
			if(length > nodes.size()) {
				//use BHDD to do reduction within this level while no preselection succeed until the preselecting
				//length reach the number of nodes within this level
				System.out.println("Pretreatment failed, start BHDD");
				needBHDD = true;
				downSubListMap.remove(nodes.get(nodes.size() - 1));
				downSubListMap.put(nodes.get(nodes.size() - 1), (ArrayList<EventState>) lastSubList);
				return nodes;
			}
			nodesNeed = new ArrayList<Integer>(nodes.subList(nodes.size() - length, nodes.size()));
		}while(length < nodes.size());
		return nodesNeed;
	}

	//The method to do extra check on preselecting result nodes
	private boolean CheckIncludeResult(List<EventState> nodes) {
		includecheck = true;
		//remove the last event and add the event sequence matching to the subtree of last node
		nodes.remove(nodes.size() - 1);
		nodes.addAll(lastSubList);

		//check whether same crash is reproduced
		return executeEventList(nodes);
	}

	//The method to manage the generation of event sequence of nodes above the level now
	private ArrayList<EventState> createUpSubList(){
		ArrayList<EventState> list = new ArrayList<EventState>();
		AddUpEventState(list, nodeList.get(1));
		return list;
	}

	//The method to add events to the event sequence of nodes above the level now recursively
	private void AddUpEventState(ArrayList<EventState> currList, HddTreeNode currNode){
		currList.add(eQueue.get(currNode.getIdx()-1));
		if(level == currNode.getLevel()+1)
			return;
		int i;
		for(i=0; i<currNode.getChildNodes().size(); i++)
			AddUpEventState(currList, currNode.getChildNodes().get(i));
		return;
	}

	//The method to manage the generation of event sequence matching to the subtree of a given node
	private ArrayList<EventState> createDownSubList(int idx) {
		ArrayList<EventState> list = new ArrayList<EventState>();
		AddDownEventState(list, nodeList.get(idx));
		return list;
	}

	//The method to add events to the event sequence matching to the subtree of a given node recursively
	private void AddDownEventState(ArrayList<EventState> currList, HddTreeNode currNode) {
		currList.add(eQueue.get(currNode.getIdx()-1));
		sublistsize++;
		int i;
		for(i=0; i<currNode.getChildNodes().size(); i++)
			AddDownEventState(currList, currNode.getChildNodes().get(i));
		return;
	}

	//The method to eliminate useless nodes from hierarchy tree
	private void pruneHddTree(List<Integer> nodes){
		List<Integer> temp = new ArrayList<Integer>(nodes);
		//tag useless nodes
		temp.removeAll(minConfig);
		//then remove these nodes as well as their subtree recursively
		int i,j;
		for(i=0; i<temp.size(); i++) {
			j = temp.get(i);
			nodeList.get(j).getParentNode().getChildNodes().remove(nodeList.get(j));
			destroyChildNodes(j);
		}
	}

	//The method to remove a node as well as nodes in its subtree recursively
	private void destroyChildNodes(int idx){
		int i;
		nodeList.get(idx).setParentNode(null);
		for(i=0; i<nodeList.get(idx).getChildNodes().size(); i++) {
			destroyChildNodes(nodeList.get(idx).getChildNodes().get(i).getIdx());
		}
		nodeList.get(idx).getChildNodes().clear();
		nodeList.remove(idx);
		nodeList.add(idx, null);
		return;
	}

	//The method to initialize reduction on a given node sequence in hierarchy tree
	private void ddmin(List<Integer> nodes){
		minConfig = new ArrayList<Integer>(nodes);
		//begin the reduction formally
		ddmin(nodes, 2);
		return;
	}

	//The method to do reduction on a given node sequence
	private void ddmin(List<Integer> nodes, int part){
		System.out.println("EQ: " + nodes.size() + ", partition: " + part);

		//while there is only 1 node in the sequence, stop the reduction
		if(nodes.size() == 1)
			return;
		//ensure that the number of partition would not exceed the number of nodes in the sequence
		if(nodes.size() < part)
			part=nodes.size();
		//divide the nodes into several partitions while use BHDD
		if(needBHDD)
			setDownSubListGroup(nodes, part);
		boolean succ = false;

		//first attempt each partition of the sequence
		succ = execDeltaOrGrad(nodes, part, TESTCASE_DELTA);
		if(succ) return;

			//if every attempt failed, then attempt each complement
		else succ = execDeltaOrGrad(nodes, part, TESTCASE_GRADIENT);
		if(succ) return;

		//if still failed, attempt finer partition
		if(!succ && part < nodes.size()) {    //��ʧ�ܣ����ӷֶ���
			ddmin(nodes, Math.min(nodes.size(), 2 * part));
		}
		return;
	}

	//The method to calculate the partition scheme that ensure the total number of nodes within subtrees
	//of nodes in each partition is as approaching as possible
	private void setDownSubListGroup(List<Integer> nodes, int part) {
		int i,l,n=0;
		float avgsize;

		//calculate number of nodes in all subtrees
		for(i=0; i<nodes.size(); i++){
			n += nodeList.get(nodes.get(i)).getSubtreenodes();
		}
		avgsize = (float)n / part;
		downSubListGroup.clear();

		//add the index of the first node in each partition into a sequence
		for(i=0, l=nodes.size()-part, n=0; i<nodes.size(); i++){
			if(l == 0){
				downSubListGroup.add(i);
				continue;
			}
			n += nodeList.get(nodes.get(i)).getSubtreenodes();
			if(n >= avgsize){
				n = 0;
				downSubListGroup.add(i);
				continue;
			}
			l--;
		}
	}

	//The method to attempt reduction on a partition or complement
	private boolean execDeltaOrGrad(List<Integer> tmpQueue, int partition, int type){
		List<Integer> currList = tmpQueue;
		List<Integer> attpList = new ArrayList<Integer>();
		int partsize = (currList.size() + 1) / partition;
		boolean succ = false, isCrash = false;
		String sign = null;

		//skip those partitions or complements that do not contain last node automatically
		for(int i = ((type == TESTCASE_DELTA)? partition-1: partition-2); i >= ((type == TESTCASE_DELTA)? partition-1:0); i--){
			List<EventState> tmp = null;
			//generate the event sequence for reduction attempt
			if(needBHDD)
				tmp = createEventList(currList, i, type, attpList);
			else
				tmp = createEventList(currList, i, partsize, type, attpList);

			//skip those event sequences that have been executed and verified as failed attempt
			sign = MD5.getMD5(tmp);
			if(failedSet.contains(sign)) continue;

			//execute the event sequence on testing phone and check whether the attempt is succeed
			isCrash = executeEventList(tmp);
			if(isCrash){
				succ = true;
				//if reduction attempt succeed, record the attempt node sequence
				minConfig = new ArrayList<Integer>(attpList);
				//and call the method of reduction recursively
				if(type == TESTCASE_DELTA) {
					ddmin(attpList, 2);
				} else {
					ddmin(attpList, Math.max(partition - 1, 2));
				}
				break;
			} else {    //��CRASH�޷����֣�����ʧ�ܼ���
				if(!failedSet.contains(sign))
					failedSet.add(sign);
			}
		}
		return succ;
	}

	//The method to generate event sequence through given original node sequence and parameters
	//Note that this method is used for HDD algorithm originally
	private List<EventState> createEventList(List<Integer> queue, int idx, int size, int type, List<Integer> queuer){
		List<EventState> res = new ArrayList<EventState>(upSubList);
		queuer.clear();
		int i,j,k;

		//for the partition, add to event sequence all events within the event sequences matching to
		//the subtree of nodes within the given partition
		if(type == TESTCASE_DELTA){
			for(i = idx * size, j = 0; i < Math.min(queue.size(), (idx+1) * size); i++){
				queuer.add(queue.get(i));

				k = downSubListMap.get(queue.get(i)).get(0).getIndex();
				while(j<res.size() && res.get(j).getIndex() < k)
					j++;
				res.addAll(j, downSubListMap.get(queue.get(i)));
				j+=downSubListMap.get(queue.get(i)).size();
			}
		}
		//for the complement, add to event sequence all events within the event sequences matching to
		//the subtree of nodes except the given partition
		if(type == TESTCASE_GRADIENT){
			for(i = 0, j = 0; i < queue.size(); i++){
				if(i < idx * size || i >= (idx+1) * size){
					queuer.add(queue.get(i));

					k = downSubListMap.get(queue.get(i)).get(0).getIndex();
					while(j<res.size() && res.get(j).getIndex() < k)
						j++;
					res.addAll(j, downSubListMap.get(queue.get(i)));
					j+=downSubListMap.get(queue.get(i)).size();
				}
			}
		}
		return res;
	}

	//The method to generate event sequence through given original node sequence and parameters
	//Note that this method is used for BHDD algorithm originally
	private List<EventState> createEventList(List<Integer> queue, int idx, int type, List<Integer> queuer){
		List<EventState> res = new ArrayList<EventState>(upSubList);
		queuer.clear();
		int i,j,k,i0,i1;
		i0 = (idx==0? 0: downSubListGroup.get(idx-1)+1);
		i1 = downSubListGroup.get(idx);

		//for the partition, add to event sequence all events within the event sequences matching to
		//the subtree of nodes within the given partition
		if(type == TESTCASE_DELTA){
			for(i = i0, j = 0; i <= i1; i++){
				queuer.add(queue.get(i));

				k = downSubListMap.get(queue.get(i)).get(0).getIndex();
				while(j<res.size() && res.get(j).getIndex() < k)
					j++;
				res.addAll(j, downSubListMap.get(queue.get(i)));
				j+=downSubListMap.get(queue.get(i)).size();
			}
		}
		//for the complement, add to event sequence all events within the event sequences matching to
		//the subtree of nodes except the given partition
		if(type == TESTCASE_GRADIENT){
			for(i = 0, j = 0; i < queue.size(); i++){
				if(i < i0 || i > i1){
					queuer.add(queue.get(i));

					k = downSubListMap.get(queue.get(i)).get(0).getIndex();
					while(j<res.size() && res.get(j).getIndex() < k)
						j++;
					res.addAll(j, downSubListMap.get(queue.get(i)));
					j+=downSubListMap.get(queue.get(i)).size();
				}
			}
		}
		return res;
	}

	//The method to execute a event sequence on testing phone and check whether the attempt is succeed
	private boolean executeEventList(List<EventState> list){

//		try {
//			System.out.println("python D:\\BaiduNetdiskDownload\\booster\\input\\sbb\\sethome.py"+" --package "+ReductionRunner.generatePackage()+" --main_activity "+ReductionRunner.generateMainActivity());
//			Process process = Runtime.getRuntime().exec("python D:\\BaiduNetdiskDownload\\booster\\input\\sbb\\sethome.py"+" --package "+ReductionRunner.generatePackage()+" --main_activity "+ReductionRunner.generateMainActivity());
//			process.waitFor();
//
//		} catch (Exception e) {
//			e.printStackTrace();
//		}
		System.out.println("===========================Starting a new trial=================================");
		if(list == null)
			return false;

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
			InputStreamReader ir = new InputStreamReader(process.getInputStream());
            LineNumberReader input = new LineNumberReader(ir);
            String line;
			while ((line = input.readLine()) != null) {
                result = result+line+"\n";
            }
            input.close();
            ir.close();
        } catch (IOException e) {
            e.printStackTrace();
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

	//The method to check whether crash is reproduced or whether target activity is arrived
	// private boolean checkResult(){
	// 	EventQueueOperation eqo = new EventQueueOperation();
	// 	if(level >= maxlevel || includecheck || needBHDD) {	//��Ϊĩ�����Ԥѡ��������Ƿ񴥷�CRASH
	// 		//check whether crash is reproduced while the level now is not above the level of last node or
	// 		//while doing extra check or while using BHDD to do reduction
	// 		includecheck = false;
	// 		String newCrash = eqo.getCrash(ReductionRunner.generateResultPath(index, 4) + "execute_tmp.log");
	// 		if(newCrash != null && newCrash.equals(crash))
	// 		{
	// 			AdbOperation adb = new AdbOperation();
	// 			adb.recordResult(ReductionRunner.generateResultPath(index, 4), ReductionRunner.DEVICE_TMP_PATH, ReductionRunner.DEVICE_ID);
	// 			return true;
	// 		}
	// 		else
	// 			return false;
	// 	}
	// 	else {
	// 		//check whether target activity is arrived while in other condition
	// 		String achieveActivity = eqo.getTargetActivity(ReductionRunner.generateResultPath(index, 4) + "execute_tmp.log");
	// 		if(achieveActivity != null && achieveActivity.equals(targetActivity))
	// 			return true;
	// 		else
	// 			return false;
	// 	}
	// }
}