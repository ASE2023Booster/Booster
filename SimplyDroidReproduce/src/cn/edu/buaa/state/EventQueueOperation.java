package cn.edu.buaa.state;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
// import cn.edu.buaa.util.GenerateScript;

public class EventQueueOperation {

	private List<EventState> eventQueue = new ArrayList<EventState>();
	// private String crash = null;
	// private String tact = null; 

	public EventQueueOperation() {
		super();
	}

	private void readSARAFile(String filePath) throws IOException{
		FileInputStream scriptStream = new FileInputStream(filePath + ".py");
		DataInputStream scriptInputStream = new DataInputStream(scriptStream);
		BufferedReader scriptBufferedReader = new BufferedReader(new InputStreamReader(scriptInputStream));

        String line;
		List<String> content = new ArrayList<>();
		Boolean flag = false;

		while ((line = scriptBufferedReader.readLine()) != null) {
			if (line.trim().equals("post_action(0)")){
				flag = true;
				continue;
			}
			if (line.trim().equals("except Exception as e:")){
				break;
			}
			if (flag){
				content.add(line.trim());
			}
		}
		content.removeIf(String::isEmpty);

		for (int i=0;i<content.size();i=i+2){
			EventState bas = new EventState();
            bas.setIndex(i/2);
            bas.setEvent("        "+content.get(i)+"\n        "+content.get(i+1)+"\n");
			
			FileInputStream activityStream = new FileInputStream(filePath + "\\activity_"+Integer.toString(i/2)+".txt");
			DataInputStream activityInputStream = new DataInputStream(activityStream);
			BufferedReader activityBufferedReader = new BufferedReader(new InputStreamReader(activityInputStream));
			bas.setActivity(activityBufferedReader.readLine().trim());
			activityBufferedReader.close();
			activityInputStream.close();
			activityStream.close();

            eventQueue.add(bas);
		}
                
        scriptBufferedReader.close();
        scriptInputStream.close();
        scriptStream.close();
	}

	
	//The method to manage the reading of log files
	public List<EventState> readLog(String filePath){
		try {
			readSARAFile(filePath);
		} catch (IOException e) {
			e.printStackTrace();
		}		
		return eventQueue;
	}
	
	//the method to print given event sequence into log file script.log
	public boolean printScript(List<EventState> eQueue, String filePath){
		
		File fp = new File(filePath + "script_tmp.log");
		// if(fp.exists()){
		// 	fp.delete();
		// }
		if(!fp.exists()){
			try{
				fp.createNewFile();
			} catch (IOException e) {
				e.printStackTrace();
				return false;
			}
		}
		try {
			// fp.createNewFile();
			FileWriter fpWriter = new FileWriter(fp, true);
			fpWriter.write("# Start Script\n");
			System.out.println("# Start Script");
			fpWriter.write("type= user\n");
			System.out.println("type= user");
			fpWriter.write("count= 10\n");
			System.out.println("count= 10");
			fpWriter.write("speed= 1.0\n" );
			System.out.println("speed= 1.0");
			fpWriter.write("start data >>\n");
			System.out.println("start data >>");
			for(int i = 0; i < eQueue.size(); i++){
				fpWriter.write(eQueue.get(i).getEvent());
				System.out.println(eQueue.get(i).getEvent());
				fpWriter.write("\n");
			}
			System.out.println();
			fpWriter.write("\n");
			fpWriter.close();
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
		
		return true;
	}
	
}
