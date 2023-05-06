package cn.edu.buaa.util;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;
import cn.edu.buaa.state.EventState;

public class GenerateScript {

	public static boolean generateScript(List<EventState> eQueue, String filePath){
		File fp = new File(filePath);
        System.out.println("Trial file path: "+filePath);
        System.out.println("Trial length: "+eQueue.size());
        System.out.println();
		if(fp.exists()){
			fp.delete();
		}
		try {
			fp.createNewFile();
			
			String script = initHeader();
			for(int i = 0; i < eQueue.size(); i++){
				script += eQueue.get(i).getEvent();
			}
            script = appendTail(script);


            FileWriter fpWriter = new FileWriter(fp, true);
			fpWriter.write(script);
			fpWriter.close();

		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
		
		return true;
	}


    private static String initHeader(){
        String line;
        String content = "";
        try{
            FileInputStream scriptStream = new FileInputStream("C:\\Users\\Administrator\\Desktop\\simplydroid\\SimpliDroidReproduce\\src\\cn\\edu\\buaa\\util\\header.txt");
            DataInputStream scriptInputStream = new DataInputStream(scriptStream);
            BufferedReader scriptBufferedReader = new BufferedReader(new InputStreamReader(scriptInputStream));

            while ((line = scriptBufferedReader.readLine()) != null) {
                content = content+line+"\n";
            }
                    
            scriptBufferedReader.close();
            scriptInputStream.close();
            scriptStream.close();
        } catch (IOException e) {
			e.printStackTrace();
		}

        return content;
    }

    private static String appendTail(String script){
        String line;
        try{
            FileInputStream scriptStream = new FileInputStream("C:\\Users\\Administrator\\Desktop\\simplydroid\\SimpliDroidReproduce\\src\\cn\\edu\\buaa\\util\\tail.txt");
            DataInputStream scriptInputStream = new DataInputStream(scriptStream);
            BufferedReader scriptBufferedReader = new BufferedReader(new InputStreamReader(scriptInputStream));

            while ((line = scriptBufferedReader.readLine()) != null) {
                script = script+line+"\n";
            }
                    
            scriptBufferedReader.close();
            scriptInputStream.close();
            scriptStream.close();
        } catch (IOException e) {
			e.printStackTrace();
		}

        return script;
    }
    
}
