package SamplePackage1;

import java.io.File;
import java.io.FileNotFoundException;
import java.security.Key;
import java.util.Scanner;

public class ReadFile {

	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}
	public String Path="";
	public static String getKeyFromFile(String Path) {
		String key=null;
		File file = new File(Path);
		
		try {
			Scanner scanner = new Scanner(file);
			key = scanner.next();
			
		}
		catch(FileNotFoundException e){
			e.printStackTrace();
		}
		return key;
	}

}
