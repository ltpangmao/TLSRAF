package it.unitn.tlsraf.func;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.LinkedList;

public class Func {
	public static String prepareFormalExpression(String target) {
		return target.trim().replaceAll(" ", "_").replaceAll("-|'|’", "").toLowerCase().replaceAll("__", "_").replaceAll("__", "_").replaceAll("__", "_").replaceAll("__", "_");
	}
	
	public static String fitGraphviz(String target) {
		return target.replace("\\[", "").replace("\\]", "");
		
	}
	
	public static String readFile(String path, Charset encoding) {
		byte[] encoded;
		try {
			encoded = Files.readAllBytes(Paths.get(path));
			return encoding.decode(ByteBuffer.wrap(encoded)).toString();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	public static LinkedList<String> readFileByLine(String path) {
		LinkedList<String> contents = new LinkedList<String>(); 
		try {
			BufferedReader br = new BufferedReader(new FileReader(path));
			String line;
		    while ((line = br.readLine()) != null) {
		       contents.add(line);
		    }
		    br.close();
		    return contents;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;
	}
	
	

	public static void writeFile(String path, String content, boolean append) {
		
		PrintWriter writer;
		try {
			writer = new PrintWriter(new FileWriter(path, append));
			writer.println(content);
			writer.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
}
