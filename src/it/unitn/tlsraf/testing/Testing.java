package it.unitn.tlsraf.testing;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;

import javax.script.ScriptException;


public class Testing {

	public static void main(String args[]) throws IOException, ScriptException{

		byte[] encoded = Files.readAllBytes(Paths.get("/Users/litong30/research/Trento/Workspace/TLSRAF/applescript/import_info_return.applescript"));
		String script= Charset.defaultCharset().decode(ByteBuffer.wrap(encoded)).toString();
//		
//		ScriptEngineManager mgr = new ScriptEngineManager();
//		ScriptEngine engine = mgr.getEngineByName("osascript");
//		Object s = engine.eval(script);
		
		
		
		Runtime runtime = Runtime.getRuntime();
		String[] argus = { "osascript", "-e", script };
		Process process = runtime.exec(argus);
		
		BufferedInputStream bio = (BufferedInputStream) process.getInputStream();
		
		int i;
		while ((i=bio.read())!=-1)
		System.out.print((char)i);
		
		
		
//		System.out.println(s);
	}
	
}
