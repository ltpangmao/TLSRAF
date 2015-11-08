package it.unitn.tlsraf.func;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Func {
	public static String prepareFormalExpression(String target) {
		target = target.trim();
		return target.trim().replaceAll(" ", "_").replaceAll("-|'|’", "").toLowerCase().replaceAll("__", "_").replaceAll("__", "_").replaceAll("__", "_").replaceAll("__", "_");
	}
	
	public static String readFile(String path, Charset encoding) throws IOException {
		byte[] encoded = Files.readAllBytes(Paths.get(path));
		return encoding.decode(ByteBuffer.wrap(encoded)).toString();
	}

	public static void writeFile(String path, String content, boolean append) throws IOException {
		PrintWriter writer = new PrintWriter(new FileWriter(path, append));
		writer.println(content);
		writer.close();
	}
}
