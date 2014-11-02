package it.unitn.tlsraf.testing;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;

import javax.script.ScriptException;
import javax.xml.namespace.QName;
import javax.xml.xquery.XQConnection;
import javax.xml.xquery.XQDataSource;
import javax.xml.xquery.XQException;
import javax.xml.xquery.XQExpression;
import javax.xml.xquery.XQPreparedExpression;
import javax.xml.xquery.XQResultSequence;

import net.xqj.basex.BaseXXQDataSource;


public class Testing {

	public static void main(String args[]) throws IOException, ScriptException, XQException{

//		 XQDataSource xqs = new BaseXXQDataSource();
//		    
////		 xqs.setProperty("serverName", "localhost");
////		    xqs.setProperty("port", "1984");
////
////		    // Change USERNAME and PASSWORD values
//		    XQConnection conn = xqs.getConnection("admin", "admin");
//
////		 	XQConnection conn = xqs.getConnection();
//		    XQExpression xqpe =conn.createExpression();
////		    		( "//country"
////		    		+ "for $country in db:open('factbook')"
////		    		+ "let $name := $country/name[1]"
////		    		+ "return $name"
////		    		);
//		    
////		    conn.prepareExpression("declare variable $x as xs:string external; $x");
////		    xqpe.bindString(new QName("x"), "Hello World!", null);
//
//		    
//		    XQResultSequence rs = xqpe.executeQuery("doc(factbook.xml)//country");
//		    
//		    while(rs.next())
//		      System.out.println(rs.getObject().toString());
////		    	rs.getItemAsString(null));
//
//		    conn.close();
		String s="";
		String []ss = null;
//		System.out.println("1"+ ss.length);
		ss = s.split(" ");
		System.out.println("2"+ ss.length);
		}
}
