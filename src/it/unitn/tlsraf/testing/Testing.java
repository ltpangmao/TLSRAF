package it.unitn.tlsraf.testing;

import it.unitn.tlsraf.ds.InfoEnum;
import it.unitn.tlsraf.func.CommandPanel;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
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
//		System.out.println("1"+ ss.length);
		String refine_rule = "";
		
		refine_rule = InfoEnum.current_directory+"/dlv/dlv -silent "
					+ InfoEnum.current_directory+"/dlv/anti_goal_rules/refine_target.rule "
					+ InfoEnum.current_directory+"/dlv/models/req_business_model.dl "
					+ InfoEnum.current_directory+"/dlv/models/security_model_business.dl ";
		

		Runtime rt = Runtime.getRuntime();
		Process pr = rt.exec(refine_rule);

		BufferedReader input = new BufferedReader(new InputStreamReader(pr.getInputStream()));
		String line = null;
		
		while ((line = input.readLine()) != null) {
//			System.out.println(line);
			String[] result = line.split(", ");
			for(String s:result)
				System.out.println(s);
		}
	}
}
