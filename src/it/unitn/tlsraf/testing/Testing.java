package it.unitn.tlsraf.testing;

import it.unitn.tlsraf.ds.AttackPattern;
import it.unitn.tlsraf.ds.Element;
import it.unitn.tlsraf.ds.HolisticSecurityGoalModel;
import it.unitn.tlsraf.ds.InfoEnum;
import it.unitn.tlsraf.ds.RequirementElement;
import it.unitn.tlsraf.func.AppleScript;
import it.unitn.tlsraf.func.CommandPanel;
import it.unitn.tlsraf.func.Func;
import it.unitn.tlsraf.func.HSGMInference;
import it.unitn.tlsraf.func.Inference;
import it.unitn.tlsraf.func.ReferenceModelInference;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

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

	public static void main(String args[]) throws IOException, ScriptException, XQException, InterruptedException {
//		stringTesting();
		 ruleTesting();
//		processTesting();
		// newTesting();

		
		// XQDataSource xqs = new BaseXXQDataSource();
		//
		// // xqs.setProperty("serverName", "localhost");
		// // xqs.setProperty("port", "1984");
		// //
		// // // Change USERNAME and PASSWORD values
		// XQConnection conn = xqs.getConnection("admin", "admin");
		//
		// // XQConnection conn = xqs.getConnection();
		// XQExpression xqpe =conn.createExpression();
		// // ( "//country"
		// // + "for $country in db:open('factbook')"
		// // + "let $name := $country/name[1]"
		// // + "return $name"
		// // );
		//
		// // conn.prepareExpression("declare variable $x as xs:string external; $x");
		// // xqpe.bindString(new QName("x"), "Hello World!", null);
		//
		//
		// XQResultSequence rs = xqpe.executeQuery("doc(factbook.xml)//country");
		//
		// while(rs.next())
		// System.out.println(rs.getObject().toString());
		// // rs.getItemAsString(null));
		//
		// conn.close();
		// System.out.println("1"+ ss.length);

		// ruleTesting();

	}

	private static void ruleTesting() throws IOException {
		String refine_rule = "";

		refine_rule = InfoEnum.current_directory + "/dlv/dlv -silent " + InfoEnum.current_directory + "/dlv/anti_goal_rules/refine_target.rule " + InfoEnum.current_directory
				+ "/dlv/anti_goal_rules/threat_knowledge.rule " + InfoEnum.current_directory + "/dlv/models/req_business_model.dl " + InfoEnum.current_directory
				+ "/dlv/models/security_model_business.dl ";

		refine_rule = "/Users/litong30/research/Trento/Workspace/TLSRAF/dlv/dlv -silent  "
				+ "/Users/litong30/research/Trento/Workspace/TLSRAF/dlv/anti_goal_rules/refine_all.rule "
				+ "/Users/litong30/research/Trento/Workspace/TLSRAF/dlv/models/req_business_model.dl "
				+ "/Users/litong30/research/Trento/Workspace/TLSRAF/dlv/models/security_model_business.dl  "
				+ "/Users/litong30/research/Trento/Workspace/TLSRAF/dlv/anti_goal_rules/threat_knowledge.rule "
				+ "/Users/litong30/research/Trento/Workspace/TLSRAF/dlv/models/asset_model.dl ";

		refine_rule = "/Users/litong30/research/Trento/Workspace/TLSRAF/dlv/dlv -silent  " + "/Users/litong30/research/Trento/Workspace/TLSRAF/dlv/models/req_business_model.dl "
				+ "/Users/litong30/research/Trento/Workspace/TLSRAF/dlv/models/security_model_business.dl  "
				+ "/Users/litong30/research/Trento/Workspace/TLSRAF/dlv/rules/refine_security_attribute.rule ";

		refine_rule = InfoEnum.current_directory + "/dlv/dlv -silent  " + InfoEnum.current_directory + "/dlv/models/req_business_model.dl " + InfoEnum.current_directory
				+ "/dlv/models/data_flow_model.dl " + InfoEnum.current_directory + "/dlv/models/asset_model.dl " + InfoEnum.current_directory + "/dlv/models/threat_model.dl "
				+ InfoEnum.current_directory + "/dlv/rules/threat_based_simplification.rule ";
		
		//-nofacts
		refine_rule = InfoEnum.current_directory + "/dlv/dlv -silent -nofacts " 
				+ InfoEnum.current_directory + "/dlv/rules/threat_based_simplification.rule "
				+ InfoEnum.current_directory + "/dlv/models/data_flow_model.dl " 
				+ InfoEnum.current_directory + "/dlv/models/threat_model.dl " 
				+ InfoEnum.current_directory + "/dlv/models/asset_model.dl "
				+ InfoEnum.current_directory + "/dlv/models/req_business_model.dl ";
		
		// draw pdf figure for the corresponding graph
		int visualization =1;
		 refine_rule = InfoEnum.current_directory + "/graphviz/dot -Tpdf " + InfoEnum.current_directory + "/graphviz/sec_goal_" + visualization + ".gv -o "
						+ InfoEnum.current_directory + "/graphviz/sec_goal_" + visualization + ".pdf";
		 refine_rule = "/usr/bin/neato -Tpdf -O" + InfoEnum.current_directory + "/graphviz/sec_goal_" + visualization + ".gv";
		
		 
		 refine_rule = InfoEnum.current_directory + "/dlv/dlv -silent -nofacts " + InfoEnum.current_directory + "/dlv/rules/operationalization.rule " 
		 + "/Users/tongli/research/Trento/Workspace/TLSRAF/dlv/models/req_business_model.dl  "
		+ "/Users/tongli/research/Trento/Workspace/TLSRAF/dlv/models/security_model_business.dl ";
		 
		 refine_rule = "/Users/tongli/OneDrive/reseach/Workspace/TLSRAF/dlv/dlv -silent -nofacts "
		 		+ "/Users/tongli/OneDrive/reseach/Workspace/TLSRAF/dlv/rules/operationalization.rule "
		 		+ "/Users/tongli/OneDrive/reseach/Workspace/TLSRAF/dlv/models/req_business_model.dl  "
		 		+ "/Users/tongli/OneDrive/reseach/Workspace/TLSRAF/dlv/models/security_model_business.dl  ";
		 
		 refine_rule = InfoEnum.current_directory + "/dlv/dlv -silent  -nofacts " 
					+ InfoEnum.current_directory + "/dlv/rules/threat_based_simplification.rule "
					+ InfoEnum.current_directory + "/dlv/models/data_flow_model.dl " 
					+ InfoEnum.current_directory + "/dlv/models/threat_model.dl " 
					+ InfoEnum.current_directory + "/dlv/models/asset_model.dl "
					+ "/Users/tongli/OneDrive/reseach/Workspace/TLSRAF/dlv/models/req_business_model.dl  "
					+ "/Users/tongli/OneDrive/reseach/Workspace/TLSRAF/dlv/models/req_application_model.dl  ";

		 refine_rule = InfoEnum.current_directory + "/dlv/dlv -silent -nofacts " + InfoEnum.current_directory + "/dlv/rules/cross_layer.rule "					
				 	+ "/Users/tongli/OneDrive/reseach/Workspace/TLSRAF/dlv/models/req_physical_model.dl  "
					+ "/Users/tongli/OneDrive/reseach/Workspace/TLSRAF/dlv/models/req_application_model.dl  ";

		 String hsgm_file = InfoEnum.current_directory + "/dlv/models/holistic_security_goal_model.dl";
			

			// inference
		 refine_rule= InfoEnum.current_directory + "/dlv/dlv -silent -nofacts " + InfoEnum.current_directory + "/dlv/rules/find_alternative.rule " // rules
					+ hsgm_file; // model files
		 
//		 -nofacts
		 refine_rule = "/Users/tongli/OneDrive/reseach/Workspace/TLSRAF/dlv/dlv -silent  /Users/tongli/OneDrive/reseach/Workspace/TLSRAF/dlv/rules/threat_based_simplification.rule /Users/tongli/OneDrive/reseach/Workspace/TLSRAF/dlv/models/data_flow_model.dl /Users/tongli/OneDrive/reseach/Workspace/TLSRAF/dlv/models/threat_model.dl /Users/tongli/OneDrive/reseach/Workspace/TLSRAF/dlv/models/asset_model.dl /Users/tongli/OneDrive/reseach/Workspace/TLSRAF/dlv/models/ex_req_business_model.dl /Users/tongli/OneDrive/reseach/Workspace/TLSRAF/dlv/models/ex_req_application_model.dl /Users/tongli/OneDrive/reseach/Workspace/TLSRAF/dlv/models/ex_req_physical_model.dl "; 


		 
		 
		 
		 
		 
		 
		Runtime rt = Runtime.getRuntime();
		Process pr = rt.exec(refine_rule);

		BufferedReader input = new BufferedReader(new InputStreamReader(pr.getInputStream()));
		String line = null;

		while ((line = input.readLine()) != null) {
			// System.out.println(line);
			String[] result = line.split(", ");
			for (String s : result)
				System.out.println(s);
		}
	}
	
	public static void processTesting() throws IOException, InterruptedException {
		ProcessBuilder pb = new ProcessBuilder("./graphviz/dot", "-Tpdf /Users/tongli/OneDrive/reseach/Workspace/TLSRAF/graphviz/sec_goal_0.gv -o /Users/tongli/OneDrive/reseach/Workspace/TLSRAF/graphviz/sec_goal_0.pdf");
//		System.out.println("Run echo command");
		Process process = pb.start();
		int errCode = process.waitFor();

	}

	public static void newTesting() throws IOException, ScriptException {
		CommandPanel.setup();
		HolisticSecurityGoalModel hsgm = new HolisticSecurityGoalModel();
		HSGMInference.importHolisticSecurityGoalModel(hsgm, true);
		LinkedList<String> result = HSGMInference.sanityCheckRepeat(hsgm);
		if (result.size() > 0) {
			System.out.println(result.get(0));
		}
	}

	public static void stringTesting() throws IOException, ScriptException {
		
		
		String result = "and_refine_sec_goal_1(very_high,data_confidentiality,patient_information,2351,53933)";
		result = result.substring(result.indexOf("(") + 1, result.indexOf(")"));
		System.out.println(result);
		
		
		String target = "{Asset:\"Social worker information, \", Threat:\"Spoofing, Tampering,Repudiation,Information disclosure,Information disclosure,\", Interval:\"Dispense medicine to patient,Deliver medice to patient\"}";

		// here we specifically assume all properties have been specified, the value of which is separated using ","
		String formal_expressions = "";
		List<String> assets = new LinkedList<String>();
		List<String> threats = new LinkedList<String>();
		List<String> intervals = new LinkedList<String>();
		List<String> temp_set = new LinkedList<String>();

		List<String> user_data_set = Arrays.asList(target.split("\","));
		for (String temp : user_data_set) {
			int separator = temp.indexOf(":");
			String key = temp.substring(0, separator).trim().toLowerCase();
			
//			String value = Func.prepareFormalExpression(temp.substring(separator + 2).replace("\"}", ""));
			String value = temp.substring(separator + 2).trim().replace("\"}", "");
			// if a property is matched
			if(key.toLowerCase().contains("asset")){
				temp_set = Arrays.asList(value.split(","));
				for (String asset: temp_set){
					assets.add(Func.prepareFormalExpression(asset));
				}
				// additional check
				if(assets.size()<1){
//					log
				}
			} else if(key.toLowerCase().contains("threat")){
				temp_set = Arrays.asList(value.split(","));
				for (String threat: temp_set){
					threats.add(Func.prepareFormalExpression(threat));
				}
				// additional check
				if(threats.size()<1){
//					log
				}
			}
			else if(key.toLowerCase().contains("interval")){
				temp_set = Arrays.asList(value.split(","));
				for (String interval: temp_set){
					intervals.add(Func.prepareFormalExpression(interval));
				}
				// additional check
				if(intervals.size()<1){
//					log
				}
			}
		}
		// traverse all information set to produce related knowledge
		for(String threat: threats){
			for(String asset: assets){
				for(String interval: intervals){
					formal_expressions += "anti_goal("+threat+","+asset+","+interval+").\n";
				}
			}
		}
			
		
//		System.out.println(formal_expressions);

	}
}

// /Users/litong30/research/Trento/Workspace/TLSARF/dlv/dlv -silent /Users/litong30/research/Trento/Workspace/TLSARF/dlv/models/req_application_model.dl
// /Users/litong30/research/Trento/Workspace/TLSARF/dlv/rules/refine_interval.rule
