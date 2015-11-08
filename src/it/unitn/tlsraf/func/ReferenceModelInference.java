package it.unitn.tlsraf.func;

import it.unitn.tlsraf.ds.Actor;
import it.unitn.tlsraf.ds.Element;
import it.unitn.tlsraf.ds.HolisticSecurityGoalModel;
import it.unitn.tlsraf.ds.InfoEnum;
import it.unitn.tlsraf.ds.RequirementElement;
import it.unitn.tlsraf.ds.RequirementLink;
import it.unitn.tlsraf.ds.SecurityGoal;

import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import javax.script.ScriptException;

import org.apache.commons.lang3.tuple.Pair;

import net.xqj.basex.bin.al;

public class ReferenceModelInference {

	/**
	 * processing the user data to import the correspond data flow information. Note that the processing function is specific to current data set, where each property only has one
	 * value. The way of data representation and processing has not been fixed yet, we will determine this soon.
	 * 
	 * @param from_canvas
	 * @throws IOException
	 * @throws ScriptException
	 */
	public static void importDataFlowModel(Boolean from_canvas) throws IOException, ScriptException {
		String result = "";
		if (from_canvas) {
			String script_path = InfoEnum.current_directory + "/applescript/import_info_return.applescript";
			// here the related results are directly returned from that apple script.
			result = (String) Inference.execAppleScript(script_path);
		}

		String formal_expressions = "";
		List<String> elements = Arrays.asList(result.split("\n"));
		for (String element : elements) {
			if (element.startsWith("element")) {
				List<String> factors = Arrays.asList(element.split(";"));
				/*
				 * this part is exclusively for requirement elements 0)notation,element; 1)id,51670; 2)shape,Hexagon; 3)name,Calculate price; 4)Layer, Layer 1 by default;
				 * 5)thickness,; 6)double stroke; 7)size: 117.945899963379 43.817626953125; 8)no fill; 9)0.0 corner radius 10) stroke pattern: 0 11) origin: 87.234039306641
				 * 1084.06665039062 12) owner: xx 13) Canvas, Actor association; 14)user data, {|input 2|:\"Patient medical data\", |input 1|:\"Patient personal information\"}
				 */
				// exclusively consider tasks here
				if (factors.get(2).equals("Hexagon")) {
					// if there are some user data
					if (!factors.get(14).equals(" ")) {
						List<String> user_data_set = Arrays.asList(factors.get(14).split("\","));
						for (String temp : user_data_set) {
							int separator = temp.indexOf(":");
							String key = temp.substring(0, separator).trim().toLowerCase();
							String value = Func.prepareFormalExpression(temp.substring(separator + 2).replace("\"}", ""));
							// if this is an input annotation
							if (key.toLowerCase().contains("input")) {
								String task_expression = Func.prepareFormalExpression(factors.get(3));
								formal_expressions += "has_input(" + task_expression + "," + value + ").\n";
							} else if (key.toLowerCase().contains("output")) {
								String task_expression = Func.prepareFormalExpression(factors.get(3));
								formal_expressions += "has_output(" + task_expression + "," + value + ").\n";
							}
							// System.out.println(key+" "+value+" "+temp);
						}
					}
				}
			}
		}
		Func.writeFile("dlv/models/imported_model/data_flow_model.dl", formal_expressions, false);
		CommandPanel.logger.info(formal_expressions);
	}

	/**
	 * Import threat model There is a same issue with the data_flow import, the way of defining model is still flexible, and the function here is specific to the data format we
	 * currently use.
	 * 
	 * @param from_canvas
	 * @throws IOException
	 * @throws ScriptException
	 */
	public static void importThreatModel(Boolean from_canvas) throws IOException, ScriptException {
		String result = "";
		if (from_canvas) {
			String script_path = InfoEnum.current_directory + "/applescript/import_info_return.applescript";
			// here the related results are directly returned from that apple script.
			result = (String) Inference.execAppleScript(script_path);
		}

		// here we specifically assume all properties have been specified, the value of which is separated using ","
		String formal_expressions = "";
		List<String> assets = new LinkedList<String>();
		List<String> threats = new LinkedList<String>();
		List<String> intervals = new LinkedList<String>();
		List<String> temp_set = new LinkedList<String>();

		List<String> elements = Arrays.asList(result.split("\n"));
		for (String element : elements) {
			if (element.startsWith("element")) {
				List<String> factors = Arrays.asList(element.split(";"));
				// exclusively consider (anti-)goals that has certain user data
				if (factors.get(2).equals("Circle") && !factors.get(14).equals(" ")) {
					/*
					 * this part is exclusively for requirement elements 0)notation,element; 1)id,51670; 2)shape,Hexagon; 3)name,Calculate price; 4)Layer, Layer 1 by default;
					 * 5)thickness,; 6)double stroke; 7)size: 117.945899963379 43.817626953125; 8)no fill; 9)0.0 corner radius 10) stroke pattern: 0 11) origin: 87.234039306641
					 * 1084.06665039062 12) owner: xx 13) Canvas, Actor association; 14)user data, {|input 2|:\"Patient medical data\", |input 1|:\"Patient personal information\"}
					 */
					List<String> user_data_set = Arrays.asList(factors.get(14).split("\","));
					for (String temp : user_data_set) {
						int separator = temp.indexOf(":");
						String key = temp.substring(0, separator).trim().toLowerCase();
						String value = temp.substring(separator + 2).replace("\"}", "");
						// if a property is matched
						if (key.toLowerCase().contains("asset")) {
							temp_set = Arrays.asList(value.split(","));
							for (String asset : temp_set) {
								assets.add(Func.prepareFormalExpression(asset));
							}
							// additional check
							if (assets.size() < 1) {
								// log
							}
						} else if (key.toLowerCase().contains("threat")) {
							temp_set = Arrays.asList(value.split(","));
							for (String threat : temp_set) {
								threats.add(Func.prepareFormalExpression(threat));
							}
							// additional check
							if (threats.size() < 1) {
								// log
							}
						} else if (key.toLowerCase().contains("interval")) {
							temp_set = Arrays.asList(value.split(","));
							for (String interval : temp_set) {
								intervals.add(Func.prepareFormalExpression(interval));
							}
							// additional check
							if (intervals.size() < 1) {
								// log
							}
						}
					}
					// traverse all information set to produce related knowledge
					for (String threat : threats) {
						for (String asset : assets) {
							for (String interval : intervals) {
								formal_expressions += "anti_goal(" + threat + "," + asset + "," + interval + ").\n";
							}
						}
					}
				}
			}
		}
		Func.writeFile("dlv/models/imported_model/threat_model.dl", formal_expressions, false);
		CommandPanel.logger.info(formal_expressions);
	}

	public static void importResourceSchema(Boolean from_canvas) throws IOException, ScriptException {
		String result = "";
		if (from_canvas) {
			String script_path = InfoEnum.current_directory + "/applescript/import_info_return.applescript";
			// here the related results are directly returned from that apple script.
			result = (String) Inference.execAppleScript(script_path);
		}

		String formal_expressions = "";
		LinkedList<Pair<String, String>> resources = new LinkedList<Pair<String, String>>();
		List<String> elements = Arrays.asList(result.split("\n"));
		// first, process all nodes
		for (String element : elements) {
			if (element.startsWith("element")) {
				List<String> factors = Arrays.asList(element.split(";"));
				/*
				 * this part is exclusively for requirement elements 0)notation,element; 1)id,51670; 2)shape,Hexagon; 3)name,Calculate price; 4)Layer, Layer 1 by default;
				 * 5)thickness,; 6)double stroke; 7)size: 117.945899963379 43.817626953125; 8)no fill; 9)0.0 corner radius 10) stroke pattern: 0 11) origin: 87.234039306641
				 * 1084.06665039062 12) owner: xx 13) Canvas, Actor association; 14)user data, {|input 2|:\"Patient medical data\", |input 1|:\"Patient personal information\"}
				 */
				// exclusively consider resource here
				if (factors.get(2).equals("Rectangle")) {
					String id = factors.get(1).trim().replaceAll(" ", "_");
					String resource = Func.prepareFormalExpression(factors.get(3));
					if (!resource.contains("part_of")) { // avoid the mis-processing on part_of tags
						formal_expressions += "asset(" + resource + ").\n";
						resources.add(Pair.of(id, resource));
					}
				}
			}
		}
		// then, process all links
		for (String element : elements) {
			if (element.startsWith("link")) {
				List<String> factors = Arrays.asList(element.split(";"));
				/*
				 * this part is exclusively for requirement elements 0)link; 1)id,51690 2)arrow type,StickArrow; 3)line type, curved; 4)source/tail,51670; 5)destination/head,51490;
				 * 6)label,NoLabel;(The shape of that label is not considered, only the content of that label) 7)dash type,0; 8)thickness,1.0; 9)head scale,1.0; 10) layer, BUSINESS
				 */
				// exclusively consider part_of here
				if (factors.get(2).equals("StickArrow")) { // simplify the processing here: && factors.get(6).toLowerCase().equals("part_of")) {
					String source_id = factors.get(4).trim().replaceAll(" ", "_");
					String des_id = factors.get(5).trim().replaceAll(" ", "_");
					String source = null;
					String des = null;
					for (Pair<String, String> resource : resources) {
						if (resource.getKey().toString().equals(source_id)) {
							source = resource.getValue().toString();
						} else if (resource.getKey().toString().equals(des_id)) {
							des = resource.getValue().toString();
						}
					}
					if (source != null && des != null) {
						formal_expressions += "part_of(" + source + "," + des + ").\n";
					}
				}
			}
		}

		Func.writeFile("dlv/models/imported_model/asset_model.dl", formal_expressions, false);
		CommandPanel.logger.info(formal_expressions);
	}

}
