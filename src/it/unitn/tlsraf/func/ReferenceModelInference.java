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
				 * 1084.06665039062 12) owner: xx 13) Canvas, Actor association; 14)input; 15)output; 16)threat; 17)asset; 18)interval;
				 */
				// exclusively consider tasks here
				if (factors.get(2).equals("Hexagon")) {
					if (!factors.get(14).equals(" ")) {
						String task_expression = factors.get(3).trim().replaceAll(" ", "_");
						String input_expression = factors.get(14).trim().replaceAll(" ", "_");
						formal_expressions += "has_input(" + task_expression + "," + input_expression + ").\n";
					}
					if (!factors.get(15).equals(" ")) {
						String task_expression = factors.get(3).trim().replaceAll(" ", "_");
						String output_expression = factors.get(15).trim().replaceAll(" ", "_");
						formal_expressions += "has_output(" + task_expression + "," + output_expression + ").\n";
					}
				}
			}
		}
		writeFile("dlv/models/imported model/data_flow_model.dl", formal_expressions, false);
		CommandPanel.logger.info(formal_expressions);
	}

	public static void importThreatModel(Boolean from_canvas) throws IOException, ScriptException {
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
				 * 1084.06665039062 12) owner: xx 13) Canvas, Actor association; 14)input; 15)output; 16)threat; 17)asset; 18)interval;
				 */
				// exclusively consider (anti-)goals here
				if (factors.get(2).equals("Circle")) {
					String threat = "";
					String asset = "";
					String interval = "all";
					if (!factors.get(16).equals(" ")) {
						threat = factors.get(16).trim().replaceAll(" ", "_");
					}
					if (!factors.get(17).equals(" ")) {
						asset = factors.get(17).trim().replaceAll(" ", "_");
					}
					if (!factors.get(18).equals(" ")) {
						interval = factors.get(18).trim().replaceAll(" ", "_");
					}

					formal_expressions += "anti_goal(" + threat + "," + asset + "," + interval + ").\n";
				}
			}
		}
		writeFile("dlv/models/imported model/threat_model.dl", formal_expressions, false);
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
		LinkedList<Pair<String,String>> resources = new LinkedList<Pair<String,String>>();
		List<String> elements = Arrays.asList(result.split("\n"));
		// first, process all nodes
		for (String element : elements) {
			if (element.startsWith("element")) {
				List<String> factors = Arrays.asList(element.split(";"));
				/*
				 * this part is exclusively for requirement elements 0)notation,element; 1)id,51670; 2)shape,Hexagon; 3)name,Calculate price; 4)Layer, Layer 1 by default;
				 * 5)thickness,; 6)double stroke; 7)size: 117.945899963379 43.817626953125; 8)no fill; 9)0.0 corner radius 10) stroke pattern: 0 11) origin: 87.234039306641
				 * 1084.06665039062 12) owner: xx 13) Canvas, Actor association; 14)input; 15)output; 16)threat; 17)asset; 18)interval;
				 */
				// exclusively consider resource here
				if (factors.get(2).equals("Rectangle")) {
					String id = factors.get(1).trim().replaceAll(" ", "_");
					String resource = factors.get(3).trim().replaceAll(" ", "_");
					if(!resource.equals("part_of")){	//avoid the mis-processing on part_of tags
						formal_expressions += "asset(" + resource + ").\n";
						resources.add(Pair.of(id, resource));
					}
				}
			}
		}
		//then, process all links
		for (String element : elements) {
			if (element.startsWith("link")) {
				List<String> factors = Arrays.asList(element.split(";"));
				/*
				 * this part is exclusively for requirement elements 0)link; 1)id,51690 2)arrow type,StickArrow; 3)line type, curved; 4)source/tail,51670; 5)destination/head,51490;
				 * 6)label,NoLabel;(The shape of that label is not considered, only the content of that label) 7)dash type,0; 8)thickness,1.0; 9)head scale,1.0; 10) layer, BUSINESS
				 */
				// exclusively consider part_of here
				if (factors.get(2).equals("StickArrow") && factors.get(6).equals("part_of")) {
					String source_id = factors.get(4).trim().replaceAll(" ", "_");
					String des_id = factors.get(5).trim().replaceAll(" ", "_");
					String source = null;
					String des = null;
					for(Pair<String, String> resource: resources){
						if(resource.getKey().toString().equals(source_id)){
							source = resource.getValue().toString();
						}
						else if(resource.getKey().toString().equals(des_id)){
							des = resource.getValue().toString();
						}
					}
					if(source!=null && des !=null){
						formal_expressions += "part_of(" + source +","+ des +").\n";
					}
				}
			}
		}

		writeFile("dlv/models/imported model/asset_model.dl", formal_expressions, false);
		CommandPanel.logger.info(formal_expressions);
	}

	public static void writeFile(String path, String content, boolean append) throws IOException {
		PrintWriter writer = new PrintWriter(new FileWriter(path, append));
		writer.println(content);
		writer.close();
	}

}
