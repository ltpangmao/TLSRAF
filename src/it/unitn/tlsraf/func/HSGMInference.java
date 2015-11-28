package it.unitn.tlsraf.func;

import it.unitn.tlsraf.ds.Element;
import it.unitn.tlsraf.ds.HolisticSecurityGoalModel;
import it.unitn.tlsraf.ds.InfoEnum;
import it.unitn.tlsraf.ds.RequirementElement;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.LinkedList;

import javax.script.ScriptException;

import net.xqj.basex.bin.al;

public class HSGMInference {

	/**
	 * Import a constructed holistic security goal model, in order to analyze all holistic security solutions
	 * 
	 * @param holistic_security_model
	 * @param from_canvas
	 * @throws IOException
	 * @throws ScriptException
	 */
	public static void importHolisticSecurityGoalModel(HolisticSecurityGoalModel holistic_security_model, Boolean from_canvas) throws IOException, ScriptException {
		String result = "";
		if (from_canvas) {
			String script_path = InfoEnum.current_directory + "/applescript/import_info_return.applescript";
			// here the related results are directly returned from that apple script.
			result = (String) Inference.execAppleScript(script_path);
		}
		holistic_security_model.importGraphInfo(result);

		// writeFile("dlv/models/holistic_security_goal_model.dl", holistic_security_model.generateFormalExpression(), false);
		// CommandPanel.logger.info(holistic_security_model.generateFormalExpression());
	}

	/**
	 * Inference the
	 * 
	 * @param holistic_security_model
	 * @throws IOException
	 * @throws ScriptException
	 */
	public static LinkedList<String> generateHolisticSecuritySolutions(HolisticSecurityGoalModel holistic_security_model) throws IOException, ScriptException {

		// prepare the model
		String hsgm_file = InfoEnum.current_directory + "/dlv/models/holistic_security_goal_model.dl";
		Inference.writeFile(hsgm_file, holistic_security_model.generateFormalExpression(), false);
		for (Element e : holistic_security_model.getElements()) {
			RequirementElement re = (RequirementElement) e;
			if (re.getType().equals(InfoEnum.RequirementElementType.SECURITY_GOAL.name())) {
				// The root security goal has no outgoing links
				if (re.getOutLinks().size() == 0) {
					// append the satisfaction info of the root goal
					Inference.writeFile(hsgm_file, "satisfied(" + re.getId() + ").", true);
					break;
				}
			}
		}

		// inference
		String dlv_command = InfoEnum.current_directory + "/dlv/dlv -silent -nofacts " + InfoEnum.current_directory + "/dlv/rules/find_alternative.rule " // rules
				+ hsgm_file; // model files
		Runtime rt = Runtime.getRuntime();
		Process pr = rt.exec(dlv_command);
		BufferedReader input = new BufferedReader(new InputStreamReader(pr.getInputStream()));
		String line = null;

		// process results
		LinkedList<LinkedList<Element>> all_alternatives = new LinkedList<LinkedList<Element>>();
		LinkedList<String> alternative_description = new LinkedList<String>();

		while ((line = input.readLine()) != null) {
			LinkedList<Element> one_alternative = new LinkedList<Element>();
			line = line.substring(1, line.length() - 1);
			String[] result = line.split(", ");
			for (String s : result) {
				// System.out.println(s);
				// process satisfied goals
				if (s.startsWith("satisfied")) {
					// System.out.println(s);
					// String id = s.substring(s.indexOf("(")+1,s.indexOf(")"));
					// Element node = holistic_security_model.findElementById(id);
					// if(node!=null){
					// System.out.println("satisfied("+node.getName()+")");
					// }
					// else{
					// System.out.println("satisfied elements cannot be found.");
					// }
				}
				if (s.startsWith("result")) {
					String id = s.substring(s.indexOf("(") + 1, s.indexOf(")"));
					Element node = holistic_security_model.findElementById(id);
					if (node != null) {
						if (node.getType().equals(InfoEnum.RequirementElementType.SECURITY_MECHANISM.name()) || node.getType().equals(InfoEnum.RequirementElementType.TASK.name())) {
							one_alternative.add(node);
						}
					} else {
						System.out.println("result elements cannot be found.");
					}
				}
			}
			all_alternatives.add(one_alternative);
		}

		int number = 0;
		for (LinkedList<Element> list : all_alternatives) {
			number++;
			String temp = "Solution " + number + "(" + list.size() + " mechanisms)" + ":{";
			String business = "";
			String application = "";
			String infrstructure = "";
			for (Element e : list) {
				RequirementElement re = (RequirementElement) e;
				// further consider layers of each mechanism, to better show the analysis result
				if (re.getLayer().equals(InfoEnum.Layer.BUSINESS.name())) {
					business += e.getName() + ", ";
				} else if (re.getLayer().equals(InfoEnum.Layer.APPLICATION.name())) {
					application += e.getName() + ", ";
				} else if (re.getLayer().equals(InfoEnum.Layer.PHYSICAL.name())) {
					infrstructure += e.getName() + ", ";
				} else {
					// if the element has no layer information, we exclude it from the final result
					System.out.println("Missing layer information");
				}
			}
			// add corresponding layer security solutions to the final result
			if (business.length() > 0) {
				business = business.substring(0, business.length() - 2);
				temp += "\n Social Layer: " + business;
			}
			if (application.length() > 0) {
				application = application.substring(0, application.length() - 2);
				temp += "\n Software Layer: " + application;
			}
			if (infrstructure.length() > 0) {
				infrstructure = infrstructure.substring(0, infrstructure.length() - 2);
				temp += "\n Infrastructure Layer: " + infrstructure;
			}

			temp += "\n}\n";
			// add the temporal description to the alternative description set
			alternative_description.add(temp);
			// System.out.println(temp);
		}

		return alternative_description;
	}

	/**
	 * Check the content of the current graph to ensure the validity of the data itself This method checks whether there are two security mechanisms that have the same content
	 * 
	 * @param holistic_security_model
	 * @return
	 */
	public static LinkedList<String> sanityCheckRepeat(HolisticSecurityGoalModel holistic_security_model) {
		LinkedList<String> repeat_elements = new LinkedList<String>();

		// first get the mechanisms set in order to reduce computational complexity.
		LinkedList<Element> mechanisms = new LinkedList<Element>();
		for (Element e1 : holistic_security_model.getElements()) {
			// we check repeated elements except for domain assumptions
			if (e1.getType().equals(InfoEnum.RequirementElementType.SECURITY_MECHANISM.name())) {
				mechanisms.add(e1);
			}
		}
		
		// check repeat 
		for (Element e1 : mechanisms) {
			for (Element e2 : mechanisms) {
				if ((!e1.getId().equals(e2.getId())) && e1.getName().equals(e2.getName())) {
					repeat_elements.add(e1.getName());
				}
			}
		}

		return repeat_elements;

	}

}
