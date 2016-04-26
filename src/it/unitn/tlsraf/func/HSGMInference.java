package it.unitn.tlsraf.func;

import it.unitn.tlsraf.ds.Element;
import it.unitn.tlsraf.ds.HolisticSecurityGoalModel;
import it.unitn.tlsraf.ds.InfoEnum;
import it.unitn.tlsraf.ds.RequirementElement;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Collections;
import java.util.LinkedList;

import javax.script.ScriptException;

import net.xqj.basex.bin.al;

public class HSGMInference {
	
	private static int top = 100;

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
//		 CommandPanel.logger.info(holistic_security_model.generateFormalExpression());
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
		LinkedList<Alternative> all_alters = new LinkedList<Alternative>();
		LinkedList<Integer> top_cost_list = new LinkedList<Integer>();
				
		while ((line = input.readLine()) != null) {
			LinkedList<Element> one_alternative = new LinkedList<Element>();
			int cost = 0;
			line = line.substring(1, line.length() - 1);
			String[] result = line.split(", ");
			for (String s : result) {
				// System.out.println(s);
				// process resulting nodes in each alternative
				if (s.startsWith("result")) {
					String id = s.substring(s.indexOf("(") + 1, s.indexOf(")"));
					Element node = holistic_security_model.findElementById(id);
					if (node != null) {
						if (node.getType().equals(InfoEnum.RequirementElementType.SECURITY_MECHANISM.name()) || node.getType().equals(InfoEnum.RequirementElementType.TASK.name())) {
							one_alternative.add(node);
							// obtain the cost of this mechanism
							int temp = getCost(Func.prepareFormalExpression(node.getName()));
							if(temp ==0){
								System.out.println(Func.prepareFormalExpression(node.getName()));
							}
							else{
								cost += temp; // calculate accumulated solutions
							}
						}
					} else {
						System.out.println("result elements cannot be found.");
					}
				}
			}
			Alternative alter = new Alternative();
			alter.alternative_elements=one_alternative;
			alter.cost=cost;
			
			// we here check redundancy based on costs 
			boolean existance = false;
			for(Alternative temp: all_alters){
				if(temp.cost == alter.cost){
					existance = true;
				}
			}
			if(!existance){
				all_alters.add(alter);
			}
	
			// obtain top X solutions
			// Note that we filter repeated alternatives based on their total cost, which may mis-classify some different ones as the same, but definitely will create different alternatives. 
			if(!top_cost_list.contains(cost)){
				top_cost_list.add(cost);
				Collections.sort(top_cost_list);
				if(top_cost_list.size()>top){
					top_cost_list.removeLast();
				}
			}
		}

		// get top ranked solutions
		LinkedList<LinkedList<Element>> top_alternatives = new LinkedList<LinkedList<Element>>();
		top_alternatives = obtainTopRankedSolutions(all_alters, top_cost_list);

		// Generate textual descriptions for the top XX(5) holistic solutions
		LinkedList<String> top_alternative_description = new LinkedList<String>();
		top_alternative_description = generateAlternativeDescription(top_alternatives);
		
		// add the top number and the total number of holistic solutions as the first element of the List, respectively.
		top_alternative_description.addFirst(Integer.toString(top));
		top_alternative_description.addFirst(Integer.toString(all_alters.size()));

		return top_alternative_description;
	}

	/**
	 * get top ranked solutions from all solutions
	 * @param all_alters
	 * @param top_cost_list
	 * @return
	 */
	private static LinkedList<LinkedList<Element>> obtainTopRankedSolutions(LinkedList<Alternative> all_alters, LinkedList<Integer> top_cost_list) {
		LinkedList<LinkedList<Element>> top_alternatives = new LinkedList<LinkedList<Element>>();
		for(Integer i:top_cost_list){
			for(Alternative temp_alt: all_alters){
				if(i.intValue()==temp_alt.cost){
					if(top_alternatives.contains(temp_alt.alternative_elements)){
						continue;
					}else{
						// add to the final result
						top_alternatives.add(temp_alt.alternative_elements);
						break;
					}
				}
			}
		}
		return top_alternatives;
	}

	/**
	 * generate description of alternative
	 * @param top_alternatives
	 * @param top_alternative_description
	 */
	private static LinkedList<String> generateAlternativeDescription(LinkedList<LinkedList<Element>> top_alternatives) {
		LinkedList<String> top_alternative_description = new LinkedList<String>();
		int number = 0;
		for (LinkedList<Element> list : top_alternatives) {
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
			top_alternative_description.add(temp);
			// System.out.println(temp);
		}
		return top_alternative_description;
	}

	private static int getCost(String mechanism) {
		// business
		if(mechanism.contains("alternative_service")){
			return 1101;
		} else if(mechanism.contains("client_checking")){
			return 1202;
		} else if(mechanism.contains("separation_of_duty")){
			return 2103;
		} else if(mechanism.contains("certification_authority")){
			return 1204;
		} else if(mechanism.contains("supervision_relation")){
			return 2105;
		} else if(mechanism.contains("control") && mechanism.contains("access")){
			return 1406;
		} else if(mechanism.contains("auditing")){
			return 1507;
		}
		// application
		else if(mechanism.contains("input_guard")){
			return 6008;
		} else if(mechanism.contains("firewall")){
			return 4009;
		} else if(mechanism.contains("server_sandbox")){
			return 2100;
		} else if(mechanism.contains("replicated_system")){
			return 1201;
		} else if(mechanism.contains("load_balancer")){
			return 3002;
		} else if(mechanism.contains("limited_view")){
			return 2003;
		} else if(mechanism.contains("full_view_with_errors")){
			return 2104;
		} else if(mechanism.contains("secure_access_layer")){
			return 1205;
		} else if(mechanism.contains("secure_pipe")){
			return 3006;
		} else if(mechanism.contains("storage_encryption")){
			return 2007;
		}
		// application
		else if(mechanism.contains("equipment_siting_and_protection")){
			return 3008;
		} else if(mechanism.contains("supporting_utility")){
			return 2009;
		} else if(mechanism.contains("physical_entry_control")){
			return 2100;
		} else if(mechanism.contains("cabling_security")){
			return 1201;
		}
		
		return 0;
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
	
	
 static class Alternative{
		LinkedList<Element> alternative_elements;
		int cost;
		
		public Alternative() {
			super();
			alternative_elements = new LinkedList<Element>();
			cost = 0;
		}
		
		
	}

}
