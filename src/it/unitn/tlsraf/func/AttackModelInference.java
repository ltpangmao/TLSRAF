package it.unitn.tlsraf.func;

import it.unitn.tlsraf.ds.AttackModel;
import it.unitn.tlsraf.ds.AttackPattern;
import it.unitn.tlsraf.ds.Element;
import it.unitn.tlsraf.ds.HolisticSecurityGoalModel;
import it.unitn.tlsraf.ds.InfoEnum;
import it.unitn.tlsraf.ds.RequirementElement;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.LinkedList;

import javax.script.ScriptException;
import javax.xml.xquery.XQException;

public class AttackModelInference {

	// all attack patterns we will analyze here
	static private LinkedList<AttackPattern> all_attack_patterns = new LinkedList<AttackPattern>();

	/**
	 * Import a constructed holistic security goal model, in order to analyze all holistic security solutions
	 * 
	 * @param attack_model
	 * @param from_canvas
	 * @throws IOException
	 * @throws ScriptException
	 */
	public static void importAttackModel(AttackModel attack_model, Boolean from_canvas) throws IOException, ScriptException {
		String result = "";
		if (from_canvas) {
			String script_path = InfoEnum.current_directory + "/applescript/import_info_return.applescript";
			// here the related results are directly returned from that apple script.
			result = (String) Inference.execAppleScript(script_path);
		}
		attack_model.importGraphInfo(result);

		// writeFile("dlv/attack/attack_model.dl", attack_model.generateFormalExpression(), false);
		// CommandPanel.logger.info(holistic_security_model.generateFormalExpression());
	}

	
	/**
	 * Find relevant patterns to the selected leaf-anti goal. But we only check "leaf" among the selected nodes
	 * We assume the user only select the leaf nodes to analyze. The function works well when people select all elements.
	 * The only exceptional case is that the leaf goal in the selected model is not leaf in the entire model
	 * @param attack_model
	 * @param scope
	 * @throws IOException
	 * @throws ScriptException
	 */
	public static void identifyRelevantPattern(AttackModel attack_model, int scope) throws IOException, ScriptException {
		// prepare the model
		String attack_file = InfoEnum.current_directory + "/dlv/attack/attack_model.dl";
		Inference.writeFile(attack_file, attack_model.generateFormalExpression(scope), false);

		// inference
		String dlv_command = InfoEnum.current_directory + "/dlv/dlv -silent -nofacts " + InfoEnum.current_directory + "/dlv/attack/operationalization.rule " // rules
				+ InfoEnum.current_directory + "/dlv/attack/attack_patterns.dl " + attack_file; // model files
		Runtime rt = Runtime.getRuntime();
		Process pr = rt.exec(dlv_command);
		BufferedReader input = new BufferedReader(new InputStreamReader(pr.getInputStream()));
		String line = null;

		LinkedList<String> relevant_attack_patterns = new LinkedList<String>();
		RequirementElement anti_goal = null;
		// process results
		while ((line = input.readLine()) != null) {
			line = line.substring(1, line.length() - 1);
			String[] result = line.split(", ");
			for (String s : result) {
				// System.out.println(s);
				if (s.startsWith("relevant_to_with_name")) { // relevant_to(AP,NA,GID)
					String content = s.substring(s.indexOf("(") + 1, s.indexOf(")"));
					String[] relevant = content.split(",");
					if (relevant.length == 3) {
						String anti_task_id = "";
						anti_goal = (RequirementElement) attack_model.findElementById(relevant[2]);
						// use attack id as identifier
						relevant_attack_patterns.add(relevant[0]);
						// RequirementElement anti_task = new RequirementElement(relevant[1].replace("_", " "), InfoEnum.RequirementElementType.TASK.name(), "none");
						// if (anti_goal != null) {
						// // for now, we have to do the reasoning within the "Model" canvas
						// anti_task_id = AppleScript.drawRequirementElement(anti_task, anti_goal, "down");
						// AppleScript.drawArbitraryRequirementLink("Model", "none", anti_goal.getId(), anti_task_id, "Arrow", "0", "none", "none");
						// // RequirementLink rl = new RequirementLink(InfoEnum.RequirementLinkType.OPERATIONALIZE.name(),anti_task,anti_goal);
						// // AppleScript.drawRequirementLink(rl, InfoEnum.SINGLE_LAYER);
						// } else {
						// System.out.println("result elements cannot be found.");
						// }
					} else {
						System.out.println("Datalog results are incorrect.");
					}
				}
			}
		}
		// load all pattern information
		loadPatternHierarchy();
		// store processed patterns
		LinkedList<String> processed_pattern_ids = new LinkedList<String>();
		// draw all relevant pattern
		// Traverse each element, if one element has a root within the set, then move to that node, if not draw a link to root.
		for (String attack_pattern_id : relevant_attack_patterns) {
			// process each un-processed patterns
			if (!processed_pattern_ids.contains(attack_pattern_id)) {
				generateSingleRelevantPatternHierarchy(anti_goal, attack_pattern_id, relevant_attack_patterns, processed_pattern_ids);

			} else {
				// This means the pattern has already been processed
			}
		}
	}
	

	/**
	 * A nested algorithm for generating pattern hierarchy related to one pattern
	 * 
	 * @param anti_goal
	 * @param target_pattern_id
	 * @param relevant_attack_patterns
	 * @param processed_pattern_ids
	 */
	private static void generateSingleRelevantPatternHierarchy(RequirementElement anti_goal, String target_pattern_id, LinkedList<String> relevant_attack_patterns,
			LinkedList<String> processed_pattern_ids) {
		AttackPattern ap = findAttackPatternById(target_pattern_id);
		if (ap != null) {
			RequirementElement anti_task = new RequirementElement(ap.name, InfoEnum.RequirementElementType.TASK.name(), "none");
			ap.graphical_id = AppleScript.drawRequirementElement(anti_task, anti_goal, "down");
			anti_task.setId(ap.graphical_id);
			processed_pattern_ids.add(ap.id);
			// link target pattern to its parents or the root
			if (ap.parents.size() != 0) {
				boolean drawn = false;
				for (String parent_id : ap.parents) {
					if (!relevant_attack_patterns.contains(parent_id)) {

					} else {
						// first retrieve the parent pattern element
						AttackPattern parent = findAttackPatternById(parent_id); // assume parent is not null
						if (processed_pattern_ids.contains(parent_id)) {
							// draw a link to that parent
							AppleScript.drawArbitraryRequirementLink("Model", "none", parent.graphical_id, anti_task.getId(), "SharpArrow", "0", "none", "none");
							drawn = true;
						} else {
							// for unprocessed pattern, we should process them first, and then link to that element
							generateSingleRelevantPatternHierarchy(anti_goal, parent_id, relevant_attack_patterns, processed_pattern_ids);
							// draw a link to that parent
							AppleScript.drawArbitraryRequirementLink("Model", "none", parent.graphical_id, anti_task.getId(), "SharpArrow", "0", "none", "none");
							drawn = true;
						}
					}
				}
				if (!drawn) {
					// if no parents can be drawn, then directly draw a link to the anti-goal
					AppleScript.drawArbitraryRequirementLink("Model", "none", anti_goal.getId(), anti_task.getId(), "Arrow", "0", "none", "none");
				}
			} else {
				// directly draw a link to the anti-goal
				AppleScript.drawArbitraryRequirementLink("Model", "none", anti_goal.getId(), anti_task.getId(), "Arrow", "0", "none", "none");
			}

		}
	}

	/**
	 * Initiate the attack pattern trees
	 * 
	 * @throws IOException
	 */
	private static void loadPatternHierarchy() throws IOException {
		String target_patterns = "112,20,49,97,55,70,16,";
		target_patterns += "184,185,207,186,187,";
		target_patterns += "66,108,109,110,7,";
		target_patterns += "100,46,47,44,45,8,24,42,67,10,";
		target_patterns += "22,77,39,94,13,56,57,219,9,76,69,122,180,1,58,17,";
		target_patterns += "115,237,114,90,14,21,62,102,61,60,31,196,59,";
		target_patterns += "416,424,425,422,423,420,421,426,417,427,419,418,434,433,435,428,429,430,431,432,";
		target_patterns += "390,395,391,396,394,393,399,398,397,400,547,507,";
		target_patterns += "438,520,521,516,517,518,519,511,537,439,523,524,522,111";

		String[] pattern_ids = target_patterns.split(",");
		for (String id : pattern_ids) {
			AttackPattern ap = new AttackPattern();
			ap.id = id;
			all_attack_patterns.add(ap);
		}

		BufferedReader br = new BufferedReader(new FileReader(new File("dlv/attack/attack_patterns.dl")));
		AttackPattern ap = null;
		String line;
		while ((line = br.readLine()) != null) {
			if (line.startsWith("child_of")) {
				String content = line.substring(line.indexOf("(") + 1, line.indexOf(")"));
				String[] patterns = content.split(",");
				// add parent attributes
				ap = findAttackPatternById(patterns[0]);
				if (ap != null) {
					if (!ap.parents.contains(patterns[1])) {
						ap.parents.add(patterns[1]);
					}
				} else {
					System.out.println("Child-of relation processing error");
				}
			} else if (line.startsWith("has_name")) {
				String content = line.substring(line.indexOf("(") + 1, line.indexOf(")"));
				String[] patterns = content.split(",");
				// add parent name
				ap = findAttackPatternById(patterns[0]);
				if (ap != null) {
					ap.name = patterns[1].replace("_", " ");
				} else {
					System.out.println("has_name relation processing error");
				}
			}
		}
	}

	/**
	 * searching function
	 * 
	 * @param pattern_id
	 * @return
	 */
	private static AttackPattern findAttackPatternById(String pattern_id) {
		for (AttackPattern ap : all_attack_patterns) {
			if (ap.id.equals(pattern_id)) {
				return ap;
			}
		}
		return null;
	}

	/**
	 * searching function
	 * 
	 * @param pattern_id
	 * @return
	 */
	private static AttackPattern findAttackPatternByName(String name) {
		for (AttackPattern ap : all_attack_patterns) {
			if (ap.name.equals(name)) {
				return ap;
			}
		}
		return null;
	}
	
	
	
	
	
	
	public static LinkedList<String> identifyApplicablePattern(AttackModel attack_model, int scope) throws IOException, ScriptException {
		// prepare the model
		String attack_file = InfoEnum.current_directory + "/dlv/attack/attack_model.dl";
		// we have special processing on the attack model. The content of the inferred attack model does not respect the "scope"
		String inference_attack_model = attack_model.generateFormalExpression(InfoEnum.ALL_MODELS);
		// we generate additional predicates for selected tasks (attack patterns)
		ArrayList<Long> selected_elements = null;
		String relevant_attacks = "";
		try {
			// here the returned value won't be null
			selected_elements = AppleScript.getSelectedGraph();
			RequirementElement selected_element = null;
			for (Long id : selected_elements) {
				selected_element = (RequirementElement) attack_model.findElementById(Long.toString(id));
				if (selected_element != null && selected_element.getType().equals(InfoEnum.RequirementElementType.TASK.name())) {
					relevant_attacks += "selected_pattern_name("+selected_element.getName().replace(" ", "_") + "," +selected_element.getFormalName()+").\n";
				}
			}
		} catch (ScriptException e1) {
			e1.printStackTrace();
		}
		// merge results
		inference_attack_model += relevant_attacks;
		Inference.writeFile(attack_file, inference_attack_model, false);
		
		//selected_pattern_name(NA,TID)
		//relevant_to_with_name(AP,NA,GID)
		
		//applicable_to(AP,GID)
		
		// inference
		String dlv_command = InfoEnum.current_directory + "/dlv/dlv -silent -nofacts "
				+ InfoEnum.current_directory + "/dlv/attack/operationalization.rule " // rules for determining relevance
				+ InfoEnum.current_directory + "/dlv/attack/attack_pattern_contexts.rule " // rules for determining applicability
				+ InfoEnum.current_directory + "/dlv/attack/attack_patterns.dl " // facts of attack patterns
				+ InfoEnum.current_directory + "/dlv/attack/checked_context.dl " // facts of checked context
				+ attack_file; // attack model files
		Runtime rt = Runtime.getRuntime();
		Process pr = rt.exec(dlv_command);
		BufferedReader input = new BufferedReader(new InputStreamReader(pr.getInputStream()));
		String line = null;

		LinkedList<String> questions = new LinkedList<String>();
		RequirementElement anti_task = null;
		// process results
		while ((line = input.readLine()) != null) {
			line = line.substring(1, line.length() - 1);
			String[] result = line.split(", ");
			for (String s : result) {
				// System.out.println(s);
				// if there are interactive questions, then add them into the question list
				if (s.startsWith("question")) { // question(technical_context, TA, expose_an_api_to_users)
					String temp = s.substring(s.indexOf("(") + 1, s.indexOf(")"));
					String[] question_contents = temp.split(",");
					// prepare the facts to be generated, if the answer is yes
					String fact = question_contents[0]+"("+question_contents[1]+","+question_contents[2]+")";
					if (question_contents.length == 3) {
						String question = "Does " + question_contents[1].replace("_", " ") + " " + question_contents[2].replace("_", " ")+"$"+fact;
						questions.add(question);
					} else {
						System.out.println("Datalog results (about question) are incorrect.");
					}
				} 
				// process applicable 
				else if (s.startsWith("applicable_task_id")) { // applicable_task_id(TID)
					String content = s.substring(s.indexOf("(") + 1, s.indexOf(")"));
					anti_task = (RequirementElement) attack_model.findElementById(content);
					if (anti_task != null) {
						// highlight the
						AppleScript.changeAttributeOfElement(InfoEnum.REQ_TARGET_CANVAS, "none", anti_task.getId(), "5", "none", "none");
					} else {
						System.out.println("Datalog results (about applicability) are incorrect.");
					}
				}
			}
		}
		return questions;
	}

	
	
	

	/**
	 * Inference the
	 * 
	 * @param attack_model
	 * @throws IOException
	 * @throws ScriptException
	 */
	public static LinkedList<String> generateAttackPlans(AttackModel attack_model) throws IOException, ScriptException {

		// prepare the model
		String attack_file = InfoEnum.current_directory + "/dlv/attack/attack_model.dl";
		Inference.writeFile(attack_file, attack_model.generateFormalExpression(InfoEnum.ALL_MODELS), false);
		for (Element e : attack_model.getElements()) {
			RequirementElement re = (RequirementElement) e;
			if (re.getType().equals(InfoEnum.RequirementElementType.NEW_ANTI_GOAL.name())) {
				// The root security goal has no outgoing links
				if (re.getOutLinks().size() == 0) {
					// append the satisfaction info of the root goal
					Inference.writeFile(attack_file, "satisfied(" + re.getId() + ").", true);
					break;
				}
			}
		}

		// inference
		String dlv_command = InfoEnum.current_directory + "/dlv/dlv -silent -nofacts " + InfoEnum.current_directory + "/dlv/attack/find_alternative_attacks.rule " // rules
				+ attack_file; // model files
		Runtime rt = Runtime.getRuntime();
		Process pr = rt.exec(dlv_command);
		BufferedReader input = new BufferedReader(new InputStreamReader(pr.getInputStream()));
		String line = null;

		// process results
		LinkedList<LinkedList<String>> all_alternatives = new LinkedList<LinkedList<String>>();
		LinkedList<String> alternative_description = new LinkedList<String>();

		while ((line = input.readLine()) != null) {
			LinkedList<String> one_alternative = new LinkedList<String>();
			line = line.substring(1, line.length() - 1);
			String[] result = line.split(", ");
			boolean validity = false;
			for (String s : result) {
				// System.out.println(s);
				if (s.startsWith("result")) {
					// result(GT,TA)
					String id = s.substring(s.indexOf("(") + 1, s.indexOf(","));
					String target = s.substring(s.indexOf(",") + 1, s.indexOf(")")).replace("_", " ");
					Element node = attack_model.findElementById(id);
					if (node != null) {
						// only list tasks, i.e., skip domain assumptions
						if (node.getType().equals(InfoEnum.RequirementElementType.TASK.name())) {
							// add this step to the alternative
							one_alternative.add("perform " + node.getName() + " to " + target);
							// here we assume each attack alternative has to have at least one task, if only domain assumptions it doesn't make sense.
							validity =true;
						}
					} else {
						System.out.println("result elements cannot be found.");
					}
				} else if (s.startsWith("unachievable")) {
					// this alternative is invalid, if some goal cannot be operationalized
					validity = false;
					break;
				}
			}
			if (validity) {
				all_alternatives.add(one_alternative);
			}
		}

		int number = 0;
		for (LinkedList<String> list : all_alternatives) {
			number++;
			String temp = "Attack alterntive " + number + "(" + list.size() + " attack)" + ":{";
			String attacks = "";
			for (String attack : list) {
				attacks += attack + ", ";
			}
			// add the content of this attack, while removing the last comma
			temp += attacks.substring(0, attacks.length() - 2);
			temp += "}";
			// add the temporal description to the alternative description set
			alternative_description.add(temp);
			// System.out.println(temp);
		}

		return alternative_description;
	}

	private static boolean checkSolutionValidity(LinkedList<Element> list) {
		// TODO Auto-generated method stub
		return false;
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

	// public static void main(String args[]) throws IOException, ScriptException, XQException, InterruptedException {
	// loadPatternHierarchy();
	// }

}
