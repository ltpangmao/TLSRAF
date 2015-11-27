package it.unitn.tlsraf.func;

import it.unitn.tlsraf.ds.Actor;
import it.unitn.tlsraf.ds.ActorAssociationGraph;
import it.unitn.tlsraf.ds.Element;
import it.unitn.tlsraf.ds.HolisticSecurityGoalModel;
import it.unitn.tlsraf.ds.InfoEnum;
import it.unitn.tlsraf.ds.Link;
import it.unitn.tlsraf.ds.RequirementElement;
import it.unitn.tlsraf.ds.RequirementGraph;
import it.unitn.tlsraf.ds.RequirementLink;
import it.unitn.tlsraf.ds.SecurityGoal;
import it.unitn.tlsraf.ds.Threat;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;

import javax.script.ScriptException;

/**
 * Processing logic of inference rules Interact with additional files (i.e. non-java files)
 * 
 * @author litong30
 */
public class Inference {

	/**
	 * Construct logical requirements models from selected elements or from files
	 * 
	 * @param ms
	 * @param from_canvas
	 * @throws IOException
	 * @throws ScriptException
	 */
	public static void importReqModel(ModelSet ms, boolean from_canvas) throws IOException, ScriptException {
		// this import allows us to incrementally add model, but not delete/overwrite model, which should be done later
		String result = "";
		if (from_canvas) {
			String script_path = InfoEnum.current_directory + "/applescript/import_info_return.applescript";
			// here the related results are directly returned from that apple script.
			result = (String) execAppleScript(script_path);
		}

		// pre-processing the results to classify information to different layers
		String bus_result = "";
		String app_result = "";
		String phy_result = "";
		List<String> elements = Arrays.asList(result.split("\n"));
		for (String s : elements) {
			if (s.indexOf(InfoEnum.Layer.BUSINESS.name()) >= 0) {
				bus_result += s + "\n";
			} else if (s.indexOf(InfoEnum.Layer.APPLICATION.name()) >= 0) {
				app_result += s + "\n";
			} else if (s.indexOf(InfoEnum.Layer.PHYSICAL.name()) >= 0) {
				phy_result += s + "\n";
			}
		}
		// import requirements into three separate models
		ms.req_bus_model.importGraphInfo(bus_result);
		ms.req_app_model.importGraphInfo(app_result);
		ms.req_phy_model.importGraphInfo(phy_result);
		// process the support links between layers.
		ms.importSupportLinks();

//		ms.req_bus_model.generateFormalExpressionToFile(InfoEnum.ALL_MODELS);
//		ms.req_app_model.generateFormalExpressionToFile(InfoEnum.ALL_MODELS);
//		ms.req_phy_model.generateFormalExpressionToFile(InfoEnum.ALL_MODELS);
	}

	/**
	 * Construct actor models from selected elements or from files
	 * As this is used to perform the trust-based analysis, we deprecate this function for now
	 * 
	 * @param actor_model
	 * @param from_canvas
	 * @throws IOException
	 * @throws ScriptException
	 * @deprecated
	 */
	public static void importActorModel(ActorAssociationGraph actor_model, Boolean from_canvas) throws IOException, ScriptException {
		String result = "";
		if (from_canvas) {
			String script_path = InfoEnum.current_directory + "/applescript/import_info_return.applescript";
			// here the related results are directly returned from that apple script.
			result = (String) execAppleScript(script_path);
		}

		actor_model.importGraphInfo(result);

		// writeFile("dlv/models/actor_association_model.dl", actor_model.generateFormalExpression());
		CommandPanel.logger.info(actor_model.generateFormalExpression());
	}

	
	
	
	




	public static void securityGoalRefine(RequirementGraph req_model, String type, int scope) throws IOException, ScriptException {
		String expression_file = req_model.generateFormalExpressionToFile(scope);

		String security_model_file = InfoEnum.current_directory + "/dlv/models/security_model_" + req_model.getLayer().toLowerCase() + ".dl ";
		// absolute path: /Users/litong30/research/Trento/Workspace/research/TLSAF/
		String refine_rule = "";
		if (type.equals(InfoEnum.RefinementDimension.ASSET.name())) {
			refine_rule = InfoEnum.current_directory + "/dlv/dlv -silent -nofacts " + InfoEnum.current_directory + "/dlv/rules/refine_asset.rule " + InfoEnum.current_directory
					+ "/dlv/models/asset_model.dl " + expression_file;
		} else if (type.equals(InfoEnum.RefinementDimension.SECURITY_PROPERTY.name())) {
			refine_rule = InfoEnum.current_directory + "/dlv/dlv -silent -nofacts " + InfoEnum.current_directory + "/dlv/rules/refine_security_attribute.rule " + expression_file
					+ " " + security_model_file;
		} else if (type.equals(InfoEnum.RefinementDimension.INTERVAL.name())) {
			refine_rule = InfoEnum.current_directory + "/dlv/dlv -silent -nofacts " + InfoEnum.current_directory + "/dlv/rules/refine_interval.rule " + expression_file;
		} else {
			CommandPanel.logger.severe("Error refinement type!");
		}

		Runtime rt = Runtime.getRuntime();
		Process pr = rt.exec(refine_rule);

		BufferedReader input = new BufferedReader(new InputStreamReader(pr.getInputStream()));
		String line = null;

		/*
		 * having the restriction that we only process "and_refined_sec_goal" we could harden a bit drawing logic into code.
		 */
		// LinkedList<RequirementLink> new_links = new LinkedList<RequirementLink>();
		LinkedList<RequirementElement> refined_elems = new LinkedList<RequirementElement>();

		// parse reasoning result
		while ((line = input.readLine()) != null) {
			line = line.substring(1, line.length() - 1);
			String[] result = line.split(", ");
			for (String s : result) {
				// System.out.println(s);
				// only consider related security goals
				if (s.startsWith("and_refined_sec_goal")) {
					// parse facts
					s = s.replaceAll("and_refined_sec_goal\\(", "");
					s = s.replaceAll("\\)", "");
					String[] sg = s.split(",");
					// create new element`
//					SecurityGoal refined_goal = (SecurityGoal) req_model.findElementByFormalName(sg[4]);
					SecurityGoal refined_goal = (SecurityGoal) req_model.findElementById(sg[4]);

					// find the actor element, which is an asset in application and physical layer
					Element asset = null;
					if(req_model.getLayer().equals(InfoEnum.Layer.APPLICATION.name())||req_model.getLayer().equals(InfoEnum.Layer.PHYSICAL.name())){
						asset = req_model.findElementById(sg[2]);
						if(asset==null){
							CommandPanel.logger.severe("Asset error");
						}
					}
					
					// find the corresponding goal/task element according to the obtained id
					Element re = req_model.findElementById(sg[3]);
					SecurityGoal new_sg = null;
					if (re != null) {
						new_sg = new SecurityGoal(sg[0], sg[1], sg[2], re, InfoEnum.RequirementElementType.SECURITY_GOAL.name(), refined_goal.getLayer());
						if(asset!=null){
							// as the asset here is just the ID of application (actor) and hardware (actor), to be readable, we manually change the name of the security goal
							new_sg.setName((new_sg.getImportance() + " " + new_sg.getSecurityAttribute() + " [" + asset.getName() + ", " + new_sg.getInterval().getName() + "]").replaceAll("\\_", " "));
						}
					} else {
						CommandPanel.logger.severe("Security goal cannot be created: interval id-->" + sg[3]);
					}
					
					// update ownership relations
					new_sg.owner_text = refined_goal.owner_text;
					if (refined_goal.owner != null) {
						refined_goal.owner.getOwnedElement().add(new_sg);
						new_sg.owner = refined_goal.owner;
					}
					else{
						// as this is not really important at all for our current analysis, we just fake the onwer for the time being
						// we here assume the owner only used for its formal name...
						Actor fake_owner = new Actor(refined_goal.owner_text, InfoEnum.RequirementElementType.ACTOR.name(), refined_goal.getLayer());
						fake_owner.setId(refined_goal.owner_text);
						new_sg.owner = fake_owner;
//						CommandPanel.logger.severe("Security goal misses owner information: interval, the security goal id-->" + refined_goal.getId());
//						return;
					}

					req_model.getElements().add(new_sg);
					// create new link
					RequirementLink new_and_refine = new RequirementLink(InfoEnum.RequirementLinkType.AND_REFINE.name(), new_sg, refined_goal);
					req_model.getLinks().add(new_and_refine);

					refined_goal.and_refine_links.add(new_and_refine);
					if (refined_elems.indexOf(refined_goal) == -1) {
						refined_elems.add(refined_goal);
					}
					// System.out.println(new_sg.getFormalExpression()+"\n"+new_and_refine.getFormalExpression());
					// no id for newly added elements and links. This should be
					// done after graphic representation.
				}
			}
		}
		VisualizationFunctions.drawAndRefinement(refined_elems);
	}

	


	/**
	 * Simplify security goals by identifying critical ones
	 * Here we adopt the threat-based approach for identifying the critical security goal
	 * 
	 * To accommodate the simplification analysis across layers, we need to include all model files, not only the specific layer
	 * @param ms
	 * @param scope
	 * @throws IOException
	 * @throws ScriptException
	 */
	public static void threatBasedSecurityGoalSimplification(ModelSet ms, RequirementGraph req_model, int scope) throws IOException, ScriptException {
		String req_bus_model_file = ms.req_bus_model.generateFormalExpressionToFile(scope);
		String req_app_model_file = ms.req_app_model.generateFormalExpressionToFile(scope);
		String req_phy_model_file = ms.req_phy_model.generateFormalExpressionToFile(scope);

		String inference_rule = InfoEnum.current_directory + "/dlv/dlv -silent -nofacts " 
				+ InfoEnum.current_directory + "/dlv/rules/threat_based_simplification.rule "
				+ InfoEnum.current_directory + "/dlv/models/data_flow_model.dl " 
				+ InfoEnum.current_directory + "/dlv/models/threat_model.dl " 
				+ InfoEnum.current_directory + "/dlv/models/asset_model.dl " 
				+ req_bus_model_file + req_app_model_file + req_phy_model_file;

		Runtime rt = Runtime.getRuntime();
		Process pr = rt.exec(inference_rule);

		BufferedReader input = new BufferedReader(new InputStreamReader(pr.getInputStream()));
		String line = null;

		// this is used to store all the security goals that are to be highlighted
		LinkedList<SecurityGoal> highlight_sgs = new LinkedList<SecurityGoal>();
		
		while ((line = input.readLine()) != null) {
			// line = input.readLine();
			line = line.substring(1, line.length() - 1);
			String[] result = line.split(", ");
			for (String s : result) {
//				CommandPanel.logger.info(s);

				// highlight the critical one
				if (s.startsWith("is_critical")) {
					// parse facts
					s = s.replaceAll("is\\_critical\\(", "");
					s = s.replaceAll("\\)", "");

//					SecurityGoal critical_sec_goal = (SecurityGoal) req_model.findElementByFormalName(s);
					int separator = s.indexOf(",");
					String sg_id = s.substring(0, separator);
					String threat_id = s.substring(separator+1);
					
					SecurityGoal critical_sec_goal = (SecurityGoal) req_model.findElementById(sg_id);
					if (critical_sec_goal != null) {
						critical_sec_goal.setCriticality(true);
						// add the threat information
						if(!critical_sec_goal.threats.contains(threat_id)){
							critical_sec_goal.threats.add(threat_id);
						}
						// add the critical security goal to the highlight queue
						if(!highlight_sgs.contains(critical_sec_goal)){
							highlight_sgs.add(critical_sec_goal);
						}
					} else {
						CommandPanel.logger.severe("Simplification error: cannot find the security goal element");
					}
				}
				
				// show the not determined one. not used anymore
//				else if (s.startsWith("non_deterministic")) {
//					// parse facts
//					s = s.replaceAll("non\\_deterministic\\(", "");
//					s = s.replaceAll("\\)", "");
//
//					SecurityGoal critical_sec_goal = (SecurityGoal) req_model.findElementById(s);
//					critical_sec_goal.setNon_deterministic(true);
//					AppleScript.changeAttributeOfElement(InfoEnum.REQ_TARGET_CANVAS, critical_sec_goal.getLayer(), critical_sec_goal.getId(), "3", "none", "none");
//				}
			}
		}
		
		for(SecurityGoal critical_sec_goal: highlight_sgs){
			AppleScript.changeAttributeOfElement(InfoEnum.REQ_TARGET_CANVAS, critical_sec_goal.getLayer(), critical_sec_goal.getId(), "5", "none", "none");
			AppleScript.addUserData2(InfoEnum.REQ_TARGET_CANVAS, critical_sec_goal.getLayer(), critical_sec_goal, critical_sec_goal.owner_text);
		}
	}

	/**
	 * Simplify security goals by identifying critical ones
	 * Here we adopt the trust-based approach for identifying the critical security goal, which probably will not be used in the future
	 * 
	 * @param req_model
	 * @param actor_model
	 * @param scope
	 * @throws IOException
	 * @throws ScriptException
	 * @deprecated
	 */
	public static void securityGoalSimplification(RequirementGraph req_model, ActorAssociationGraph actor_model, int scope) throws IOException, ScriptException {
		String req_model_file = req_model.generateFormalExpressionToFile(scope);
		// normally the actor association model keeps unchanged, so no need to rewrite it.
		String actor_model_file = InfoEnum.current_directory + "/dlv/models/actor_association_model.dl ";
		if (actor_model.getElements().size() != 0) {
			actor_model_file = actor_model.generateFormalExpressionToFile();
		}

		String inference_rule = "";
		if (req_model.getLayer().equals(InfoEnum.Layer.BUSINESS.name())) {
			inference_rule = InfoEnum.current_directory + "/dlv/dlv -silent -nofacts " + InfoEnum.current_directory + "/dlv/rules/simplification_bus.rule "
					+ InfoEnum.current_directory + "/dlv/rules/simplification_general.rule " + InfoEnum.current_directory + "/dlv/models/business_process_model.dl "
					+ InfoEnum.current_directory + "/dlv/models/asset_model.dl " + req_model_file + " " + actor_model_file;
		} else if (req_model.getLayer().equals(InfoEnum.Layer.APPLICATION.name())) {
			inference_rule = InfoEnum.current_directory + "/dlv/dlv -silent -nofacts " + InfoEnum.current_directory + "/dlv/rules/simplification_app.rule "
					+ InfoEnum.current_directory + "/dlv/rules/simplification_general.rule " + InfoEnum.current_directory + "/dlv/models/software_architecture_model.dl "
					+ InfoEnum.current_directory + "/dlv/models/asset_model.dl " + req_model_file + " " + actor_model_file;
			// + "dlv/rules/sec_goal_ownership.rule " + "dlv/models/temp_app_fact.dl "
		} else if (req_model.getLayer().equals(InfoEnum.Layer.PHYSICAL.name())) {
			inference_rule = InfoEnum.current_directory + "/dlv/dlv -silent -nofacts " + InfoEnum.current_directory + "/dlv/rules/simplification_phy.rule "
					+ InfoEnum.current_directory + "/dlv/rules/simplification_general.rule " + InfoEnum.current_directory + "/dlv/models/deployment_model.dl "
					+ InfoEnum.current_directory + "/dlv/models/software_architecture_model.dl " // infer additional knowledge from software
					+ InfoEnum.current_directory + "/dlv/models/asset_model.dl " + req_model_file + " " + actor_model_file;
		} else {
			CommandPanel.logger.severe("Error refinement type!");
		}

		Runtime rt = Runtime.getRuntime();
		Process pr = rt.exec(inference_rule);

		BufferedReader input = new BufferedReader(new InputStreamReader(pr.getInputStream()));
		String line = null;

		while ((line = input.readLine()) != null) {
			// line = input.readLine();
			line = line.substring(1, line.length() - 1);
			String[] result = line.split(", ");
			for (String s : result) {
				CommandPanel.logger.info(s);

				// highlight the critical one
				if (s.startsWith("is_critical")) {
					// parse facts
					s = s.replaceAll("is\\_critical\\(", "");
					s = s.replaceAll("\\)", "");

					SecurityGoal critical_sec_goal = (SecurityGoal) req_model.findElementByFormalName(s);
					critical_sec_goal.setCriticality(true);
					AppleScript.changeAttributeOfElement(InfoEnum.REQ_TARGET_CANVAS, critical_sec_goal.getLayer(), critical_sec_goal.getId(), "5", "none", "none");
				}
				// show the not determined one.
				else if (s.startsWith("non_deterministic")) {
					// parse facts
					s = s.replaceAll("non\\_deterministic\\(", "");
					s = s.replaceAll("\\)", "");

					SecurityGoal critical_sec_goal = (SecurityGoal) req_model.findElementByFormalName(s);
					critical_sec_goal.setNon_deterministic(true);
					AppleScript.changeAttributeOfElement(InfoEnum.REQ_TARGET_CANVAS, critical_sec_goal.getLayer(), critical_sec_goal.getId(), "3", "none", "none");

				}
			}
		}
	}

	
	/**
	 * This method calculate all possible refinements and represent them in another graph. Thus, the analysis result will not be shown in the graph. The output of this analysis
	 * should be put into a separate data structure, which is only designed to carry out the complete refinements analysis.
	 * 
	 * @param req_model
	 * @param actor_model
	 * @param visualization
	 * @throws IOException
	 * @throws ScriptException
	 */
	public static void exhaustiveSecurityGoalRefineAnalysis(ModelSet ms, RequirementGraph req_model, ActorAssociationGraph actor_model, int visual_type, int scope) throws IOException,
			ScriptException {
		// first empty the potential security goal set.
		req_model.getSg_elem().clear();
		req_model.getSg_links().clear();

		String expression_file = req_model.generateFormalExpressionToFile(scope);
		String security_model_file = InfoEnum.current_directory + "/dlv/models/security_model_" + req_model.getLayer().toLowerCase() + ".dl ";

		String refine_rule = "";
		refine_rule = InfoEnum.current_directory + "/dlv/dlv -silent -nofacts " + InfoEnum.current_directory + "/dlv/rules/refine_all.rule " + InfoEnum.current_directory
				+ "/dlv/models/asset_model.dl " + expression_file + " " + security_model_file;
		Runtime rt = Runtime.getRuntime();
		Process pr = rt.exec(refine_rule);

		BufferedReader input = new BufferedReader(new InputStreamReader(pr.getInputStream()));
		String line = null;

		// parse inference results
		while ((line = input.readLine()) != null) {
			line = line.substring(1, line.length() - 1);
			String[] result = line.split(", ");

			// Assign all security goals with ordered numbers, which are just used as identifiers.
			// to avoid conflicts with existing element id.
			int number = 100000;
			for (String s : result) {
				// only consider related security goals
				if (s.startsWith("ex_and_refined_sec_goal")) {
					// parse facts
					s = s.replaceAll("ex_and_refined_sec_goal\\(", "");
					s = s.replaceAll("\\)", "");
					String[] sg = s.split(",");

					// create two security goals, and the and-refinement relation between them.
					SecurityGoal new_sg = req_model.findExhausiveSecurityGoalByAttributes(sg[0], sg[1], sg[2], sg[3]);
					SecurityGoal refined_sg = req_model.findExhausiveSecurityGoalByAttributes(sg[4], sg[5], sg[6], sg[7]);

					// add elements to the security goal graph
					if (new_sg == null) {
						// find the corresponding goal/task element according to the obtained id
						Element re = req_model.findElementById(sg[3]);
						if (re != null) {
							new_sg = new SecurityGoal(sg[0], sg[1], sg[2], re, InfoEnum.RequirementElementType.SECURITY_GOAL.name(), req_model.getLayer());
							new_sg.setId(String.valueOf(number));
							number++;
							req_model.getSg_elem().add(new_sg);
						} else {
							CommandPanel.logger.severe("Security goal cannot be created: interval id-->" + sg[3]);
						}
					}
					if (refined_sg == null) {
						// find the corresponding goal/task element according to the obtained id
						Element re = req_model.findElementById(sg[7]);
						if (re != null) {
							refined_sg = new SecurityGoal(sg[4], sg[5], sg[6], re, InfoEnum.RequirementElementType.SECURITY_GOAL.name(), req_model.getLayer());
							refined_sg.setId(String.valueOf(number));
							number++;
							req_model.getSg_elem().add(refined_sg);
						} else {
							CommandPanel.logger.severe("Security goal cannot be created: interval id-->" + sg[3]);
						}
					}

					// record related links
					RequirementLink new_and_refine = new RequirementLink(InfoEnum.RequirementLinkType.AND_REFINE.name(), new_sg, refined_sg);
					// determine the type of this refinement
					if (!sg[1].equals(sg[5])) {
						new_and_refine.refine_type = InfoEnum.RefineType.ATTRIBUTE.name();
					} else if (!sg[2].equals(sg[6])) {
						new_and_refine.refine_type = InfoEnum.RefineType.ASSET.name();
					} else if (!sg[3].equals(sg[7])) {
						new_and_refine.refine_type = InfoEnum.RefineType.INTERVAL.name();
					} else {
						CommandPanel.logger.log(Level.SEVERE, "Refine type is not set correctly");
					}
					// the refinement links should always be added, as there may be several elements that refine/be refined to one element.
					if (!req_model.getSg_links().contains(new_and_refine)) {
						req_model.getSg_links().add(new_and_refine);
					}

					// add the refinement link to the target security goal
					refined_sg.and_refine_links.add(new_and_refine);
					// add refined security and links to its refinement
					new_sg.parent = refined_sg;
					new_sg.parent_link = new_and_refine;
				}
			}

			// visualize exhaustive refinements via Graphviz
			if (visual_type == InfoEnum.GRAPHVIZ) {
				// graphviz can generate the three view separately
				VisualizationFunctions.visualizeGraph(ms, req_model, actor_model, InfoEnum.GRAPHVIZ, InfoEnum.INITIAL_VIEW);
				VisualizationFunctions.visualizeGraph(ms, req_model, actor_model, InfoEnum.GRAPHVIZ, InfoEnum.HIGHLIGHT_VIEW);
				VisualizationFunctions.visualizeGraph(ms, req_model, actor_model, InfoEnum.GRAPHVIZ, InfoEnum.SIMPLIFIED_VIEW);
			} else if (visual_type == InfoEnum.CANVAS) {
				// we only provide one view in the canvas
				// the highlight and simpliefied view are put together in one view
				// visualizeGraph(req_model, actor_model, InfoEnum.CANVAS, InfoEnum.INITIAL_VIEW);
				VisualizationFunctions.visualizeGraph(ms, req_model, actor_model, InfoEnum.CANVAS, InfoEnum.HIGHLIGHT_VIEW);
			} else {
				CommandPanel.logger.warning("Visualization type error!");
			}

			// visualizeGraph(req_model, actor_model, 1);
			// visualizeGraph(req_model, actor_model, 2);
		}
	}

	
	
	
	/**
	 * Operationalize security goals into security mechanisms by using security patterns
	 * 
	 * @param req_model
	 * @param scope
	 * @throws IOException
	 * @throws ScriptException
	 */
	public static void securityGoalOperationalization(RequirementGraph req_model, int scope) throws IOException, ScriptException {

		String expression_file = req_model.generateFormalExpressionToFile(scope);
		// only consider security mechanisms that are specific for the current layer
		String security_model_file = InfoEnum.current_directory + "/dlv/models/security_model_" + req_model.getLayer().toLowerCase() + ".dl ";

		String refine_rule = InfoEnum.current_directory + "/dlv/dlv -silent -nofacts " 
		+ InfoEnum.current_directory + "/dlv/rules/operationalization.rule " + expression_file + " "
				+ security_model_file;

		Runtime rt = Runtime.getRuntime();
		Process pr = rt.exec(refine_rule);

		BufferedReader input = new BufferedReader(new InputStreamReader(pr.getInputStream()));
		String line = null;

		LinkedList<RequirementElement> operated_elems = new LinkedList<RequirementElement>();
		while ((line = input.readLine()) != null) {
			// line = input.readLine();
			line = line.substring(1, line.length() - 1);
			String[] result = line.split(", ");
			for (String s : result) {
				// System.out.println(s);
				if (s.startsWith("operationalize")) {
					// parse facts
					s = s.replaceAll("operationalize\\(", "");
					s = s.replaceAll("\\)", "");
					String[] sg = s.split(",");
					// we should only operationalize security goals that have been selected. 
					// Here we have an additional control, as DLV -nofacts doesn't work well for no reason
					if (VisualizationFunctions.selectionCheck(sg[1])) {
						// create new element
						SecurityGoal op_goal = (SecurityGoal) req_model.findElementByFormalName(sg[1]);
						sg[0] = sg[0].replaceAll("\\_", " ");
						RequirementElement sec_mech = new RequirementElement(sg[0], InfoEnum.RequirementElementType.SECURITY_MECHANISM.name(), op_goal.getLayer());
						req_model.getElements().add(sec_mech);
						// create new link
						RequirementLink new_op = new RequirementLink(InfoEnum.RequirementLinkType.OPERATIONALIZE.name(), sec_mech, op_goal);
						req_model.getLinks().add(new_op);

						op_goal.op_links.add(new_op);
						if (operated_elems.indexOf(op_goal) == -1) {
							operated_elems.add(op_goal);
						}
					}
				} 
				else {
				}
			}
			// draw the reasoning result on omnigraffle
			for (RequirementElement operated_elem : operated_elems) {
				for (RequirementLink op : operated_elem.op_links) {
					String source_id = AppleScript.drawRequirementElement(op.getSource(), op.getTarget(), "down");
					op.getSource().setId(source_id);
					String link_id = AppleScript.drawRequirementLink(op, InfoEnum.SINGLE_LAYER);
					op.setId(link_id);
				}
			}
		}
	}

	
	/**
	 * This function is initially used for generating security mechanism alternatives in one layer
	 * As we have already implement the holistic security goal model analysis for generating holistic security solution across three layers,
	 * this method is thus deprecated.
	 * @param req_model
	 * @param scope
	 * @return
	 * @deprecated
	 */
	@SuppressWarnings("unchecked")
	public static LinkedList<String> securityAlternativeSolutions(RequirementGraph req_model, int scope) {

		LinkedList<SecurityGoal> sg_set = new LinkedList<SecurityGoal>();
		LinkedList<SecurityGoal> sg_set_temp = new LinkedList<SecurityGoal>();
		SecurityGoal sg_temp = new SecurityGoal();
		for (Element elem : req_model.getElements()) {
			if (elem.getType().equals(InfoEnum.RequirementElementType.SECURITY_GOAL.name())) {
				sg_temp = (SecurityGoal) elem;
				if (sg_temp.isCriticality() == true) {
					sg_set_temp.add(sg_temp);
				}
			}
		}
		// If we focus on the selected elements, we remove the unselected one here.
		if (scope == InfoEnum.SELECTED_MODELS) {
			// obtain selected elements' id
			ArrayList<Long> selected_elements = null;
			try {
				selected_elements = AppleScript.getSelectedGraph();
			} catch (ScriptException e1) {
				e1.printStackTrace();
			}
			// Note that we only generate alternatives for critical security goals
			for (SecurityGoal sg : sg_set_temp) {
				if (selected_elements.contains(Long.valueOf(sg.getId()))) {
					sg_set.add(sg);
				}
			}
		} else if (scope == InfoEnum.ALL_MODELS) {
			sg_set = sg_set_temp;
		}

		@SuppressWarnings("rawtypes")
		LinkedList<LinkedList> all = new LinkedList<LinkedList>();
		for (@SuppressWarnings("unused") LinkedList<RequirementLink> temp : all) {
			temp = new LinkedList<RequirementLink>();
		}
		LinkedList<RequirementLink> one = new LinkedList<RequirementLink>();

		for (SecurityGoal sg : sg_set) {
			/*
			 * add an additional element to security goals to cover the situation that not treat the security goal at this level. Accordingly, a link is added to link this element
			 * to the security goal in order to accommodate the reasoning work. however, this is an auxiliary element which doesn't exist in the model.
			 */
			RequirementElement empty = new RequirementElement("not treat " + sg.getName(), InfoEnum.RequirementElementType.SECURITY_MECHANISM.name(), sg.getLayer());
			RequirementLink rl = new RequirementLink(InfoEnum.RequirementLinkType.MAKE.name(), empty, sg);
			sg.op_links.add(rl);
		}
		getCombination(sg_set, all, one, 0);

		LinkedList<String> result = new LinkedList<String>();
		String solution = "";
		for (int i = 0; i < all.size(); i++) {
			solution = "Alternative " + (i + 1) + ": ";
			for (int j = 0; j < all.get(i).size(); j++) {
				if (((RequirementLink) all.get(i).get(j)).getSource().getName().contains("not treat")) {
					// System.out.print(((RequirementLink) all.get(i).get(j)).getSource().getName() + " ");
					solution += "not treat sg_" + ((RequirementLink) all.get(i).get(j)).getTarget().getId() + " ";
				} else {
					// System.out.print(((RequirementLink) all.get(i).get(j)).getFormalExpression() + " ");
					solution += "apply " + ((RequirementLink) all.get(i).get(j)).getSource().getName() + " to " + "sg_" + ((RequirementLink) all.get(i).get(j)).getTarget().getId()
							+ ";  ";
				}
			}
			result.add(solution);
		}

		return result;
	}

	private static void getCombination(LinkedList<SecurityGoal> sg_set, @SuppressWarnings("rawtypes") LinkedList<LinkedList> all, LinkedList<RequirementLink> one, int current) {
		if (current == sg_set.size() - 1) {
			for (RequirementLink mh : sg_set.get(current).op_links) {
				one.add(mh);
				LinkedList<RequirementLink> backup = new LinkedList<RequirementLink>();
				for (RequirementLink temp : one) {
					backup.add(temp);
				}
				all.add(backup);
				one.removeLast();
			}
			return;
		}

		for (RequirementLink mh : sg_set.get(current).op_links) {
			one.add(mh);
			getCombination(sg_set, all, one, current + 1);
			one.removeLast();
		}
	}

	/**
	 * Check the context to select appropriate security patterns
	 * 
	 * @param req_model
	 * @param scope
	 * @param primary
	 * @return
	 * @throws IOException
	 */
	public static LinkedList<String> checkSecurityPatternContext(RequirementGraph req_model, Integer scope, boolean primary) throws IOException {
		String expression_file = req_model.generateFormalExpressionToFile(scope);
		// only consider security mechanisms that are specific for the current layer
		String context_file = InfoEnum.current_directory + "/dlv/context/domain_context.dl " + InfoEnum.current_directory + "/dlv/context/pattern_context.rule ";

		String context_check_rule = InfoEnum.current_directory + "/dlv/dlv -silent -nofacts " + expression_file + " " + context_file;

		Runtime rt = Runtime.getRuntime();
		Process pr = rt.exec(context_check_rule);

		BufferedReader input = new BufferedReader(new InputStreamReader(pr.getInputStream()));
		String line = null;

		LinkedList<String> results_primary = new LinkedList<String>();
		LinkedList<String> results_secondary = new LinkedList<String>();
		while ((line = input.readLine()) != null) {
			line = line.substring(1, line.length() - 1);
			String[] result = line.split(", ");
			for (String s : result) {
				if (s.indexOf("c1") > 0) {// make sure it is the primary context
					if (s.startsWith("hold") || s.startsWith("not_hold") || s.startsWith("undecidable") || s.startsWith("question")) {
						results_primary.add(s);
					}
				} else {
					if (s.startsWith("hold") || s.startsWith("not_hold") || s.startsWith("undecidable") || s.startsWith("question")) {
						results_secondary.add(s);
					}
				}
			}
		}

		if (primary) {
			return results_primary;
		} else {
			return results_secondary;
		}
	}
	
	
	
	

	
	/**
	 * Transfer security concerns over layers 
	 * 
	 * @param up_req_model
	 * @param down_req_model
	 * @param scope
	 * @throws ScriptException
	 * @throws IOException
	 */
	public static void transferSecurityAcrossLayers(RequirementGraph up_req_model, RequirementGraph down_req_model, int scope) throws ScriptException, IOException {
		// TODO: revise here
		String expression_file1 = up_req_model.generateFormalExpressionToFile(scope);
		String expression_file2 = down_req_model.generateFormalExpressionToFile(scope);

		String refine_rule = InfoEnum.current_directory + "/dlv/dlv -silent -nofacts " + InfoEnum.current_directory + "/dlv/rules/cross_layer.rule "
				+ InfoEnum.current_directory + "/dlv/models/asset_model.dl " + expression_file1 + " " + expression_file2;

		Runtime rt = Runtime.getRuntime();
		Process pr = rt.exec(refine_rule);

		BufferedReader input = new BufferedReader(new InputStreamReader(pr.getInputStream()));
		String line = null;
		
		// a set of elements that are to be andrefined 
		LinkedList<RequirementElement> refined_elems = new LinkedList<RequirementElement>();

		while ((line = input.readLine()) != null) {
			// line = input.readLine();
			line = line.substring(1, line.length() - 1);
			String[] result = line.split(", ");
			for (String s : result) {
				if(s.startsWith("support_sec_mechanism")){
					// corresponding elements will be drawn within the method
					processCrossLayerMechanism(up_req_model, down_req_model, s);
				} else if(s.startsWith("and_refine_sec_goal_1")){
					// corresponding elements will be drawn later
					processCrossLayerSecGoal(up_req_model, down_req_model, s, InfoEnum.ASSET_TYPE_DATA, refined_elems);
				} else if(s.startsWith("and_refine_sec_goal_2")){
					// corresponding elements will be drawn later
					processCrossLayerSecGoal(up_req_model, down_req_model, s, InfoEnum.ASSET_TYPE_OTHER, refined_elems);
				} else{
					
				}
			}
		}
		
		// the and-refinement cases are drawn here, i.e., the later two cases in the above code
		VisualizationFunctions.drawAndRefinement(refined_elems);
	}
	
	
	private static void processCrossLayerMechanism(RequirementGraph up_req_model, RequirementGraph down_req_model, String result) throws ScriptException {
		// parse facts
		result = result.replaceAll("support_sec_mechanism\\(", "");
		result = result.replaceAll("\\)", "");
		String[] sg = result.split(",");
		
		if(sg.length == 6){
			// create new element
			RequirementElement supported_mechanism = (RequirementElement) up_req_model.findElementByFormalName(sg[4]);
			SecurityGoal refined_sec_goal = (SecurityGoal) up_req_model.findElementByFormalName(sg[5]);
			// determine the current layer
			String layer = null;
			if(supported_mechanism.getLayer().equals(InfoEnum.Layer.BUSINESS.name())){
				layer = InfoEnum.Layer.APPLICATION.name();
			} else if(supported_mechanism.getLayer().equals(InfoEnum.Layer.APPLICATION.name())){
				layer = InfoEnum.Layer.PHYSICAL.name();
			} else {
				CommandPanel.logger.severe("Layer processing error");
			}
			// find the actor element, which is an asset in the next layer down. Here is a special case 
			Element asset = down_req_model.findElementById(sg[2]);
			if(asset==null){
				CommandPanel.logger.severe("Asset error");
			}
			// find the corresponding interval(goal/task) element according to the obtained id
			Element re = down_req_model.findElementById(sg[3]);
			SecurityGoal new_sg = null;
			String new_sg_id,support_link_id;
			if (re != null && layer !=null) {
				new_sg = new SecurityGoal(sg[0], sg[1], sg[2], re, InfoEnum.RequirementElementType.SECURITY_GOAL.name(), layer);
				// as the asset here is just the ID of application (actor) and hardware (actor), to be readable, we manually change the name of the security goal
				new_sg.setName((new_sg.getImportance() + " " + new_sg.getSecurityAttribute() + " [" + asset.getName() + ", " + new_sg.getInterval().getName() + "]").replaceAll("\\_", " "));
				// propagate the owner of security goal to its refinements.
				new_sg.owner_text = refined_sec_goal.owner_text;
				if (refined_sec_goal.owner != null) {
					refined_sec_goal.owner.getOwnedElement().add(new_sg);
					new_sg.owner = refined_sec_goal.owner;
				}
			} else {
				CommandPanel.logger.severe("Security goal cannot be created: interval id-->" + sg[3]);
			}
			//first draw the support security goal
			new_sg_id = AppleScript.drawRequirementElement(new_sg, supported_mechanism, "down");
			new_sg.setId(new_sg_id);
			// add mouse-over annotation
			AppleScript.addUserData2("Model", new_sg.getLayer(), new_sg, new_sg.owner_text);
			
			// then draw the link to connect the two goals
			RequirementLink support_link = new RequirementLink(InfoEnum.RequirementLinkType.SUPPORT.name(), new_sg, supported_mechanism); 
			support_link_id = AppleScript.drawRequirementLink(support_link, InfoEnum.CROSS_LAYERS);
			support_link.setId(support_link_id);
			// add the newly generated elements and links
			down_req_model.getElements().add(new_sg);
			down_req_model.getLinks().add(support_link);
		}
		else{
			CommandPanel.logger.severe("Parsing mechanism support has problems.");
		}
	}
	

	private static void processCrossLayerSecGoal(RequirementGraph up_req_model, RequirementGraph down_req_model, String result, int asset_type, LinkedList<RequirementElement> refined_elems) throws ScriptException {
		// parse facts
		result = result.substring(result.indexOf("(") + 1, result.indexOf(")"));
		String[] sg = result.split(",");

		// ensure the validity of the input
		if (sg.length == 5) {
			// create new element
			SecurityGoal refined_sec_goal = (SecurityGoal) up_req_model.findElementByFormalName(sg[4]);
			// determine the current layer
			String layer = null;
			if (refined_sec_goal.getLayer().equals(InfoEnum.Layer.BUSINESS.name())) {
				layer = InfoEnum.Layer.APPLICATION.name();
			} else if (refined_sec_goal.getLayer().equals(InfoEnum.Layer.APPLICATION.name())) {
				layer = InfoEnum.Layer.PHYSICAL.name();
			} else {
				CommandPanel.logger.severe("Layer processing error");
			}
			// for non-data asset, we will have additional processing operations
			Element asset = null;
			if (asset_type == InfoEnum.ASSET_TYPE_OTHER) {
				// find the actor element, which is an asset in the next layer down. Here is a special case
				asset = down_req_model.findElementById(sg[2]);
				if (asset == null) {
					CommandPanel.logger.severe("Asset error");
				}
			}
			// find the corresponding interval(goal/task) element according to the obtained id
			Element interval = down_req_model.findElementById(sg[3]);
			SecurityGoal new_sg = null;
			if (interval != null) {
				new_sg = new SecurityGoal(sg[0], sg[1], sg[2], interval, InfoEnum.RequirementElementType.SECURITY_GOAL.name(), layer);
				// propagate the owner of security goal to its refinements.
				if (refined_sec_goal.owner != null) {
					refined_sec_goal.owner.getOwnedElement().add(new_sg);
					new_sg.owner = refined_sec_goal.owner;
				}
				else{
					new_sg.owner_text = refined_sec_goal.owner_text;
				}
				// change asset representation if necessary
				if (asset_type == InfoEnum.ASSET_TYPE_OTHER && asset != null) {
					// as the asset here is just the ID of application (actor) and hardware (actor), to be readable, we manually change the name of the security goal
					new_sg.setName((new_sg.getImportance() + " " + new_sg.getSecurityAttribute() + " [" + asset.getName() + ", " + new_sg.getInterval().getName() + "]")
							.replaceAll("\\_", " "));
				}
			} else {
				CommandPanel.logger.severe("Security goal cannot be created: interval id-->" + sg[3]);
			}

			// create new link
			RequirementLink new_and_refine = new RequirementLink(InfoEnum.RequirementLinkType.AND_REFINE.name(), new_sg, refined_sec_goal);

			refined_sec_goal.and_refine_links.add(new_and_refine);
			if (refined_elems.indexOf(refined_sec_goal) == -1) {
				refined_elems.add(refined_sec_goal);
			}
			// add the newly generated elements and links
			down_req_model.getElements().add(new_sg);
			down_req_model.getLinks().add(new_and_refine);
		} else {
			CommandPanel.logger.severe("Parsing mechanism support has problems.");
		}
	}

	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	/**
	 * Transfer untreated security goals to the next layer down
	 * 
	 * @param up_req_model
	 * @param down_req_model
	 * @param scope
	 * @throws IOException
	 * @throws ScriptException
	 */
	private static void crossLayerSecurityGoal(RequirementGraph up_req_model, RequirementGraph down_req_model, int scope) throws IOException, ScriptException {
		// TODO: revise here
		String expression_file1 = up_req_model.generateFormalExpressionToFile(scope);
		String expression_file2 = down_req_model.generateFormalExpressionToFile(scope);

		String refine_rule = InfoEnum.current_directory + "/dlv/dlv -silent -nofacts " + InfoEnum.current_directory + "/dlv/rules/cross_layer.rule " + InfoEnum.current_directory
				+ "/dlv/models/asset_model.dl " + expression_file1 + " " + expression_file2;
		// String refine_rule =
		// "dlv/dlv -silent -nofacts dlv/rules/cross_layer.rule dlv/rules/general.rule dlv/models/req_business_model.dl dlv/models/req_application_model.dl";
		Runtime rt = Runtime.getRuntime();
		Process pr = rt.exec(refine_rule);

		BufferedReader input = new BufferedReader(new InputStreamReader(pr.getInputStream()));
		String line = null;

		// LinkedList<RequirementLink> new_links = new LinkedList<RequirementLink>();
		LinkedList<RequirementElement> refined_elems = new LinkedList<RequirementElement>();

		while ((line = input.readLine()) != null) {
			// line = input.readLine();
			line = line.substring(1, line.length() - 1);
			String[] result = line.split(", ");
			for (String s : result) {
				// System.out.println(s);
				if (s.startsWith("refined_sec_goal")) {
					// parse facts
					s = s.replaceAll("refined_sec_goal\\(", "");
					s = s.replaceAll("\\)", "");
					String[] sg = s.split(",");
					// create new element
					SecurityGoal refined_goal = (SecurityGoal) up_req_model.findElementByFormalName(sg[4]);
					
					SecurityGoal new_sg = null;
					// find the corresponding goal/task element according to the obtained id
					Element re = down_req_model.findElementById(sg[3]);
					if (re != null) {
						new_sg = new SecurityGoal(sg[0], sg[1], sg[2], re, InfoEnum.RequirementElementType.SECURITY_GOAL.name(), down_req_model.getLayer());
						// propagate the owner of security goal to its refinements.
						if (refined_goal.owner != null) {
							refined_goal.owner.getOwnedElement().add(new_sg);
							new_sg.owner = refined_goal.owner;
						}
					} else {
						CommandPanel.logger.severe("Security goal cannot be created: interval id-->" + sg[3]);
					}
					
					

					down_req_model.getElements().add(new_sg);

					// create new link
					RequirementLink new_and_refine = new RequirementLink(InfoEnum.RequirementLinkType.AND_REFINE.name(), new_sg, refined_goal);
					down_req_model.getLinks().add(new_and_refine);

					refined_goal.and_refine_links.add(new_and_refine);
					if (refined_elems.indexOf(refined_goal) == -1) {
						refined_elems.add(refined_goal);
					}
				}
			}
		}

		String position = "";

		// for (RequirementElement sg : refined_elems) {
		// // add the new elements below the refined sg.
		// position = "{"+sg.origin_x+","+(sg.origin_y+220)+"}";
		// String id = AppleScript.drawArbitraryRequirementElement(InfoEnum.REQ_TARGET_CANVAS, sg.getLayer(), "Cloud", position, "0",
		// "(S)\n" + sg.getName());
		// sg.setId(id);
		// }

		VisualizationFunctions.drawAndRefinement(refined_elems);
	}

	/*
	 * Related methods
	 */
	public static Object execAppleScript(String script_path) throws IOException, ScriptException {
		String script = readFile(script_path, Charset.defaultCharset());
		// System.out.println(script);

		// call runtime to execut applescript by using osa
		Runtime runtime = Runtime.getRuntime();
		String[] argus = { "osascript", "-e", script };
		Process process = runtime.exec(argus);

		// get the output of the "process"
		String method_output = "";
		String temp = "";
		BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
		while ((temp = in.readLine()) != null) {
			method_output += temp + "\n";
		}

		// BufferedInputStream bio = (BufferedInputStream) process.getInputStream();
		// int read_int;
		// while ((read_int=bio.read())!=-1)
		// method_output+=(char)read_int;

		// System.out.println(method_output);

		// has been depleted in the new released OS X
		// ScriptEngineManager mgr = new ScriptEngineManager();
		// ScriptEngine engine = mgr.getEngineByName("AppleScript");
		// Object s = engine.eval(script);

		return method_output;
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
