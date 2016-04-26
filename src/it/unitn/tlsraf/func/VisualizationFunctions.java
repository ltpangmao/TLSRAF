package it.unitn.tlsraf.func;

import it.unitn.tlsraf.ds.Actor;
import it.unitn.tlsraf.ds.ActorAssociationGraph;
import it.unitn.tlsraf.ds.InfoEnum;
import it.unitn.tlsraf.ds.RequirementElement;
import it.unitn.tlsraf.ds.RequirementGraph;
import it.unitn.tlsraf.ds.RequirementLink;
import it.unitn.tlsraf.ds.SecurityGoal;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.LinkedList;

import javax.script.ScriptException;

public class VisualizationFunctions {
	
	/**
	 * This function is used to check whether an security element (goal/mechanism) has been selected
	 * It is used to deal with the situation, when DLV -nofacts doesn't work well for whatever reasons
	 * 
	 * @param target_id
	 */
	public static boolean selectionCheck(String target_id) {
		// obtain selected elements' id
		ArrayList<Long> selected_elements = null;
		try {
			// here the returned value won't be null
			selected_elements = AppleScript.getSelectedGraph();
		} catch (ScriptException e1) {
			e1.printStackTrace();
		}
		
		if(selected_elements==null){
			return false;
		}
		else{
			if(selected_elements.contains(Long.valueOf(target_id))){
				return true;
			}
		}
		
		return false;
	}

	
	
	/**
	 * As the and-refine is not directly drawn in the picture, a bit more processing is required.
	 * 
	 * Currently, this method is particularly designed for refining "security goals" (specific notes) The more general one can be found in the AntiGoalInference class
	 * 
	 * @param refined_elems
	 *            : a list of elements (security goals) that are fined.
	 * @throws ScriptException
	 */
	public static void drawAndRefinement(LinkedList<RequirementElement> refined_elems) throws ScriptException {
		// draw the reasoning result on omnigraffle
		for (RequirementElement refined_goal : refined_elems) {
			if (refined_goal.and_refine_links.size() == 1) {
				RequirementLink target_link = refined_goal.and_refine_links.getFirst();
				String source_id = AppleScript.drawRequirementElement(target_link.getSource(), refined_goal, "down");
				target_link.getSource().setId(source_id);
				// add mouse-over annotation owner.getFormalName()
				AppleScript.addUserData2(InfoEnum.REQ_TARGET_CANVAS, target_link.getSource().getLayer(), (SecurityGoal)target_link.getSource(),
						target_link.getSource().owner_text);
				// if there is only one refinement, we change and_refine to
				// refine
				target_link.setType(InfoEnum.RequirementLinkType.REFINE.name());
				String link_id = AppleScript.drawRequirementLink(target_link, InfoEnum.SINGLE_LAYER);
				target_link.setId(link_id);
			} else {
				// redundant link
				RequirementElement mid = new RequirementElement("", InfoEnum.RequirementElementType.MIDDLE_POINT.name(), refined_goal.getLayer());
				String mid_id = AppleScript.drawRequirementElement(mid, refined_goal, "down");
				mid.setId(mid_id);
				// doesn't add this into the logic model, as it does not make
				// sense.
				RequirementLink redundant_link = new RequirementLink(InfoEnum.RequirementLinkType.AND_REFINE_ARROW.name(), mid, refined_goal);
				redundant_link.setRemark(InfoEnum.LinkRemark.REDUNDANT.name());

				String redundant_id = AppleScript.drawRequirementLink(redundant_link, InfoEnum.SINGLE_LAYER);
				redundant_link.setId(redundant_id);
				// every and_refine link
				RequirementLink first_rl = refined_goal.and_refine_links.getFirst();
				RequirementElement first_re = first_rl.getSource();
				String temp_id = AppleScript.drawRequirementElement(first_re, mid, "down");
				first_re.setId(temp_id);
				// add mouse-over annotation
				AppleScript.addUserData2("Model", first_re.getLayer(), (SecurityGoal)first_re, first_re.owner_text);

				RequirementLink fake_rl = new RequirementLink(first_rl.getType(), first_rl.getSource(), mid);
				String link_id = AppleScript.drawRequirementLink(fake_rl, InfoEnum.SINGLE_LAYER);
				fake_rl.setId(link_id);

				// refined_goal.refine_links.removeFirst();
				RequirementElement next = null;
				RequirementElement reference = first_re;
				RequirementLink rl = null;
				for (int i = 1; i < refined_goal.and_refine_links.size(); i++) {
					rl = refined_goal.and_refine_links.get(i);
					fake_rl = new RequirementLink(rl.getType(), rl.getSource(), mid);
					next = rl.getSource();
					String next_id = AppleScript.drawRequirementElement(next, reference, "right");
					next.setId(next_id);
					reference = next;
					// add mouse-over annotation
					AppleScript.addUserData2("Model", next.getLayer(), (SecurityGoal)next, next.owner_text);

					link_id = AppleScript.drawRequirementLink(fake_rl, InfoEnum.SINGLE_LAYER);
					fake_rl.setId(link_id);
				}
			}
		}
	}

	

	/**
	 * @param req_model
	 * @param actor_model
	 * @param visualization
	 * @throws IOException
	 * @throws FileNotFoundException
	 * @throws UnsupportedEncodingException
	 * @throws ScriptException
	 */
	public static void visualizeGraph(ModelSet ms, RequirementGraph req_model, ActorAssociationGraph actor_model, int type, int visualization) throws IOException, FileNotFoundException,
			UnsupportedEncodingException, ScriptException {
		// original graph
		if (visualization == InfoEnum.INITIAL_VIEW) {
			if (type == InfoEnum.GRAPHVIZ) {
				// visualize security goals in Graphviz
				showExhaustiveGraphInGraphviz(req_model, visualization);
			} else if (type == InfoEnum.CANVAS) {
				// visualize security goals in Canvas
				showExhaustiveGraphInCanvas(req_model, visualization);
			} else {
			}
		} else {
			/***** This part is problematic after certain changes.
			 * As it is originally designed for perform trust-based security analysis, we don't really need it here. 
			 * So, to be aware that, after commenting this code, we are going to abandon the trust-based analysis.
			 * */
			// reprocess ownership of security goals
			for (SecurityGoal sg : req_model.getSg_elem()) {
				SecurityGoal temp_sg = (SecurityGoal) req_model.findElementByFormalName(sg.getFormalName());
				if (temp_sg != null) {
					sg.setRemark(InfoEnum.ElementRemark.TOPSG.name());
					sg.owner = temp_sg.owner;
					propagateSecurityGoalOwnership(sg, temp_sg.owner);
				}
			}
			
			// identify criticality for each potential security goals
			identifyCriticalSecurityGoal(ms, req_model, actor_model);
			// identify best refinement path
			identifyBestRefinePath(req_model);
			
			// visualize security goals according to the type of visualization
			if (type == InfoEnum.GRAPHVIZ) {
				// visualize security goals in Graphviz
				showExhaustiveGraphInGraphviz(req_model, visualization);
			} else if (type == InfoEnum.CANVAS) {
				// visualize security goals in Canvas
				showExhaustiveGraphInCanvas(req_model, visualization);
			} else {
			}

		}
	}

	private static void propagateSecurityGoalOwnership(SecurityGoal sg, Actor owner) {
		for (RequirementLink rl : sg.and_refine_links) {
			SecurityGoal temp_sg = (SecurityGoal) rl.getSource();
			temp_sg.owner = owner;
			propagateSecurityGoalOwnership(temp_sg, owner);
		}
	}

	/**
	 * bottom-up way for identifying best path currently the path is not guaranteed to be the best one, as the parent of critical goals are always replaced by the last one.
	 * 
	 * @param req_model
	 */
	private static void identifyBestRefinePath(RequirementGraph req_model) {
		for (SecurityGoal sg : req_model.getSg_elem()) {
			if (sg.isCriticality()) {
				if (sg.parent != null && sg.parent_link != null) {
					sg.parent.setRemark(InfoEnum.ElementRemark.BESTPATH.name());
					sg.parent_link.setRemark(InfoEnum.LinkRemark.BESTPATH.name());
					propagateBestRefinePath(sg.parent);
				}
			}
		}
	}

	private static void propagateBestRefinePath(SecurityGoal sg) {
		if (sg.parent != null && sg.parent_link != null) {
			sg.parent.setRemark(InfoEnum.ElementRemark.BESTPATH.name());
			sg.parent_link.setRemark(InfoEnum.LinkRemark.BESTPATH.name());
			propagateBestRefinePath(sg.parent);
		} else {
			return;
		}
	}

	
	/**
	 * top-down analysis for refinement path
	 * 
	 * @param req_model
	 */
	private static void identifyTopDownBestRefinePath(RequirementGraph req_model) {
		for (SecurityGoal sg : req_model.getSg_elem()) {
			if (sg.getRemark().equals(InfoEnum.ElementRemark.TOPSG.name())) {
				propagateTopDownBestRefinePath(sg);
			}
		}
	}

	private static void propagateTopDownBestRefinePath(SecurityGoal sg) {
		// sg.setRemark(InfoEnum.ElementRemark.BESTPATH.name());
		boolean refined = false;
		if (sg.isCriticality() || sg.isNon_deterministic()) {
			return;
		} else {
			// first refine via interval
			for (RequirementLink rl : sg.and_refine_links) {
				if (rl.refine_type.equals(InfoEnum.RefineType.INTERVAL.name())) {
					refined = true;
					rl.setRemark(InfoEnum.LinkRemark.BESTPATH.name());
					rl.getSource().setRemark(InfoEnum.ElementRemark.BESTPATH.name());
					propagateTopDownBestRefinePath((SecurityGoal) rl.getSource());
				}
			}
			// then, refine via security attribute
			if (!refined) {
				for (RequirementLink rl : sg.and_refine_links) {
					if (rl.refine_type.equals(InfoEnum.RefineType.ATTRIBUTE.name())) {
						refined = true;
						rl.setRemark(InfoEnum.LinkRemark.BESTPATH.name());
						rl.getSource().setRemark(InfoEnum.ElementRemark.BESTPATH.name());
						propagateTopDownBestRefinePath((SecurityGoal) rl.getSource());
					}
				}
				// finally, refine via asset
				if (!refined) {
					for (RequirementLink rl : sg.and_refine_links) {
						if (rl.refine_type.equals(InfoEnum.RefineType.ASSET.name())) {
							refined = true;
							rl.setRemark(InfoEnum.LinkRemark.BESTPATH.name());
							rl.getSource().setRemark(InfoEnum.ElementRemark.BESTPATH.name());
							propagateTopDownBestRefinePath((SecurityGoal) rl.getSource());
						}
					}
				}
			}
		}
	}

	
	/**
	 * during exhaustive security goal refinement analysis, this method is used to identify threats
	 * Initially, this method is designed to perform trust-based analysis, but now we have switch to threat-based analysis
	 * 
	 * @param req_model
	 * @throws FileNotFoundException
	 * @throws UnsupportedEncodingException
	 * @throws IOException
	 * @throws ScriptException
	 */
	private static void identifyCriticalSecurityGoal(ModelSet ms, RequirementGraph req_model, ActorAssociationGraph actor_model) throws FileNotFoundException, UnsupportedEncodingException,
			IOException, ScriptException {

		String ex_req_model_file = req_model.generateExhaustiveFormalExpression();
		// normally the actor association model keeps unchanged, so no need to rewrite it.
//		String actor_model_file = InfoEnum.current_directory + "/dlv/models/actor_association_model.dl ";
//		if (actor_model.getElements().size() != 0) {
//			actor_model_file = actor_model.generateFormalExpressionToFile();
//		}

		
		String inference_rule = "";
		// original trust-based criticality analysis
//		if (req_model.getLayer().equals(InfoEnum.Layer.BUSINESS.name())) {
//			inference_rule = InfoEnum.current_directory + "/dlv/dlv -silent -nofacts " + InfoEnum.current_directory + "/dlv/rules/simplification_bus.rule "
//					+ InfoEnum.current_directory + "/dlv/rules/simplification_general.rule " + InfoEnum.current_directory + "/dlv/models/business_process_model.dl "
//					+ InfoEnum.current_directory + "/dlv/models/asset_model.dl " + ex_req_model_file + " " + actor_model_file;
//		} else if (req_model.getLayer().equals(InfoEnum.Layer.APPLICATION.name())) {
//			inference_rule = InfoEnum.current_directory + "/dlv/dlv -silent -nofacts " + InfoEnum.current_directory + "/dlv/rules/simplification_app.rule "
//					+ InfoEnum.current_directory + "/dlv/rules/simplification_general.rule "
//					+ InfoEnum.current_directory
//					+ "/dlv/rules/sec_goal_ownership.rule " // infer security goal ownership from upper layers (deprecated).
//					// + InfoEnum.current_directory+"/dlv/models/temp_app_fact.dl "
//					+ InfoEnum.current_directory + "/dlv/models/software_architecture_model.dl " + InfoEnum.current_directory + "/dlv/models/asset_model.dl " + ex_req_model_file
//					+ " " + actor_model_file;
//		} else if (req_model.getLayer().equals(InfoEnum.Layer.PHYSICAL.name())) {
//			inference_rule = InfoEnum.current_directory + "/dlv/dlv -silent -nofacts " + InfoEnum.current_directory + "/dlv/rules/simplification_phy.rule "
//					+ InfoEnum.current_directory + "/dlv/rules/simplification_general.rule " + InfoEnum.current_directory + "/dlv/models/deployment_model.dl "
//					+ InfoEnum.current_directory + "/dlv/models/asset_model.dl " + ex_req_model_file + " " + actor_model_file;
//		} else {
//			CommandPanel.logger.severe("Error refinement type!");
//		}

		// Threat-based criticality analysis
		inference_rule = InfoEnum.current_directory + "/dlv/dlv -silent -nofacts " 
				+ InfoEnum.current_directory + "/dlv/rules/threat_based_simplification.rule "
				+ InfoEnum.current_directory + "/dlv/models/data_flow_model.dl " 
				+ InfoEnum.current_directory + "/dlv/models/threat_model.dl " 
				+ InfoEnum.current_directory + "/dlv/models/asset_model.dl " + ex_req_model_file;

		String req_bus_model_file = ms.req_bus_model.generateExhaustiveFormalExpression();
		String req_app_model_file = ms.req_app_model.generateExhaustiveFormalExpression();
		String req_phy_model_file = ms.req_phy_model.generateExhaustiveFormalExpression();

		inference_rule = InfoEnum.current_directory + "/dlv/dlv -silent -nofacts " 
				+ InfoEnum.current_directory + "/dlv/rules/threat_based_simplification.rule "
				+ InfoEnum.current_directory + "/dlv/models/data_flow_model.dl " 
				+ InfoEnum.current_directory + "/dlv/models/threat_model.dl " 
				+ InfoEnum.current_directory + "/dlv/models/asset_model.dl " 
				+ req_bus_model_file + req_app_model_file + req_phy_model_file;

		Runtime rt = Runtime.getRuntime();
		Process pr = rt.exec(inference_rule);

		BufferedReader input = new BufferedReader(new InputStreamReader(pr.getInputStream()));
		String line = null;

		while ((line = input.readLine()) != null) {
			// line = input.readLine();
			line = line.substring(1, line.length() - 1);
			String[] result = line.split(", ");
			for (String s : result) {
				// highlight the critical one
				if (s.startsWith("is_critical")) {
					// parse facts
					s = s.replaceAll("is\\_critical\\(", "");
					s = s.replaceAll("\\)", "");
					
					int separator = s.indexOf(",");
					String sg_id = s.substring(0, separator);
					String threat_id = s.substring(separator+1);
					SecurityGoal critical_sec_goal = (SecurityGoal) req_model.findExhaustiveSecurityGoalByFormalName(sg_id);
					
					if (critical_sec_goal != null) {
						critical_sec_goal.applicability=true;
						critical_sec_goal.setCriticality(true);
						critical_sec_goal.threats.add(threat_id);
					} else {
						CommandPanel.logger.severe("critical secuirty goal error! "+ sg_id+ "  "+ s);
					}
				}
				// highlight the critical one
				else if (s.startsWith("is_applicable")) {
					// parse facts
					s = s.replaceAll("is\\_applicable\\(", "");
					s = s.replaceAll("\\)", "");

					SecurityGoal applicable_sec_goal = (SecurityGoal) req_model.findExhaustiveSecurityGoalByFormalName(s);
					
					if (applicable_sec_goal != null) {
						applicable_sec_goal.applicability=true;
					} else {
						CommandPanel.logger.severe("critical secuirty goal error! "+ s);
					}
				}
			}
		}
	}

	/**
	 * Show the initial exhaustive refinement results in OmniGraffle canvas, which only have critical security goal, not best path
	 * @param req_model
	 * @param visualization
	 * @throws ScriptException
	 */
	private static void showExhaustiveGraphInCanvas(RequirementGraph req_model, int visualization) throws ScriptException {
		// processing elements
		for (SecurityGoal sg : req_model.getSg_elem()) {
			String element_id = AppleScript.drawArbitraryRequirementElement(InfoEnum.esg_canvas_mapping.get(req_model.getLayer()), "All",
					InfoEnum.reverse_req_elem_type_map.get(InfoEnum.RequirementElementType.SOFTGOAL.name()), InfoEnum.NORMAL_SIZE, "{500,500}", "0", sg.getName(), "0", "1");
			sg.setId(element_id);

			if (sg.isCriticality()) {
				AppleScript.changeAttributeOfElement(InfoEnum.esg_canvas_mapping.get(req_model.getLayer()), "none", element_id, "5", "Red", "Simple");
			} 
			else if (sg.applicability==true) {
				AppleScript.changeAttributeOfElement(InfoEnum.esg_canvas_mapping.get(req_model.getLayer()), "none", element_id, "3", "Green", "All");
			} 
			else if (visualization != InfoEnum.INITIAL_VIEW && sg.getRemark().equals(InfoEnum.ElementRemark.BESTPATH.name())) {
				// only process under particular view.
				AppleScript.changeAttributeOfElement(InfoEnum.esg_canvas_mapping.get(req_model.getLayer()), "none", element_id, "5", "Blue", "Simple");
			}
			// if(sg.getRemark().equals(InfoEnum.ElementRemark.TOPSG.name()))
		}

		// processing links
		for (RequirementLink rl : req_model.getSg_links()) {
			String link_id = AppleScript.drawExhaustiveRefinementLink(rl);
			rl.setId(link_id);
			// set the layer of the link to "All", which cannot be done in last step...
			// TODO: further work might be done to fix this problem.
			AppleScript.changeAttributeOfLink(InfoEnum.esg_canvas_mapping.get(rl.getSource().getLayer()), "none", rl.getId(), "1", "none", "All");

			if (visualization != InfoEnum.INITIAL_VIEW && rl.getRemark().equals(InfoEnum.LinkRemark.BESTPATH.name())) {
				AppleScript.changeAttributeOfLink(InfoEnum.esg_canvas_mapping.get(rl.getSource().getLayer()), "none", rl.getId(), "3", "Blue", "Simple");
			}
			// if(((SecurityGoal)rl.getSource()).isCriticality() && ((SecurityGoal)rl.getTarget()).isCriticality())
		}
	}
	

	/**
	 * for exhaustive security goal refinement analysis This one only shows id of each security goal.
	 * 
	 * @param req_model
	 * @param visualization
	 * @throws FileNotFoundException
	 * @throws UnsupportedEncodingException
	 * @throws IOException
	 */
	private static void showExhaustiveGraphInGraphviz(RequirementGraph req_model, int visualization) throws IOException {
		
		// export the security goal graph and visualize it.
		// the simple way to represent the graph, which is based on the id of each element, it is simple, but does not make much sense.
		String graph = "digraph G {\n" + "rankdir = BT;\n";// Determine layout direction

		for (SecurityGoal sg : req_model.getSg_elem()) {
			String temp_graph = "";

			if (sg.isCriticality()) {
				temp_graph += "sg_" + sg.getNameForShow() + "[shape=ellipse, width=2, height=1.5, fixedsize = true, fontname=\"Helvetica-Bold\", style = filled, color = red];\n";
			} else if (sg.isNon_deterministic()) {
				temp_graph += "sg_" + sg.getNameForShow() + "[shape=ellipse, fontname=\"Helvetica-Bold\", style = filled, color = green];\n";
			} else {
				temp_graph += "sg_" + sg.getNameForShow() + "[shape=ellipse, width=2, height=1.5, fixedsize = true, fontname=\"Helvetica-Bold\"";
				// only process when visualization is 1.
				if (sg.getRemark().equals(InfoEnum.ElementRemark.BESTPATH.name())) {
					temp_graph += ", style = filled, color=blue";
				}
				temp_graph += "];\n";
			}

			// conditionally adding this edge.
			if (visualization != 2) {
				graph += temp_graph;
			} else if (sg.isCriticality() || sg.getRemark().equals(InfoEnum.ElementRemark.TOPSG.name()) || sg.getRemark().equals(InfoEnum.ElementRemark.BESTPATH.name())) {
				graph += temp_graph;
			}
		}

		for (RequirementLink rl : req_model.getSg_links()) {
			String temp_graph = "";
			SecurityGoal sg_source = (SecurityGoal) rl.getSource();
			SecurityGoal sg_target = (SecurityGoal) rl.getTarget();
			temp_graph += "sg_" + sg_source.getNameForShow() + " -> " + "sg_" + sg_target.getNameForShow();
			if (rl.refine_type.equals(InfoEnum.RefineType.ATTRIBUTE.name())) {
				temp_graph += "[label=\"S\"";
			} else if (rl.refine_type.equals(InfoEnum.RefineType.ASSET.name())) {
				temp_graph += "[label=\"A\"";
			} else if (rl.refine_type.equals(InfoEnum.RefineType.INTERVAL.name())) {
				temp_graph += "[label=\"I\"";
			} else {
				CommandPanel.logger.severe("Refinement type of the graph has problems.");
			}

			if (rl.getRemark().equals(InfoEnum.LinkRemark.BESTPATH.name())) {
				temp_graph += ", penwidth = 2.5, color=blue";
			}

			temp_graph += "];\n";

			// conditionally adding this edge.
			if (visualization != 2) { // non-trimmed graph
				graph += temp_graph;
			}
			// trimmed graph contains links, which are in the best path and are highlighted in blue
			else if (rl.getRemark().equals(InfoEnum.LinkRemark.BESTPATH.name())) {
				graph += temp_graph;
			}
			// trimmed graph also contains refinement links, which connect critical security goals
			else if (((SecurityGoal) rl.getSource()).isCriticality() && ((SecurityGoal) rl.getTarget()).isCriticality()) {
				graph += temp_graph;
			}
		}

		graph += "}";

		Func.writeFile(InfoEnum.current_directory + "/graphviz/sec_goal_" + visualization + ".gv", graph, false);

		
		/* this part doesn't work, probably the problem is related to the graphviz setting
		 * I may solve it in the future, but not now. 
		 * Currently, we just manually convert the figure. A good thing is that we can directly use OmniGraffle 
		 */
		// draw pdf figure for the corresponding graph
//		Runtime rt;
//		Process pr;
//		String draw_graphviz = InfoEnum.current_directory + "/graphviz/dot -Tpdf " + InfoEnum.current_directory + "/graphviz/sec_goal_" + visualization + ".gv -o "
//				+ InfoEnum.current_directory + "/graphviz/sec_goal_" + visualization + ".pdf";
//		rt = Runtime.getRuntime();
//		pr = rt.exec(draw_graphviz);
	}

	/**
	 * for exhaustive security goal refinement analysis This one shows the detailed content of each security goal
	 * 
	 * @param req_model
	 * @throws FileNotFoundException
	 * @throws UnsupportedEncodingException
	 * @throws IOException
	 */
	@Deprecated
	@SuppressWarnings({ "unused" })
	private static void showComplexGraph(RequirementGraph req_model) throws FileNotFoundException, UnsupportedEncodingException, IOException {

		// export the security goal graph and visualize it.
		String graph = "digraph G {\n" + "rankdir = BT\n";// Determine layout direction

		// This is a more complex way to represent security goals, which shows all dimensions.
		for (RequirementLink rl : req_model.getSg_links()) {
			SecurityGoal sg_source = (SecurityGoal) rl.getSource();
			SecurityGoal sg_target = (SecurityGoal) rl.getTarget();
			graph += sg_source.getId() + " [shape=none, margin=0, label=< " + "<TABLE BORDER=\"0\" CELLBORDER=\"1\" CELLSPACING=\"0\" CELLPADDING=\"5\">" + " <TR><TD>sg_"
					+ sg_source.getId() + "</TD></TR>" + " <TR><TD>" + sg_source.getImportance() + "</TD></TR>" + " <TR><TD>" + sg_source.getSecurityAttribute() + "</TD></TR>"
					+ " <TR><TD>" + sg_source.getAsset() + "</TD></TR>" + " <TR><TD>" + sg_source.getInterval() + "</TD></TR>" + " </TABLE>>];" + sg_target.getId()
					+ " [shape=none, margin=0, label=<" + "<TABLE BORDER=\"0\" CELLBORDER=\"1\" CELLSPACING=\"0\" CELLPADDING=\"5\">" + "<TR><TD>sg_" + sg_target.getId()
					+ "</TD></TR>" + "<TR><TD>" + sg_target.getImportance() + "</TD></TR>" + " <TR><TD>" + sg_target.getSecurityAttribute() + "</TD></TR>" + "<TR><TD>"
					+ sg_target.getAsset() + "</TD></TR>" + "<TR><TD>" + sg_target.getInterval() + "</TD></TR>" + "</TABLE>>];" + sg_source.getId() + " -> " + sg_target.getId();
			if (rl.refine_type.equals(InfoEnum.RefineType.ATTRIBUTE.name())) {
				graph += "[color=red, label=\"S\"];\n";
			} else if (rl.refine_type.equals(InfoEnum.RefineType.ASSET.name())) {
				graph += "[color=blue, label=\"A\"];\n";
			} else if (rl.refine_type.equals(InfoEnum.RefineType.INTERVAL.name())) {
				graph += "[color=green, label=\"I\"];\n";
			} else {
				CommandPanel.logger.severe("Refinement type of the graph has problems.");
			}
		}

		graph += "}";

		Func.writeFile(InfoEnum.current_directory + "/graphviz/sec_goal.gv", graph, false);

		// draw pdf figure for the corresponding graph
		Runtime rt;
		Process pr;
		String draw_graphviz = InfoEnum.current_directory + "/graphviz/dot -Tpdf " + InfoEnum.current_directory + "/graphviz/sec_goal.gv -o " + InfoEnum.current_directory
				+ "/graphviz/sec_goal.pdf";
		rt = Runtime.getRuntime();
		pr = rt.exec(draw_graphviz);
	}
	
}
