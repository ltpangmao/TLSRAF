package it.unitn.tlsraf.func;

import it.unitn.tlsraf.ds.ActorAssociationGraph;
import it.unitn.tlsraf.ds.AntiGoal;
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
import java.util.LinkedList;
import java.util.logging.Level;

import javax.script.ScriptException;

public class AntiGoalInference {
	
	public static void antiGoalRefine(RequirementGraph req_model, String type, int scope) throws IOException, ScriptException {
		String formal_model = req_model.generateFormalExpressionToFile(scope);
		
		String security_pattern_knowledge_file = InfoEnum.current_directory+"/dlv/models/security_model_"+req_model.getLayer().toLowerCase()+".dl ";
		String threat_knowledge = InfoEnum.current_directory+"/dlv/anti_goal_rules/threat_knowledge.rule ";
		// absolute path: /Users/litong30/research/Trento/Workspace/research/TLSAF/
		String refine_rule = "";
		if (type.equals(InfoEnum.RefinementDimension.ASSET.name())) {
			refine_rule = InfoEnum.current_directory+"/dlv/dlv -silent -nofacts "
					+ InfoEnum.current_directory+"/dlv/anti_goal_rules/refine_asset.rule "
					+ InfoEnum.current_directory+"/dlv/models/asset_model.dl "
					+ formal_model;
		} else if (type.equals(InfoEnum.RefinementDimension.PROTECTION.name())) {
			refine_rule = InfoEnum.current_directory+"/dlv/dlv -silent -nofacts "
					+ InfoEnum.current_directory+"/dlv/anti_goal_rules/refine_protection.rule "
					+ formal_model+ security_pattern_knowledge_file + threat_knowledge;
		} else if (type.equals(InfoEnum.RefinementDimension.TARGET.name())) {
			refine_rule = InfoEnum.current_directory+"/dlv/dlv -silent -nofacts "
					+ InfoEnum.current_directory+"/dlv/anti_goal_rules/refine_target.rule " 
					+ formal_model+security_pattern_knowledge_file+ threat_knowledge;
		} else if (type.equals(InfoEnum.RefinementDimension.THREAT.name())) {
			refine_rule = InfoEnum.current_directory+"/dlv/dlv -silent -nofacts "
					+ InfoEnum.current_directory+"/dlv/anti_goal_rules/refine_threat.rule " 
					+ formal_model+security_pattern_knowledge_file + threat_knowledge;
		} else {
			CommandPanel.logger.severe("Error refinement type!");
			return;
		}

		Runtime rt = Runtime.getRuntime();
		Process pr = rt.exec(refine_rule);

		BufferedReader input = new BufferedReader(new InputStreamReader(pr.getInputStream()));
		String line = null;

		/*
		 * having the restriction that we only process "and_refined_sec_goal" we
		 * could harden a bit drawing logic into code.
		 */
		//		LinkedList<RequirementLink> new_links = new LinkedList<RequirementLink>();
		LinkedList<RequirementElement> refined_elems = new LinkedList<RequirementElement>();

		// parse reasoning result
		while ((line = input.readLine()) != null) {
			line = line.substring(1, line.length() - 1);
			String[] result = line.split(", ");
			for (String s : result) {
				// System.out.println(s);
				// only consider related security goals
				if (s.startsWith("and_refined_anti_goal")&& (s.contains("unknown")==false)) {
					// parse facts
					s = s.replaceAll("and_refined_anti_goal\\(", "");
					s = s.replaceAll("\\)", "");
					String[] ag_args = s.split(",");
					// create new element`
					AntiGoal refined_ag = (AntiGoal) req_model.findElementByFormalName(ag_args[4]);
					AntiGoal new_ag = new AntiGoal(ag_args[0], ag_args[1], ag_args[2], ag_args[3],
							InfoEnum.RequirementElementType.ANTI_GOAL.name(), refined_ag.getLayer());

					req_model.getElements().add(new_ag);
					// create new link
					RequirementLink new_and_refine = new RequirementLink(
							InfoEnum.RequirementLinkType.AND_REFINE.name(), new_ag, refined_ag);
					req_model.getLinks().add(new_and_refine);

					refined_ag.and_refine_links.add(new_and_refine);
					if (refined_elems.indexOf(refined_ag) == -1) {
						refined_elems.add(refined_ag);
					}
				}
				if(s.startsWith("refined_anti_goal") && (s.contains("unknown")==false)){
					// parse facts
					s = s.replaceAll("refined_anti_goal\\(", "");
					s = s.replaceAll("\\)", "");
					String[] ag_args = s.split(",");
					// create new element`
					AntiGoal refined_ag = (AntiGoal) req_model.findElementByFormalName(ag_args[4]);
					AntiGoal new_ag = new AntiGoal(ag_args[0], ag_args[1], ag_args[2], ag_args[3],
							InfoEnum.RequirementElementType.ANTI_GOAL.name(), refined_ag.getLayer());

					req_model.getElements().add(new_ag);
					// create new link
					RequirementLink new_refine = new RequirementLink(
							InfoEnum.RequirementLinkType.REFINE.name(), new_ag, refined_ag);
					req_model.getLinks().add(new_refine);
					// draw single refinement
					drawRefinement(refined_ag, new_refine);
				}
			}
		}
		// draw all "and-refinements"
		drawAndRefinement(refined_elems);
	}

	/**
	 * Draw (OR-)refinement link 
	 * This can also be a general method for drawing all (or-)refinements
	 * @param refined_elem
	 * @param refine_link
	 * @throws ScriptException
	 */
	private static void drawRefinement(RequirementElement refined_goal, RequirementLink refine_link) throws ScriptException {
		String source_id = AppleScript.drawRequirementElement(refine_link.getSource(), refined_goal,"down");
		refine_link.getSource().setId(source_id);
		
		//add mouse-over annotation
//		AppleScript.addUserData(InfoEnum.REQ_TARGET_CANVAS, target_link.getSource().getLayer(), target_link.getSource().getId(),
//				target_link.getSource().owner.getFormalName());
		
		// if there is only one refinement, we change and_refine to refine
		refine_link.setType(InfoEnum.RequirementLinkType.REFINE.name());
		String link_id = AppleScript.drawRequirementLink(refine_link, InfoEnum.SINGLE_LAYER);
		refine_link.setId(link_id);
	}
	
	/**
	 * Draw (AND-)refinement link
	 * This drawing method is sort of general, i.e., contain only mandatory steps
	 * @param refined_elems
	 * @throws ScriptException
	 */
	private static void drawAndRefinement(LinkedList<RequirementElement> refined_elems) throws ScriptException {
		// draw the reasoning result on omnigraffle
		for (RequirementElement refined_goal : refined_elems) {
			if (refined_goal.and_refine_links.size() == 1) {
				RequirementLink target_link = refined_goal.and_refine_links.getFirst();
				drawRefinement(refined_goal, target_link);
			} else {
				// redundant link
				RequirementElement mid = new RequirementElement("",
						InfoEnum.RequirementElementType.MIDDLE_POINT.name(), refined_goal.getLayer());
				String mid_id = AppleScript.drawRequirementElement(mid, refined_goal, "down");
				mid.setId(mid_id);
				// doesn't add this into the logic model, as it does not make sense
				RequirementLink redundant_link = new RequirementLink(
						InfoEnum.RequirementLinkType.AND_REFINE_ARROW.name(), mid, refined_goal);
				redundant_link.setRemark(InfoEnum.LinkRemark.REDUNDANT.name());

				String redundant_id = AppleScript.drawRequirementLink(redundant_link, InfoEnum.SINGLE_LAYER);
				redundant_link.setId(redundant_id);
				// every and_refine link
				RequirementLink first_rl = refined_goal.and_refine_links.getFirst();
				RequirementElement first_re = first_rl.getSource();
				String temp_id = AppleScript.drawRequirementElement(first_re, mid, "down");
				first_re.setId(temp_id);
				
				//add mouse-over annotation
//				AppleScript.addUserData("Model", first_re.getLayer(), first_re.getId(), first_re.owner.getFormalName());
				
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
					
					//add mouse-over annotation
//					AppleScript.addUserData("Model", next.getLayer(), next.getId(), next.owner.getFormalName());

					link_id = AppleScript.drawRequirementLink(fake_rl, InfoEnum.SINGLE_LAYER);
					fake_rl.setId(link_id);
				}
			}
		}
	}
	
	
	
	
	//The actor association graph may not need, depending the simplification methods
	public static void exhaustiveAntiGoalRefineAnalysis(RequirementGraph req_model, ActorAssociationGraph actor_model, int visual_type, int scope) throws IOException, ScriptException {
		// first empty the potential security goal set.
		req_model.ag_elems.clear();
		req_model.ag_links.clear();
		
		String expression_file = req_model.generateFormalExpressionToFile(scope);
		String security_model_file = InfoEnum.current_directory+"/dlv/models/security_model_"+req_model.getLayer().toLowerCase()+".dl ";
		String threat_knowledge = InfoEnum.current_directory+"/dlv/anti_goal_rules/threat_knowledge.rule ";
		
		String refine_rule = "";
		refine_rule = InfoEnum.current_directory+"/dlv/dlv -silent -nofacts "
				+ InfoEnum.current_directory+"/dlv/anti_goal_rules/refine_all.rule "
				+ InfoEnum.current_directory+"/dlv/models/asset_model.dl "
				+ expression_file + security_model_file + threat_knowledge;
		Runtime rt = Runtime.getRuntime();
		Process pr = rt.exec(refine_rule);

		BufferedReader input = new BufferedReader(new InputStreamReader(pr.getInputStream()));
		String line = null;
		
		// parse inference results
		while ((line = input.readLine()) != null) {
			line = line.substring(1, line.length() - 1);
			String[] result = line.split(", ");
			//Assign all security goals with ordered numbers, which are just used as identifiers.
			int number = 1;
			for (String s : result) {
				// only consider related security goals
				if (s.startsWith("ex_refined_anti_goal") && !s.contains("unknown")) {
					// parse facts
					s = s.replaceAll("ex_refined_anti_goal\\(", "");
					s = s.replaceAll("\\)", "");
					String[] ag = s.split(",");

					// create two anti goals, and the refinement relation between them.
					AntiGoal child_ag = req_model.findExhausiveAntiGoalByAttributes(ag[0], ag[1], ag[2], ag[3]);
					AntiGoal parent_ag = req_model.findExhausiveAntiGoalByAttributes(ag[4], ag[5], ag[6], ag[7]);
					
					//add elements to the anti goal graph
					if (child_ag == null) {
						child_ag = new AntiGoal(ag[0], ag[1], ag[2], ag[3],
								InfoEnum.RequirementElementType.ANTI_GOAL.name(), req_model.getLayer());
						child_ag.setId(String.valueOf(number));
						number++;
						req_model.ag_elems.add(child_ag);
					}
					if (parent_ag == null) {
						parent_ag = new AntiGoal(ag[4], ag[5], ag[6], ag[7],
								InfoEnum.RequirementElementType.ANTI_GOAL.name(), req_model.getLayer());
						parent_ag.setId(String.valueOf(number));
						number++;
						req_model.ag_elems.add(parent_ag);
					}
					
					// create the new refinement link (by default is "and")
					RequirementLink new_and_refine = new RequirementLink(
							InfoEnum.RequirementLinkType.AND_REFINE.name(), child_ag, parent_ag);
					new_and_refine.refine_type = ag[8];
					// change the type of the link, if necessary
					if(new_and_refine.refine_type.contains("o_")){
						new_and_refine.setType(InfoEnum.RequirementLinkType.REFINE.name());
					}
					
					//the refinement links should always be added, as there may be several elements that refine/be refined to one element.
					if(!req_model.ag_links.contains(new_and_refine)){
						req_model.ag_links.add(new_and_refine);
					}
					
					//add the refinement link to the target anti goal
					if(new_and_refine.getType().equals(InfoEnum.RequirementLinkType.AND_REFINE.name())){
						parent_ag.and_refine_links.add(new_and_refine);
					} else{
						parent_ag.refine_links.add(new_and_refine);
					}
					child_ag.parent = parent_ag;
					child_ag.parent_link = new_and_refine;	
				}
			}
		}

			//visualize exhaustive refinements via Graphviz
//			if(visual_type==InfoEnum.GRAPHVIZ){
//				// graphviz can generate the three view separately
//				visualizeGraph(req_model, actor_model, InfoEnum.GRAPHVIZ, InfoEnum.INITIAL_VIEW);
//				visualizeGraph(req_model, actor_model, InfoEnum.GRAPHVIZ, InfoEnum.HIGHLIGHT_VIEW);
//				visualizeGraph(req_model, actor_model, InfoEnum.GRAPHVIZ, InfoEnum.SIMPLIFIED_VIEW);
//			}else if (visual_type == InfoEnum.CANVAS){
//				// we only provide one view in the canvas
				visualizeEAGGraph(req_model, actor_model, InfoEnum.CANVAS, InfoEnum.INITIAL_VIEW);
//				// the highlight and simpliefied view are put together in one view
//				visualizeGraph(req_model, actor_model, InfoEnum.CANVAS, InfoEnum.HIGHLIGHT_VIEW);
//			}
//			else{
//				CommandPanel.logger.warning("Visualization type error!");
//			}
		}
		
	private static void visualizeEAGGraph(RequirementGraph req_model, ActorAssociationGraph actor_model, int type, int visualization) throws IOException, FileNotFoundException, UnsupportedEncodingException, ScriptException {
		// original graph
		if(visualization == 0){
			if (type == InfoEnum.GRAPHVIZ) {
				//TODO This is an alternative way for showing the graph
//				showSimpleGraphInGraphviz(req_model, visualization);
			} else if (type==InfoEnum.CANVAS){
				showEAGsInCanvas(req_model, visualization);
			}else{
			}
		} else{
			//TODO
//			//reprocess ownership of security goals
//			for(SecurityGoal sg: req_model.getSg_elem()){
//				SecurityGoal temp_sg = (SecurityGoal)req_model.findElementByFormalName(sg.getFormalName());
//				if(temp_sg!=null){
//					sg.setRemark(InfoEnum.ElementRemark.TOPSG.name());
//					sg.owner = temp_sg.owner;
//					propagateSecurityGoalOwnership(sg, temp_sg.owner);
//				}
//			}
//			// identify criticality for each potential security goals
//			identifyCriticalSecurityGoal(req_model, actor_model);
//			// identify best refinement path
//			identifyBestRefinePath(req_model);
//			// visualize security goals according to the type of visualization
//			if (type == InfoEnum.GRAPHVIZ) {
//				// visualize security goals in Graphviz
//				showSimpleGraphInGraphviz(req_model, visualization);
//			} else if (type==InfoEnum.CANVAS){
//				// visualize security goals in Canvas
//				showSimpleGraphInCanvas(req_model, visualization);
//			} else{
//			}
			
		}
	}
	
	/**
	 * Show all anti-goal elements in a separate canvas
	 * Currently, it supports two view (without the "simplified view")
	 * @param req_model
	 * @param visualization
	 * @throws ScriptException
	 */
	private static void showEAGsInCanvas(RequirementGraph req_model, int visualization) throws ScriptException {
		//processing elements
		for (AntiGoal ag: req_model.ag_elems){
			String element_id = AppleScript.drawArbitraryRequirementElement(
					InfoEnum.eag_canvas_mapping.get(req_model.getLayer()), "All",
					InfoEnum.reverse_req_elem_type_map.get(InfoEnum.RequirementElementType.ANTI_GOAL.name()),
					InfoEnum.NORMAL_SIZE, "{500,500}", "0", ag.getName(), "0", "1");
			ag.setId(element_id);

			// support highlighting elements in the highlight view
			if (visualization == InfoEnum.HIGHLIGHT_VIEW && ag.isCriticality()) {
				AppleScript.changeAttributeOfElement(InfoEnum.eag_canvas_mapping.get(req_model.getLayer()), "none", element_id,
						"5", "Red", "Simple");
			} else if (visualization == InfoEnum.HIGHLIGHT_VIEW
					&& ag.getRemark().equals(InfoEnum.ElementRemark.BESTPATH.name())) {
				//only process under particular view.
				AppleScript.changeAttributeOfElement(InfoEnum.esg_canvas_mapping.get(req_model.getLayer()), "none", element_id,
						"5", "Blue", "Simple");
			}
			//if(sg.getRemark().equals(InfoEnum.ElementRemark.TOPSG.name()))
		}
		
		//processing links
		for (RequirementLink rl : req_model.ag_links) {
			String link_id = AppleScript.drawExhaustiveRefinementLink(rl);
			rl.setId(link_id);
			//set the layer of the link to "All", which cannot be done in last step...
			//TODO: further work might be done to fix this problem.
			AppleScript.changeAttributeOfLink(InfoEnum.eag_canvas_mapping.get(rl.getSource().getLayer()), "none",
					rl.getId(), "1", "none", "All");
			
			if (visualization == InfoEnum.HIGHLIGHT_VIEW && rl.getRemark().equals(InfoEnum.LinkRemark.BESTPATH.name())) {
				AppleScript.changeAttributeOfLink(InfoEnum.eag_canvas_mapping.get(rl.getSource().getLayer()), "none",
						rl.getId(), "3", "Blue", "Simple");
			}
			//if(((SecurityGoal)rl.getSource()).isCriticality() && ((SecurityGoal)rl.getTarget()).isCriticality())
		}
	}
	
}
