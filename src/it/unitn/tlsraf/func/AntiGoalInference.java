package it.unitn.tlsraf.func;

import it.unitn.tlsraf.ds.AntiGoal;
import it.unitn.tlsraf.ds.InfoEnum;
import it.unitn.tlsraf.ds.RequirementElement;
import it.unitn.tlsraf.ds.RequirementGraph;
import it.unitn.tlsraf.ds.RequirementLink;
import it.unitn.tlsraf.ds.SecurityGoal;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.LinkedList;

import javax.script.ScriptException;

public class AntiGoalInference {
	public static void antiGoalRefine(RequirementGraph req_model, String type, int scope) throws IOException, ScriptException {
		String formal_model = req_model.generateFormalExpressionToFile(scope);
		
		String security_model_file = InfoEnum.current_directory+"/dlv/models/security_model_"+req_model.getLayer().toLowerCase()+".dl ";
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
					+ formal_model+" "+security_model_file;
		} else if (type.equals(InfoEnum.RefinementDimension.TARGET.name())) {
			refine_rule = InfoEnum.current_directory+"/dlv/dlv -silent -nofacts "
					+ InfoEnum.current_directory+"/dlv/anti_goal_rules/refine_target.rule " 
					+ formal_model+" "+security_model_file;
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
					Boolean protection = Boolean.valueOf(ag_args[3]);
					AntiGoal new_ag = new AntiGoal(ag_args[0], ag_args[1], ag_args[2], protection,
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
					Boolean protection = Boolean.valueOf(ag_args[3]);
					AntiGoal new_ag = new AntiGoal(ag_args[0], ag_args[1], ag_args[2], protection,
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
	 * @param refined_elem
	 * @param refine_link
	 * @throws ScriptException
	 */
	private static void drawRefinement(RequirementElement refined_goal, RequirementLink refine_link) throws ScriptException {
		String source_id = AppleScript.drawRequirementElement(refine_link.getSource(), refined_goal,
				"down");
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
}
