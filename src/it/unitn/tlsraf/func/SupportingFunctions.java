package it.unitn.tlsraf.func;

import it.unitn.tlsraf.ds.Element;
import it.unitn.tlsraf.ds.InfoEnum;
import it.unitn.tlsraf.ds.RequirementElement;
import it.unitn.tlsraf.ds.RequirementGraph;
import it.unitn.tlsraf.ds.RequirementLink;
import it.unitn.tlsraf.ds.SecurityGoal;
import it.unitn.tlsraf.ds.Threat;

import java.io.IOException;
import java.util.ArrayList;

import javax.script.ScriptException;

/**
 * This class includes various functions that support modeling activities.
 * These functions are not mandatory for apply our approach, but can improve NFRs.
 * Probably, this class has lower priority compared to the ones in the Inference class. 
 * @author tongli
 *
 */
public class SupportingFunctions {

	/**
	 * Generate support links and elements for selected security mechanism (can include task as well) 
	 * this feature is mainly used to support modeling
	 * @param up_req_model
	 * @param down_req_model
	 * @param scope
	 * @throws ScriptException
	 * @throws IOException
	 */
	public static void generateCrossLayerSupport(RequirementGraph up_req_model, RequirementGraph down_req_model, int scope){
		// obtain selected elements' id
		ArrayList<Long> selected_elements = null;
		try {
			// here the returned value won't be null
			selected_elements = AppleScript.getSelectedGraph();
			// find the selected elements in the upper layer
			for (Element e : up_req_model.getElements()) {
				// We only selectively choose security mechanisms (and task) for this support analysis
				if ((e.getType().equals(InfoEnum.RequirementElementType.TASK.name()) || e.getType().equals(InfoEnum.RequirementElementType.SECURITY_MECHANISM.name()))
						&& selected_elements.contains(Long.valueOf(e.getId()))) {
					// create and draw the node
					RequirementElement support_goal = new RequirementElement("Support "+ e.getName().toLowerCase(), InfoEnum.RequirementElementType.GOAL.name(), down_req_model.getLayer());
					String support_goal_id, support_link_id;
					support_goal_id = AppleScript.drawRequirementElement(support_goal, (RequirementElement)e, "down");
					support_goal.setId(support_goal_id);
					// create and draw the link
					RequirementLink support_link = new RequirementLink(InfoEnum.RequirementLinkType.SUPPORT.name(), support_goal, (RequirementElement)e);
					support_link_id = AppleScript.drawRequirementLink(support_link, InfoEnum.CROSS_LAYERS);
					support_link.setId(support_link_id);
				}
			}
		} catch (ScriptException e1) {
			e1.printStackTrace();
		}
	}
	
	
	
	/**
	 * This function first obtain the selected security goal, and then return the threats to these security goals.
	 * @param ms 
	 * 
	 * @return
	 */
	public static String getThreatScenarios(ModelSet ms) {
		String threat_scenarios = "";
		// first obtain the selected security goal
		try {
			ArrayList<Long> selected_element_ids = AppleScript.getSelectedGraph();
			if(selected_element_ids.size()==0){
				// this indicates no elements has been selected
				return null;
			}
			if(ms.threats==null){
				return "no threats have been imported to the model set";
			}
			for(Long element_id: selected_element_ids){
				RequirementElement re = ms.findRequirementElementByID(String.valueOf(element_id));
				if(re!=null && re.getType().equals(InfoEnum.RequirementElementType.SECURITY_GOAL.name())){
					// traverse the threats that are related to 
					for(String threat_id: ((SecurityGoal)re).threats){
						Threat temp = null;
						if(ms.threats!=null){
							// find the threat element
							for(Threat threat: ms.threats){
								if(threat.getId().equals(threat_id)){
									temp = threat;
									break;
								}
							}
							if(temp!=null){
								// show the detailed threat scenario
//								for(String scenario: temp.getScenarios()){
//									threat_scenarios += scenario+"\n\n\n";
//								}
								
								// show the name of the threat
								threat_scenarios += temp.getName()+"\n";
							}
						}
					}
					// we here only process the first found security goal, i.e., only one security goal will be processed
					break;
				}
			}
			return threat_scenarios;
		} catch (ScriptException e) {
			e.printStackTrace();
		}
		return null;
	}


	/**
	 * This method will tag the selected critical security goals as critical and then highlight them in the canvas.
	 * @param ms
	 * @return
	 */
	public static Boolean criticalityTagging(ModelSet ms) {
		Boolean success = false;
		// first obtain the selected security goal
		try {
			ArrayList<Long> selected_element_ids = AppleScript.getSelectedGraph();
			if(selected_element_ids.size()==0){
				// this indicates no elements has been selected
				return success;
			}
			for(Long element_id: selected_element_ids){
				RequirementElement re = ms.findRequirementElementByID(String.valueOf(element_id));
				if(re!=null && re.getType().equals(InfoEnum.RequirementElementType.SECURITY_GOAL.name())){
					SecurityGoal sg = (SecurityGoal)re;
					// set criticality
					sg.setCriticality(true);
					// highlight in the canvas
					AppleScript.changeAttributeOfElement(InfoEnum.REQ_TARGET_CANVAS, sg.getLayer(), sg.getId(), "5", "none", "none");
					success = true;
				}
			}
		} catch (ScriptException e) {
			e.printStackTrace();
			return false;
		}
		return success;
	}

}
