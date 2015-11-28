package it.unitn.tlsraf.func;

import it.unitn.tlsraf.ds.ActorAssociationGraph;
import it.unitn.tlsraf.ds.Element;
import it.unitn.tlsraf.ds.HolisticSecurityGoalModel;
import it.unitn.tlsraf.ds.InfoEnum;
import it.unitn.tlsraf.ds.Link;
import it.unitn.tlsraf.ds.RequirementElement;
import it.unitn.tlsraf.ds.RequirementGraph;
import it.unitn.tlsraf.ds.RequirementLink;
import it.unitn.tlsraf.ds.InfoEnum.Layer;
import it.unitn.tlsraf.ds.InfoEnum.ModelCategory;
import it.unitn.tlsraf.ds.InfoEnum.RequirementLinkType;
import it.unitn.tlsraf.ds.Threat;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

/**
 * A collection of models that are involved in our analysis
 * As the whole analysis may use different models (modeled in different diagrams),
 * this class is responsible for synthesizing and regulating all these models
 * @author litong30
 */


public class ModelSet {
	public RequirementGraph req_bus_model;
	public RequirementGraph req_app_model;
	public RequirementGraph req_phy_model;
	
	public ActorAssociationGraph actor_model;
	public HolisticSecurityGoalModel hsgm;
	public LinkedList<String> assets;
	public LinkedList<Threat> threats;
	
	public LinkedList<Link> bus_app_support_links = new LinkedList<Link>();
	public LinkedList<Link> app_phy_support_links = new LinkedList<Link>();

	// Graph asset_model = new Graph(InfoEnum.ModelCategory.REQUIREMENT.name());
	// Graph bp_model = new Graph(InfoEnum.ModelCategory.REQUIREMENT.name());

	public ModelSet() {
		super();
		req_bus_model = new RequirementGraph(InfoEnum.ModelCategory.REQUIREMENT.name(),
				InfoEnum.Layer.BUSINESS.name());
		req_app_model = new RequirementGraph(InfoEnum.ModelCategory.REQUIREMENT.name(),
				InfoEnum.Layer.APPLICATION.name());
		req_phy_model = new RequirementGraph(InfoEnum.ModelCategory.REQUIREMENT.name(),
				InfoEnum.Layer.PHYSICAL.name());
		
		actor_model = new ActorAssociationGraph(InfoEnum.ModelCategory.ACTOR.name());
		hsgm = new HolisticSecurityGoalModel(InfoEnum.ModelCategory.HOLISTIC_SECURITY_GOAL_MODEL.name());
		assets = new LinkedList<String>(); 
		threats = new LinkedList<Threat>();
	}
	
	/**
	 * Parse and import all support links which cross layers.
	 * Here, we suppose that the three layer-specific models have been well processed
	 * Another redundant method had already been implemented in the inference... 
	 * However, this class will provide the overview of all the related models anyway. 
	 */
	public void importSupportLinks(){
		parseSupportLinks(this.req_bus_model, this.req_app_model, this.bus_app_support_links);
		parseSupportLinks(this.req_app_model, this.req_phy_model, this.app_phy_support_links);
//		writeToFile();
	}


	/**
	 * Output existing support links 
	 */
	public void writeSupportLinksToFile() {
		String support = "";
		support += getSupportLinkFormalExpression(this.bus_app_support_links);
		support += getSupportLinkFormalExpression(this.app_phy_support_links);
		
		Func.writeFile("dlv/models/support_links.dl", support, false);
	}

	/**
	 * This method search all requirement elements in the "Model" canvas 
	 * @param id
	 * @return
	 */
	public RequirementElement findRequirementElementByID(String id){
		RequirementElement re = null;
		re = (RequirementElement) this.req_bus_model.findElementById(id);
		if(re==null){
			re = (RequirementElement) this.req_app_model.findElementById(id);
			if(re==null){
				re = (RequirementElement) this.req_phy_model.findElementById(id);
			}
		}
		return re;
	}
	
	
	
	
	
	/**
	 * Get formal expressions of all support links 
	 * @param support_link_set
	 * @return
	 */
	private String getSupportLinkFormalExpression(LinkedList<Link> support_link_set) {
		String result = "";
		for(Link link: support_link_set){
			result+=link.getFormalExpressions()+"\n";
		}
		return result;
	}

	/**
	 * This method complements the information of each support link and adds it to the set of support links.
	 * If the info of requirements models is not complete, then the support link will be still empty.
	 * @param high_req_model
	 * @param low_req_model
	 * @param support_links
	 */
	private void parseSupportLinks(RequirementGraph high_req_model, RequirementGraph low_req_model, LinkedList<Link> support_links){
		for(Link link: low_req_model.getLinks()){
			RequirementLink support = (RequirementLink) link;
			if(support.getType().equals(InfoEnum.RequirementLinkType.SUPPORT.toString())){
				//search the source/target elements for each support link
				// assign the value only if we can find such an element
				Element elem = low_req_model.findElementById(support.source_id);
				if(elem!=null){
					support.setSource(elem);
				}
				elem =high_req_model.findElementById(support.des_id);
				if(elem!=null){
					support.setTarget(elem);
				}
				// add this link to the set of support links
				support_links.add(support);
			}
		}
	}
	
}
