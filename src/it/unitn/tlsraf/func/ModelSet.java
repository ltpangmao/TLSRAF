package it.unitn.tlsraf.func;

import it.unitn.tlsraf.ds.ActorAssociationGraph;
import it.unitn.tlsraf.ds.InfoEnum;
import it.unitn.tlsraf.ds.Link;
import it.unitn.tlsraf.ds.RequirementGraph;
import it.unitn.tlsraf.ds.RequirementLink;
import it.unitn.tlsraf.ds.InfoEnum.Layer;
import it.unitn.tlsraf.ds.InfoEnum.ModelCategory;
import it.unitn.tlsraf.ds.InfoEnum.RequirementLinkType;

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
				support.setSource(low_req_model.findElementById(support.source_id));
				support.setTarget(high_req_model.findElementById(support.des_id));
				// add this link to the set of support links
				support_links.add(support);
			}
		}
	}
	
}
