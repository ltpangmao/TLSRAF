package it.unitn.tlsraf.func;

import java.util.LinkedList;

import it.unitn.tlsraf.ds.AttackPattern;
import it.unitn.tlsraf.ds.InfoEnum;

/**
 * This class is responsible for generating graphical models regarding CAPEC patterns
 * @author litong30
 *
 */
public class CAPECModelGeneration {

	private LinkedList<AttackPattern> all_attack_patterns = new LinkedList<AttackPattern>();
	
	//facilitate hierarchy model generation
	private LinkedList<AttackPattern> patterns_to_draw = new LinkedList<AttackPattern>();
	private LinkedList<ChildOfLink> links_to_draw = new LinkedList<ChildOfLink>();
	
	// facilitate the (single) hierarchy model generation
	private LinkedList<AttackPattern> queue = new LinkedList<AttackPattern>();
	
	public static void main(String[] args) {
		CAPECModelGeneration generation = new CAPECModelGeneration();
//		generation.generatePatternHierarchy("All");
		
		generation.generatePatternHierarchy("248,22,390,507,184,401,441,416");
//		generation.generatePatternHierarchy("272");
		
//		generation.identifyPatternsWithPurpose();
	}
	
	
	
	/**
	 * Generate the hierarchy for all attack patterns
	 * Identify all "ChildOf" links
	 */
	public void generatePatternHierarchy(String target){
		// first import all patterns
		importAllPatterns();

		// prepare for analysis below
		patterns_to_draw.clear();
		links_to_draw.clear();
		queue.clear();
		
		// identify elements and links to be draw
		if(target.equals("All")){
			identifyModelsForAll();
		}
		else if(target.contains(",")){// process multiple nodes
			String [] ids = target.split(",");
			for(String id: ids){
				queue.add(getAttackPatternByID(id));
			}
			identifyModelsForSpecificNodes();
		}
		else{ // process single node, but didn't check validity...
			// starting point
			queue.add(getAttackPatternByID(target));
			identifyModelsForSpecificNodes();
		}
		
		// draw
		drawModels(target);
	}
	

	/**
	 * Load all the attack pattern information into this class for further analysis
	 */
	private void importAllPatterns(){
		CAPECXMLQuerying xmlQuery = new CAPECXMLQuerying();
		LinkedList<String> all_attack_ids = xmlQuery.getAllAttackIDs();
		for(String id: all_attack_ids){
			AttackPattern attack_pattern= xmlQuery.getAttackInfoAndRelations(id);
			all_attack_patterns.add(attack_pattern);
		}
		
		//testing
//		all_attack_patterns.add(xmlQuery.getAttackInfoAndRelations("111"));
//		all_attack_patterns.add(xmlQuery.getAttackInfoAndRelations("116"));
//		all_attack_patterns.add(xmlQuery.getAttackInfoAndRelations("184"));
	}	
	
	/**
	 * Identify the hierarchy model for all the attack patterns
	 * this method has to be done after importing all the pattern information
	 * otherwise, the result is nothing
	 */
	private void identifyModelsForAll(){
		// elements
		patterns_to_draw = all_attack_patterns;
		
		links_to_draw.clear();
		// links
		for(AttackPattern ap: all_attack_patterns){
			for(String parent: ap.parents){
				// all patterns has parents should add links accordingly
				links_to_draw.add(new ChildOfLink(ap.id, parent));
			}
		}
		
		//test
//		patterns_to_draw.add(getAttackPatternByID("111"));
//		patterns_to_draw.add(getAttackPatternByID("184"));
//		patterns_to_draw.add(getAttackPatternByID("116"));
//		
//		links_to_draw.add(new ChildOfLink("111", "184"));
//		links_to_draw.add(new ChildOfLink("111", "116"));
	}
	
	/**
	 * Identify the hierarchy model for a particular element
	 * this method has to be done after importing all the pattern information
	 */
	private void identifyModelsForSpecificNodes(){
		LinkedList<AttackPattern> temp = new LinkedList<AttackPattern>();
		
		for (AttackPattern parent: queue) {
			//add elements
			patterns_to_draw.add(parent);
			for (AttackPattern ap : all_attack_patterns) {
				System.out.println(ap.id);
				System.out.println(parent.id);
				
				if (ap.parents.contains(parent.id)) {
					// add non-repetitive elements
					if (!patterns_to_draw.contains(ap)) {
						links_to_draw.add(new ChildOfLink(ap.id, parent.id));
						// these are newly added elements that need to be recursively analyzed
						temp.add(ap);
					}
				}
			}
		}
		
		// if there are some newly added elements, we will recursively process them
		if(temp.size()>0){
			queue=temp;
			identifyModelsForSpecificNodes();
		}
	}
	
	
	
	
	
	/**
	 * This method pour all target patterns and links into the OmniGraffle canvas
	 * The way of drawing is specific for the attack pattern notations
	 * This should be done after identifying the drawable models
	 */
	private void drawModels(String target){
		String canvas ="";
		if(target.equals("All")){
			canvas = "Overall Hierarchy";
		}
		else{
//			canvas = "Hierarchy";
			canvas = "Model set";
		}
		
		// draw all elements in a particular way (regarding attack patterns)
		String text ="";
		for (AttackPattern ap: patterns_to_draw){
			text = "CAPEC-"+ap.id+"\n"
					+ ap.name +"\n("
					+ap.abstraction+", "+ap.completeness+")";
			ap.graphical_id = AppleScript.drawArbitraryRequirementElement(canvas, "none", "House",
					InfoEnum.NORMAL_SIZE, "(300,300)", "0", text, "0", "1");	
		}
		
		
		
		// draw all links in a particular way (regarding attack patterns)
		for(ChildOfLink col: links_to_draw){
			AttackPattern source_ap = getAttackPatternByID(col.source_id);
			AttackPattern des_ap = getAttackPatternByID(col.des_id);
			// if some node is missing, we will ignore this link
			if (des_ap != null & source_ap != null) {
				String graphical_source_id = source_ap.graphical_id;
				String graphical_des_id = des_ap.graphical_id;
				AppleScript.drawArbitraryRequirementLink(canvas, "none", graphical_des_id, graphical_source_id, "StickArrow", "0",
						"ChildOf", "none");
			}
			else{
				System.out.println(col.source_id+" "+col.des_id);
			}
		}
		
	}
	
	/**
	 * Generate the hierarchy for all attack patterns
	 * Identify all "ChildOf" links
	 */
	public void identifyPatternsWithPurpose(){
		// first import all patterns
		importAllPatterns();

		for(AttackPattern ap: all_attack_patterns){
			if(ap.purposes.size()>1){
//				System.out.println(ap.id+" "+ap.name);
				System.out.println(ap.getPrintString());
			}
		}
	}
	

	private AttackPattern getAttackPatternByID(String search_id) {
		for(AttackPattern ap: all_attack_patterns){
			if(ap.id.equals(search_id)){
				return ap;
			}
		}
		
		return null;
	}



	/**
	 * Inner class which captures the childOf relations
	 * @author litong30
	 *
	 */
	class ChildOfLink{
		String source_id; //child
		String des_id; //parent
		
		public ChildOfLink(String source_id, String des_id) {
			super();
			this.source_id = source_id;
			this.des_id = des_id;
		}
		
		
		
	}
}
