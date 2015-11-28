package it.unitn.tlsraf.func;

import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

import it.unitn.tlsraf.ds.AttackPattern;
import it.unitn.tlsraf.ds.InfoEnum;
import it.unitn.tlsraf.ds.RequirementElement;
import it.unitn.tlsraf.ds.RequirementLink;

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
		
//		generation.generatePatternHierarchy("248,22,390,507,184,401,441,416");
//		generation.generatePatternHierarchy("112");
		
//		generation.identifyPatternsWithPurpose();
		
		
		String target_patterns ="112,20,49,97,55,70,16,";
		target_patterns+="184,185,207,186,56,187,";
		target_patterns+="66,108,109,110,7,";
		target_patterns+="100,46,47,44,45,8,9,24,42,67,10,14,69,";
		target_patterns+="22,77,39,207,94,10,13,31,56,57,219,9,76,69,122,180,1,58,17,";
		target_patterns+="115,237,114,90,14,21,62,102,61,60,31,196,59,";
		target_patterns+="316,424,425,422,423,420,421,426,417,427,419,418,434,433,435,428,429,430,431,432,";
		target_patterns+="390,395,391,396,394,393,399,398,397,400,547,507,";
		target_patterns+="438,520,521,516,517,518,519,511,537,439,523,524,522";
		// 111,
//		generation.generateFormalPatternExpression(target_patterns);
//		generation.generateAttackPatternModel("112,20,49,97,55,70,16");
		generation.generateAttackPatternModel("438,520,521,516,517,518,519,511,537,439,523,524,522");
	}
	
	/**
	 * Generate a couple of related elements for an attack pattern, which will be further revised to complete the full model
	 * @param pattern_ids
	 */
	public void generateAttackPatternModel(String pattern_ids){
		// First get all domain information
		CAPECXMLProcessing xmlProcessing = new CAPECXMLProcessing();
//		xmlProcessing.calculateDomainForAllAttacks();
		xmlProcessing.importAttackDomainFromFile();
		
		
		// obtain pattern list
		LinkedList<String> ids = createNonRepeatedList(pattern_ids);
		
		for (String id: ids) {
			// Import attack patterns
			CAPECXMLQuerying xmlQuery = new CAPECXMLQuerying();
			AttackPattern ap = xmlQuery.getAttackInfoAndRelations(id);
			// Obtain all threats
			LinkedList<String> threats = ap.getAllThreats();
			// Calculate domain (target) for attack patterns
			String target = xmlProcessing.findAttackDomainByID(id);
			
			// first draw the general task element
			String general_task_id = AppleScript.drawArbitraryRequirementElement("Model set", "none", "Hexagon",
					InfoEnum.NORMAL_SIZE, "(300,300)", "0", ap.name, "0", "1");
			
			// obtain goal information 
			String goal_content = "";
			if(threats!=null){
				String goal_id = "";
				for(String threat: threats){
					goal_content="";
					goal_content +="Threat: "+threat+"\n";
					goal_content +="Target: "+target;
					// draw goal elements
					goal_id = AppleScript.drawArbitraryRequirementElement("Model set", "none", "Circle",
							InfoEnum.NORMAL_SIZE, "(300,300)", "0", goal_content, "0", "1");
					AppleScript.drawArbitraryRequirementLink("Model set", "none", goal_id, general_task_id, "Arrow", "0",
							"none", "none");
				}
			}
			
			// obtain context information
			String context_content = "";
			for(String context: ap.contexts){
				context_content+=context+"\n";
			}
			for(String prerequisite: ap.prerequisites){
				context_content+=prerequisite+"\n";
			}
			// draw context as a goal to facilitate the processing
			String context_id = AppleScript.drawArbitraryRequirementElement("Model set", "none", "Rectangle",
					InfoEnum.NORMAL_SIZE, "(300,300)", "0", context_content, "0", "0");
			AppleScript.drawArbitraryRequirementLink("Model set", "none", context_id, general_task_id, "", "0",
					"none", "none");
			
			
			// draw attack steps
			if(ap.steps.size()>1){
				// draw middle point
				String mid_id = AppleScript.drawArbitraryRequirementElement("Model set", "none", "Circle",
									InfoEnum.POINT_SIZE, "(300,300)", "0", "", "0", "1");
				AppleScript.drawArbitraryRequirementLink("Model set", "none", general_task_id, mid_id, "SharpArrow", "0",
						"none", "none");
				// draw attack steps
				String task_id = "";
				for (String step : ap.steps) {
					// operation
					task_id = AppleScript.drawArbitraryRequirementElement("Model set", "none", "Hexagon",
							InfoEnum.NORMAL_SIZE, "(300,300)", "0", step, "0", "1");
					AppleScript.drawArbitraryRequirementLink("Model set", "none", mid_id, task_id, "", "0",
							"none", "none");
				}
			}
			else{
				// I assume if a pattern has specified the attack steps, there must be more than one step
				// So, here means the attack pattern doesn't specify any attack steps, I will either skip it or manually add them.
			}
			System.out.println("Successfully draw the model!");
		}
	}
	
	/**
	 * Generate formal predicates for each pattern
	 * In particular, the formal expression includes id, threat, target(need manual process layer) and related patterns
	 * We will manually complete the target information and context information (later)
	 * In the future, if there are more information of the pattern should be added, we should probably have them in a separate file. 
	 * @param id
	 */
	public void generateFormalPatternExpression(String pattern_ids){
		
		// First get all domain information
		CAPECXMLProcessing xmlProcessing = new CAPECXMLProcessing();
		xmlProcessing.calculateDomainForAllAttacks();
		// obtain pattern list
		LinkedList<String> ids = createNonRepeatedList(pattern_ids);
		
		String expression = "";
		// iteratively process each pattern according to its id
		for (String id: ids) {
			// Import attack patterns
			CAPECXMLQuerying xmlQuery = new CAPECXMLQuerying();
			AttackPattern ap = xmlQuery.getAttackInfoAndRelations(id);
			// produce basic predicates
			expression += ap.getFormalExpression();
			// Calculate domain (target) for attack patterns
			String target = xmlProcessing.findAttackDomainByID(id);
			String target_expression = "";
			target_expression = "target(" + Func.prepareFormalExpression(id) + "," + target + ").\n"; // target can be null
			expression += target_expression+"\n\n\n"; //separate different patterns
		}
		
		Func.writeFile("dlv/attack/attack_patterns.dl", expression, false);
//		System.out.print(expression);
//		System.out.print(temp_ids.length+" "+ids.size());
	}

	/**
	 * Process the input ids and create non-repeated list accordingly
	 * @param pattern_ids
	 * @return
	 */
	private LinkedList<String> createNonRepeatedList(String pattern_ids) {
		// filter repeated patterns
		String[] temp_ids = pattern_ids.split(",");
		LinkedList<String> ids = new LinkedList<String>();
		for (int i = 0; i < temp_ids.length; i++) {
			if(!ids.contains(temp_ids[i])){
				ids.add(temp_ids[i]);
			}
			else{
//				System.out.println("Pattern "+temp_ids[i]+" is repeated!");
			}
		}
		return ids;
	}
	
	
	/**
	 * Generate the hierarchy for all attack patterns or specific patterns
	 * Identify all "ChildOf" links
	 */
	public void generatePatternHierarchyModel(String target){
		// first import all patterns
		importAllPatterns();

		// prepare for analysis below
		patterns_to_draw.clear();
		links_to_draw.clear();
		queue.clear();
		
		// identify elements and links to be draw
		if(target.equals("All")){
			identifyHierarchyModelsForAll();
		}
		else if(target.contains(",")){// process multiple nodes
			String [] ids = target.split(",");
			for(String id: ids){
				queue.add(getAttackPatternByID(id));
			}
			identifyHierarchyModelsForSpecificNodes();
		}
		else{ // process single node, but didn't check validity...
			// starting point
			queue.add(getAttackPatternByID(target));
			identifyHierarchyModelsForSpecificNodes();
		}
		
		// draw
		drawHierarchyModels(target);
		System.out.println("Finish model generation.");
	}
	

	
	/**
	 * Identify the hierarchy model for all the attack patterns
	 * this method has to be done after importing all the pattern information
	 * otherwise, the result is nothing
	 */
	private void identifyHierarchyModelsForAll(){
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
	private void identifyHierarchyModelsForSpecificNodes(){
		LinkedList<AttackPattern> temp = new LinkedList<AttackPattern>();
		
		for (AttackPattern parent: queue) {
			//add elements
			patterns_to_draw.add(parent);
			for (AttackPattern ap : all_attack_patterns) {
//				System.out.println(ap.id);
//				System.out.println(parent.id);
				
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
			identifyHierarchyModelsForSpecificNodes();
		}
	}
	
	
	
	
	
	/**
	 * This method pour all target patterns and links into the OmniGraffle canvas
	 * The way of drawing is specific for the attack pattern notations
	 * This should be done after identifying the drawable models
	 */
	private void drawHierarchyModels(String target){
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

	
//	private void identifyPatternsWithPurpose(){
//		// first import all patterns
//		importAllPatterns();
//		for(AttackPattern ap: all_attack_patterns){
//			if(ap.purposes.size()>1){
//				System.out.println(ap.getPrintString());
//			}
//		}
//	}
	

	
	
	
	
	
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
	 * Search patterns from the entire set of patterns
	 * @param search_id
	 * @return
	 */
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
