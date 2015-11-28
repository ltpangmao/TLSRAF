package it.unitn.tlsraf.ds;


import it.unitn.tlsraf.func.Func;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

/**
 * According to the specification of CAPEC
 * Define all fields as PUBLIC
 * @author litong30
 *
 */


public class AttackPattern {
	
	
	// map consequence to threat
		public static final Map<String, String> consequence_threat_mapping = new HashMap<String, String>();
		static {
				consequence_threat_mapping.put("Read application data", Threat.INFORMATION_DISCLOSURE.name());
				consequence_threat_mapping.put("Read memory", Threat.INFORMATION_DISCLOSURE.name());
				consequence_threat_mapping.put("Read files or directories", Threat.INFORMATION_DISCLOSURE.name());
				//exception
				consequence_threat_mapping.put("Read memory Read application data", Threat.INFORMATION_DISCLOSURE.name());
				consequence_threat_mapping.put("Read application data Read files or directories", Threat.INFORMATION_DISCLOSURE.name());
				consequence_threat_mapping.put("Read application data Read files or directories Read memory", Threat.INFORMATION_DISCLOSURE.name());
				consequence_threat_mapping.put("Read application data Read memory", Threat.INFORMATION_DISCLOSURE.name());
				consequence_threat_mapping.put("Read application data Read memory Read files or directories", Threat.INFORMATION_DISCLOSURE.name());
				
				
				consequence_threat_mapping.put("Modify application data", Threat.TAMPERING.name());
				consequence_threat_mapping.put("Modify application data memory", Threat.TAMPERING.name());
				consequence_threat_mapping.put("Modify application data files or directories", Threat.TAMPERING.name());
				consequence_threat_mapping.put("Unexpected states", Threat.TAMPERING.name());
				consequence_threat_mapping.put("Unexpected state", Threat.TAMPERING.name());
				consequence_threat_mapping.put("Unexpected State", Threat.TAMPERING.name());
				consequence_threat_mapping.put("Alter execution logic", Threat.TAMPERING.name());
				consequence_threat_mapping.put("Modify files or directories", Threat.TAMPERING.name());
				consequence_threat_mapping.put("Modify memory", Threat.TAMPERING.name());
				//exception
				consequence_threat_mapping.put("Modify application data Modify files or directories Modify memory", Threat.TAMPERING.name());
				consequence_threat_mapping.put("Modify memory Modify files or directories Modify application data", Threat.TAMPERING.name());
				
				consequence_threat_mapping.put("DoS: instability", Threat.DENIAL_OF_SERVICE.name());
				consequence_threat_mapping.put("DoS: resource consumption (CPU)", Threat.DENIAL_OF_SERVICE.name());
				consequence_threat_mapping.put("DoS: resource consumption (memory)", Threat.DENIAL_OF_SERVICE.name());
				consequence_threat_mapping.put("DoS: crash / exit / restart", Threat.DENIAL_OF_SERVICE.name());
				consequence_threat_mapping.put("DoS: amplification", Threat.DENIAL_OF_SERVICE.name());
				consequence_threat_mapping.put("DoS: resource consumption (other)", Threat.DENIAL_OF_SERVICE.name());
				// exception
				consequence_threat_mapping.put("DoS: amplification DoS: resource consumption (CPU) DoS: resource consumption (memory) DoS: resource consumption (other)", Threat.DENIAL_OF_SERVICE.name());
				consequence_threat_mapping.put("DoS: crash / exit / restart DoS: instability", Threat.DENIAL_OF_SERVICE.name());
				consequence_threat_mapping.put("DoS: amplification DoS: crash / exit / restart DoS: instability DoS: resource consumption (CPU) DoS: resource consumption (memory) DoS: resource consumption (other)", Threat.DENIAL_OF_SERVICE.name());
				
				
				consequence_threat_mapping.put("Gain privileges / assume identity", Threat.ELEVATION_OF_PRIVILEGE.name()+"%"+Threat.SPOOFING.name());
				consequence_threat_mapping.put("Execute unauthorized code or commands", Threat.ELEVATION_OF_PRIVILEGE.name());
				consequence_threat_mapping.put("Bypass protection mechanism", Threat.ELEVATION_OF_PRIVILEGE.name()+"%"+Threat.DEFEATED_MECHANISM.name());
				consequence_threat_mapping.put("Hide Activities", Threat.REPUDIATION.name());
				consequence_threat_mapping.put("Hide activities", Threat.REPUDIATION.name());
				//exception
				consequence_threat_mapping.put("Gain privileges / assume identity Bypass protection mechanism", Threat.ELEVATION_OF_PRIVILEGE.name()+"%"+Threat.SPOOFING.name()+"%"+Threat.DEFEATED_MECHANISM.name());
				consequence_threat_mapping.put("Bypass protection mechanism Hide activities",Threat.ELEVATION_OF_PRIVILEGE.name()+"%"+Threat.DEFEATED_MECHANISM.name()+"%"+Threat.REPUDIATION.name());
				
				// this will be further determined manually
				consequence_threat_mapping.put("\"Varies by context\"", Threat.DEPEND.name());
		}
		
		
		// Other enumerations
		public enum Threat {
			SPOOFING, TAMPERING, REPUDIATION, INFORMATION_DISCLOSURE, DENIAL_OF_SERVICE, ELEVATION_OF_PRIVILEGE, DEFEATED_MECHANISM, DEPEND
		}

	
	
	public String id;
	public String name;
	
	// description
	public String description;
	public LinkedList<String> steps = new LinkedList<String>();
	
	// evaluate likelihood
	public String severity;
	public String likelihood;
	public LinkedList<String> weaknesses = new LinkedList<String>();
	
	// analyze context
	public LinkedList<String> prerequisites = new LinkedList<String>();
	public LinkedList<String> contexts = new LinkedList<String>();
	
	// provide solutions
	public LinkedList<String> solutions = new LinkedList<String>();
	public LinkedList<String> requirements  = new LinkedList<String>();
	
	// description of attacks
	public LinkedList<String> methods = new LinkedList<String>();
	public LinkedList<String> consequences = new LinkedList<String>();
	
	
	// attributes below are specifically for attack graph generation
	public String completeness;
	public String abstraction;
	public LinkedList<String> parents = new LinkedList<String>();
	
	
	// additional attributes
	public LinkedList<String> purposes = new LinkedList<String>();
	
	// programming sugar for genering graph in OmniGraffle
	public String graphical_id;
	
	
	public AttackPattern() {
		super();
	}
	
	public String getPrintString(){
		String s="";
		
		s+="ID: "+id+"\n";
		s+="Name: "+name+"\n";
		s+="Severity: "+severity+"\n";
		s+="Likelihood: "+likelihood+"\n";
		s+="Weaknesses: \n";
		for(String temp: weaknesses){
			s+= temp+"\n";
		}
		s+="Prerequisites: \n";
		for(String temp: prerequisites){
			s+= temp+"\n";
		}
		s+="Contexts: \n";
		for(String temp: contexts){
			s+= temp+"\n";
		}
		s+="Solutions: \n";
		for(String temp: solutions){
			s+= temp+"\n";
		}
		s+="Requirements: \n";
		for(String temp: requirements){
			s+= temp+"\n";
		}
		s+="Methods: \n";
		for(String temp: methods){
			s+= temp+"\n";
		}
		s+="Consequences: \n";
		for(String temp: consequences){
			s+= temp+"\n";
		}
		
		s+="Completeness: "+completeness+"\n";
		s+="Abstraction: "+abstraction+"\n";
		s+="Children: \n";
		for(String temp: parents){
			s+= temp+"\n";
		}
		
		s+="Purposes: \n";
		for(String temp: purposes){
			s+= temp+"\n";
		}
		return s;
	}
	
	public String getRelatedString(){
		String s="";
		
		s+="ID: "+id+"\n";
		s+="Name: "+name+"\n";
		s+="Prerequisites: \n";
		for(String temp: prerequisites){
			s+= temp+"\n";
		}
		s+="Contexts: \n";
		for(String temp: contexts){
			s+= temp+"\n";
		}
		s+="Solutions: \n";
		for(String temp: solutions){
			s+= temp+"\n";
		}
		s+="Consequences: \n";
		for(String temp: consequences){
			s+= temp+"\n";
		}
		
		s+="Completeness: "+completeness+"\n";
		s+="Abstraction: "+abstraction+"\n";
		s+="Children: \n";
		for(String temp: parents){
			s+= temp+"\n";
		}
		
		s+="Purposes: \n";
		for(String temp: purposes){
			s+= temp+"\n";
		}
		return s;
	}
	
	/**
	 * Get a full set of formal expressions of this attack pattern
	 * @return
	 */
	public String getFormalExpression(){
		String result = "";
		
		result+="has_name("+Func.prepareFormalExpression(this.id)+","+Func.prepareFormalExpression(this.name)+").\n";
		
		result+= getFormalConsequence();
		result+= getFormalHierarchy();
		
		return result;
	}
	
	
	/**
	 * Obtain all threats
	 * @return
	 */
	public LinkedList<String> getAllThreats() {
		
		LinkedList<String> results = new LinkedList<String>();
		String temp_s = "";
		
		String consequence = "";
		// if there is no consequences, direct return null
		if(consequences.size()==0){  
			return null;
		}
		for (String s : consequences) {
			if (s.indexOf("Impact(Motivation):") < 0) {
				// if consequence has not specify "motivation", in most case it is empty, we will leave it for manual processing
				temp_s ="empty";
				if(!results.contains(temp_s)){
					results.add(temp_s);
				}
			} else {
				consequence = s.substring(((s.indexOf("Impact(Motivation):") + 20))).trim();
				String threat = consequence_threat_mapping.get(consequence);
				if (threat == null) {
					temp_s ="empty";
					if(!results.contains(temp_s)){
						results.add(temp_s);
					}
				} else {
					// split and generate formal predicates
					// System.out.println(threat);
					if(threat.contains("%")){
						String[] threats = threat.split("%");
						for(int i=0;i<threats.length;i++){
							temp_s =threats[i].toLowerCase().replaceAll("_", " ");
							if(!results.contains(temp_s)){
								results.add(temp_s);
							}
						}
					}else{
					 temp_s = threat.toLowerCase().replaceAll("_", " ");
					 if(!results.contains(temp_s)){
							results.add(temp_s);
						}
					}
				}
			}
		}

		return results;
	}
	
	/**
	 * Get the formal predicates of consequence
	 * @return
	 */
	private String getFormalConsequence(){
		LinkedList<String> temp = new LinkedList<String>();
		String temp_s = "";
		
		String consequence = "";
		if(consequences.size()==0){
			temp_s ="impose_threat("+Func.prepareFormalExpression(this.id)+",empty).";
			if(!temp.contains(temp_s)){
//				temp.add(temp_s);
			}
		}
		for (String s : consequences) {
			if (s.indexOf("Impact(Motivation):") < 0) {
				// consequence is empty
				temp_s ="impose_threat("+Func.prepareFormalExpression(this.id)+",empty).";
				if(!temp.contains(temp_s)){
					temp.add(temp_s);
				}
			} else {
				consequence = s.substring(((s.indexOf("Impact(Motivation):") + 20))).trim();

				String threat = consequence_threat_mapping.get(consequence);
				if (threat == null) {
					System.out.println(consequence + "## cannot be recognized");
				} else {
					// split and generate formal predicates
					// System.out.println(threat);
					if(threat.contains("%")){
						String[] threats = threat.split("%");
						for(int i=0;i<threats.length;i++){
							temp_s ="impose_threat("+Func.prepareFormalExpression(this.id)+","+Func.prepareFormalExpression(threats[i])+").";
							if(!temp.contains(temp_s)){
								temp.add(temp_s);
							}
						}
					}else{
					 temp_s="impose_threat("+Func.prepareFormalExpression(this.id)+","+Func.prepareFormalExpression(threat)+").";
					 if(!temp.contains(temp_s)){
							temp.add(temp_s);
						}
					}
				}
			}
		}
		
		String result = "";
		for(String s: temp){
			result+=s+"\n";
		}
		return result;
	}
	
	private String getFormalHierarchy(){
		String result = "";
		for(String parent: parents){
			// there is no need to have the empty relation.
			if(!parent.equals("empty")){
				result+="child_of("+Func.prepareFormalExpression(this.id)+","+Func.prepareFormalExpression(parent)+").\n";
			}
		}
		return result;
	}

	
	
	

}
