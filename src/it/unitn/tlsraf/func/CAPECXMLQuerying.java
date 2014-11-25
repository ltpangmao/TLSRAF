package it.unitn.tlsraf.func;

import it.unitn.tlsraf.ds.AttackPattern;
import it.unitn.tlsraf.ds.InfoEnum;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Map;
import java.util.Set;


public class CAPECXMLQuerying {
	
	
	// connection client
	BaseXClient session = null;
	// all prefixes
	private String query_pre = "XQUERY declare namespace capec = 'http://capec.mitre.org/capec-2'; "
			+ "let $attacks := doc('capec/All_attack_patterns.xml') "
			+ "let $attack_domains := doc('capec/attack_domains.xml') ";
	
	// attack domain information
//	LinkedList<Pair<String, String>> attack_domains = new LinkedList<Pair<String, String>>();
//	Pair<String, String> attack_domains = Pair.of("", "");
	
	
	Map<String, String> attack_domains = new HashMap<String, String>();
//		security_mechanisms.put("cryptographic_control", InfoEnum.Layer.BUSINESS.name());

	
	public CAPECXMLQuerying() {
		super();
		try {
			session = new BaseXClient("localhost", 1984, "admin", "admin");
			loadAttackDomain();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
	
	public static void main(String[] args) {
		try {
			CAPECXMLQuerying xmlQuery = new CAPECXMLQuerying();
			AttackPattern attack= xmlQuery.getAttackInfo("332");
			
			
//			xmlQuery.countPossibleAttackPatterns();
			
//			xmlQuery.getCIAImactFromConsequence(InfoEnum.SecurityProperty.Integrity.toString());
			
			// suppose we deal with an anti-goal, which concerns confidentiality at the application layer
//			LinkedList<String> possible_attacks = xmlQuery.findPosstibleAttackPatterns(InfoEnum.Layer.APPLICATION.toString(), InfoEnum.SecurityProperty.Confidentiality.toString());
//			LinkedList<String> possible_attacks = xmlQuery.getCIAImact(InfoEnum.SecurityProperty.Confidentiality.toString(), "High");
			
//			for(String temp: possible_attacks){
//				System.out.println(temp);
//			}
			
			
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	
	/** obtain all related information of the target attack
	 * @param string
	 * @return
	 * @throws IOException 
	 */
	public AttackPattern getAttackInfo(String id) {
		
		/* each returned value should be checked for its existence
		 * Here we fix the order of specifying attributes
		 * use "$" as separator, and "€" as sub-separator...
		 * 0) name, 1) severity, 2) likelihood, 3) weaknesses, 4) prerequisites 
		 * 5) context, 6) solutions, 7) requirements, 8) methods
		 * 9) consequences, 10) description
		 */
		String query = query_pre
				+ "for $ap in $attacks//capec:Attack_Pattern "
				+ "where $ap/@ID = '"+id+"' "
				+ "let $em := \"empty\" "
				+ "let $sep := '$' "
				+ "let $subsep := '€' "
				+ "let $subsubsep := '∑' "
				+ "return (" //name
				+ "if(exists($ap/@Name)) then data($ap/@Name) else $em, " 
				+ "$sep," //severity
				+ "if(exists($ap/capec:Typical_Severity)) then data($ap/capec:Typical_Severity) else $em, "
				+ "$sep," //likelihood
				+ "if(exists($ap/capec:Typical_Likelihood_of_Exploit)) then data($ap/capec:Typical_Likelihood_of_Exploit/capec:Likelihood) else $em, "
				+ "$sep," // weaknesses
				+ "if(exists($ap/capec:Related_Weaknesses)) then data(string-join($ap/capec:Related_Weaknesses//capec:CWE_ID, $subsep) ) else $em, "
				+ "$sep," // prerequisites
				+ "if(exists($ap/capec:Attack_Prerequisites)) then data(string-join($ap/capec:Attack_Prerequisites//capec:Text, $subsep) ) else $em, "
				+ "$sep," // contexts
				+ "if(exists($ap/capec:Technical_Context)) then "
				+ "(data($ap/capec:Technical_Context//capec:Architectural_Paradigm),$subsep,"
				+ "data($ap/capec:Technical_Context//capec:Framework),$subsep,"
				+ "data($ap/capec:Technical_Context//capec:Platform),$subsep,"
				+ "data($ap/capec:Technical_Context//capec:Languages)) "
				+ "else $em, "
				+ "$sep," // solutions
				+ "if(exists($ap/capec:Solutions_and_Mitigations)) then data(string-join($ap/capec:Solutions_and_Mitigations//capec:Text, $subsep) ) else $em, "
				+ "$sep," // requirements
				+ "if(exists($ap/capec:Relevant_Security_Requirements)) then data(string-join($ap/capec:Relevant_Security_Requirements//capec:Text, $subsep) ) else $em, "
				+ "$sep," // methods
				+ "if(exists($ap/capec:Methods_of_Attack)) then data(string-join($ap//capec:Method_of_Attack, $subsep) ) else $em, "
//				+ "$sep," // motivations and consequences
//				+ "if(exists($ap/capec:Attack_Motivation-Consequences)) then data(string-join($ap//capec:Attack_Motivation-Consequence, $subsep) ) else $em "
				+ "$sep," // motivations and consequences
				+ "if(exists($ap/capec:Attack_Motivation-Consequences)) then "
				+ "for $ap_consequence in $ap//capec:Attack_Motivation-Consequence "
				+ " return ( data(string-join($ap_consequence/capec:Consequence_Scope, ' ')), $subsubsep, "
				+ "  		data(string-join($ap_consequence/capec:Consequence_Technical_Impact, ' ')), $subsep)"
				+ "else $em, "
				+ "$sep," //description
				+ "if(exists($ap/capec:Description/capec:Summary)) then data($ap/capec:Description/capec:Summary//capec:Text) else $em "
				+ ")";
//				+ "return (data($ap/@Name),data($ap/Description))"; 
		
		String result="";
		try {
			result = session.execute(query);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
//		System.out.println(result);

		/* Process data  0) name, 1) severity, 2) likelihood, 3) weaknesses, 
		 * 4) prerequisites, 5) context, 6) solutions, 7) requirements
		 * 8) methods, 9) consequences
		 */
		AttackPattern ap = new AttackPattern();
		String[] attributes = result.split("\\$");
		ap.id = id;
//		System.out.println(ap.id);

		ap.name = attributes[0].trim();
		ap.severity = attributes[1].trim();
		ap.likelihood = attributes[2].trim();
		String[] temp = attributes[3].split("€");
		
		for(String weakness: temp){
			ap.weaknesses.add(weakness.trim());
		}
		
		temp = attributes[4].split("€");
		
		for(String prerequisite: temp){
			ap.prerequisites.add(prerequisite.trim());
		}
		
		// for special processing, we need to check first whether this element is empty
		temp = attributes[5].split("€");
		if(!temp[0].contains("empty")){
			ap.contexts.addLast("Architectural Paradigm: "+temp[0].trim());
			ap.contexts.addLast("Framework: "+temp[1].trim());
			ap.contexts.addLast("Platform: "+temp[2].trim());
			ap.contexts.addLast("Language: "+temp[3].trim());
		}else{
			ap.contexts.addLast(temp[0]);
		}
		
		temp = attributes[6].split("€");
		for(String solution: temp){
			ap.solutions.add(solution.trim());
		}
		
		temp = attributes[7].split("€");
		for(String requirement: temp){
			ap.requirements.add(requirement.trim());
		}
		
		temp = attributes[8].split("€");
		for(String method: temp){
			ap.methods.add(method.trim());
		}
		
		// for special processing, we need to check first whether this element is empty
		temp = attributes[9].split("€");
		for(String consequence: temp){
			if(!consequence.contains("empty")){
				String [] new_temp = consequence.split("∑");
				if(new_temp.length>=2){ // prevent empty entries introduced by extra seperators
					ap.consequences.add("Scope: "+new_temp[0]+"\n"+"Impact(Motivation): "+ new_temp[1]);
				}
			}
			else{
				ap.consequences.add(consequence);
			}
		}
		
		ap.description = attributes[10].trim();
		//
//		System.out.println(ap.getPrintString());
		return ap;
	}



	/**
	 * Find all possible attack patterns according to certain criteria
	 * Here we mainly consider layer and security property 
	 * @param layer
	 * @param sec_property
	 * @return
	 */
	public LinkedList<String> findPosstibleAttackPatterns(String layer, String sec_property) {

		LinkedList<String> cia_init_list = new LinkedList<String>();
		try {
//			cia_init_list = getCIAImact(sec_property, "Low");
			cia_init_list = getCIAImactFromConsequence(sec_property);
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		
		
		// this is supposed to be the filtered list
		LinkedList<String> cia_domain_list = new LinkedList<String>();

		if(layer.equals(InfoEnum.Layer.BUSINESS.toString())){
			for (String init_attack : cia_init_list) {
				if (attack_domains.get(init_attack)!=null&&(attack_domains.get(init_attack).equals(InfoEnum.AttackDomain.SOCIAL.toString())
						|| attack_domains.get(init_attack).equals(InfoEnum.AttackDomain.SUPPLY.toString()))) {
					cia_domain_list.add(init_attack);
				}
			}
		}else if(layer.equals(InfoEnum.Layer.APPLICATION.toString())){
			for (String init_attack : cia_init_list) {
				if (attack_domains.get(init_attack)!=null&&(attack_domains.get(init_attack).equals(InfoEnum.AttackDomain.SOFTWARE.toString())
						|| attack_domains.get(init_attack).equals(InfoEnum.AttackDomain.COMMU.toString())
						|| attack_domains.get(init_attack).equals(InfoEnum.AttackDomain.SUPPLY.toString()))) {
					cia_domain_list.add(init_attack);
				}
			}
		}else if(layer.equals(InfoEnum.Layer.PHYSICAL.toString())){
			for (String init_attack : cia_init_list) {
				if (attack_domains.get(init_attack)!=null&&(attack_domains.get(init_attack).equals(InfoEnum.AttackDomain.HARDWARE.toString())
						|| attack_domains.get(init_attack).equals(InfoEnum.AttackDomain.PHYSICAL.toString())
						|| attack_domains.get(init_attack).equals(InfoEnum.AttackDomain.SUPPLY.toString()))) {
					cia_domain_list.add(init_attack);
				}
			}
		}else{
			
		}
		
		
		return cia_domain_list;
	}
	
	/**
	 * obtain all attack-domain pairs and load them into the memory in order to avoid highly frequent query
	 * @throws IOException
	 */
	private void loadAttackDomain() throws IOException{
		// obtain attack-domain pairs
		String query = query_pre
				+ "for $ap in $attack_domains//capec:Domain_Mappings/capec:Attack_Pattern "
				+ "return (data($ap/@id),data($ap/@domain))";
		
		String result = session.execute(query);
		
		// load them into memory
		String [] temp = result.split(" ");
		for(int i=0;i<temp.length;i=i+2){
			this.attack_domains.put(temp[i], temp[i+1]);
		}
		
//		for(Pair<String, String> p: this.attack_domains){
//			System.out.println(p.toString());
//		}
	}
	
	/**
	 * Get all attacks that match the CIA criteria
	 * @param impact
	 * @return
	 * @throws IOException
	 */
	private LinkedList<String> getCIAImact(String property, String impact) throws IOException {
		String query = query_pre
				+ "for $ap in $attacks//capec:Attack_Pattern "
				+ "where $ap/capec:CIA_Impact/capec:"+property+"_Impact = '"+impact+"' "
				+ "return data($ap/@ID)";
		
		String result = session.execute(query);
//		System.out.println(result);
		// a list of ID value, separated by " "
		return getList(result);
	}

	/**
	 * An alternative way to obtain the CIA influence according to the CAPEC, 
	 * not sure what is their rationale for having both of these two
	 * @param property
	 * @param impact
	 * @return
	 * @throws IOException
	 */
	private LinkedList<String> getCIAImactFromConsequence(String property) throws IOException {
		String query = query_pre
				+ "for $ap in $attacks//capec:Attack_Pattern "
				+ "where $ap/capec:Attack_Motivation-Consequences/capec:Attack_Motivation-Consequence/"
				+ "capec:Consequence_Scope = '"+property+"'"
				+ "return data($ap/@ID)";
		
		String result = session.execute(query);
//		System.out.println(result);
		// a list of ID value, separated by " "
		return getList(result);
	}
	
	/**
	 * Get all attacks that have been specified with the CIA attribute
	 * @return
	 * @throws IOException
	 */
	private LinkedList<String> getAllCIAElement() throws IOException {
		String query = query_pre
				+ "for $ap in $attacks//capec:Attack_Pattern "
				+ "where exists($ap/capec:CIA_Impact) "
				+ "return data($ap/@ID)";
//				+ "return $ap";
		
		String result = session.execute(query); 
		
		return getList(result);
	}

	
	
	/****
	 * Auxiliary Methods
	 * not the essential part of our functions  
	 */
	
	/**
	 * A way to count the number of qualified attacks
	 */
	private void countPossibleAttackPatterns(){
		System.out.println("a b c d e f g h i");
		
		LinkedList<String> possible_attacks = findPosstibleAttackPatterns(InfoEnum.Layer.BUSINESS.toString(), InfoEnum.SecurityProperty.Confidentiality.toString());
		System.out.print(possible_attacks.size()+" ");
		possible_attacks = findPosstibleAttackPatterns(InfoEnum.Layer.BUSINESS.toString(), InfoEnum.SecurityProperty.Integrity.toString());
		System.out.print(possible_attacks.size()+" ");
		possible_attacks = findPosstibleAttackPatterns(InfoEnum.Layer.BUSINESS.toString(), InfoEnum.SecurityProperty.Availability.toString());
		System.out.print(possible_attacks.size()+" ");
		
		possible_attacks = findPosstibleAttackPatterns(InfoEnum.Layer.BUSINESS.toString(), "Access_Control");
		System.out.print(possible_attacks.size()+" ");
		possible_attacks = findPosstibleAttackPatterns(InfoEnum.Layer.BUSINESS.toString(), "Non-Repudiation");
		System.out.print(possible_attacks.size()+" ");
		possible_attacks = findPosstibleAttackPatterns(InfoEnum.Layer.BUSINESS.toString(), "Accountability");
		System.out.print(possible_attacks.size()+" ");
		possible_attacks = findPosstibleAttackPatterns(InfoEnum.Layer.BUSINESS.toString(), "Authentication");
		System.out.print(possible_attacks.size()+" ");
		possible_attacks = findPosstibleAttackPatterns(InfoEnum.Layer.BUSINESS.toString(), "Authorization");
		System.out.print(possible_attacks.size()+" ");
		possible_attacks = findPosstibleAttackPatterns(InfoEnum.Layer.BUSINESS.toString(), "Other");
		System.out.println(possible_attacks.size());
		
		
		
		
		possible_attacks = findPosstibleAttackPatterns(InfoEnum.Layer.APPLICATION.toString(), InfoEnum.SecurityProperty.Confidentiality.toString());
		System.out.print(possible_attacks.size()+" ");
		possible_attacks = findPosstibleAttackPatterns(InfoEnum.Layer.APPLICATION.toString(), InfoEnum.SecurityProperty.Integrity.toString());
		System.out.print(possible_attacks.size()+" ");
		possible_attacks = findPosstibleAttackPatterns(InfoEnum.Layer.APPLICATION.toString(), InfoEnum.SecurityProperty.Availability.toString());
		System.out.print(possible_attacks.size());
		
		possible_attacks = findPosstibleAttackPatterns(InfoEnum.Layer.APPLICATION.toString(), "Access_Control");
		System.out.print(possible_attacks.size()+" ");
		possible_attacks = findPosstibleAttackPatterns(InfoEnum.Layer.APPLICATION.toString(), "Non-Repudiation");
		System.out.print(possible_attacks.size()+" ");
		possible_attacks = findPosstibleAttackPatterns(InfoEnum.Layer.APPLICATION.toString(), "Accountability");
		System.out.print(possible_attacks.size()+" ");
		possible_attacks = findPosstibleAttackPatterns(InfoEnum.Layer.APPLICATION.toString(), "Authentication");
		System.out.print(possible_attacks.size()+" ");
		possible_attacks = findPosstibleAttackPatterns(InfoEnum.Layer.APPLICATION.toString(), "Authorization");
		System.out.print(possible_attacks.size()+" ");
		possible_attacks = findPosstibleAttackPatterns(InfoEnum.Layer.APPLICATION.toString(), "Other");
		System.out.println(possible_attacks.size());
		
		
		possible_attacks = findPosstibleAttackPatterns(InfoEnum.Layer.PHYSICAL.toString(), InfoEnum.SecurityProperty.Confidentiality.toString());
		System.out.print(possible_attacks.size()+" ");
		possible_attacks = findPosstibleAttackPatterns(InfoEnum.Layer.PHYSICAL.toString(), InfoEnum.SecurityProperty.Integrity.toString());
		System.out.print(possible_attacks.size()+" ");
		possible_attacks = findPosstibleAttackPatterns(InfoEnum.Layer.PHYSICAL.toString(), InfoEnum.SecurityProperty.Availability.toString());
		System.out.print(possible_attacks.size()+" ");
		
		possible_attacks = findPosstibleAttackPatterns(InfoEnum.Layer.PHYSICAL.toString(), "Access_Control");
		System.out.print(possible_attacks.size()+" ");
		possible_attacks = findPosstibleAttackPatterns(InfoEnum.Layer.PHYSICAL.toString(), "Non-Repudiation");
		System.out.print(possible_attacks.size()+" ");
		possible_attacks = findPosstibleAttackPatterns(InfoEnum.Layer.PHYSICAL.toString(), "Accountability");
		System.out.print(possible_attacks.size()+" ");
		possible_attacks = findPosstibleAttackPatterns(InfoEnum.Layer.PHYSICAL.toString(), "Authentication");
		System.out.print(possible_attacks.size()+" ");
		possible_attacks = findPosstibleAttackPatterns(InfoEnum.Layer.PHYSICAL.toString(), "Authorization");
		System.out.print(possible_attacks.size()+" ");
		possible_attacks = findPosstibleAttackPatterns(InfoEnum.Layer.PHYSICAL.toString(), "Other");
		System.out.println(possible_attacks.size());
	}
	
	/**
	 * designed for various number counting
	 * @return
	 * @throws IOException 
	 */
	private String count() throws IOException {
		String query = query_pre
//			+"let $ap := $attack_domains//capec:Domain_Mappings/capec:Attack_Pattern "
//			+ "return fn:count($ap)";
			+"let $ap := $attacks//capec:Attack_Patterns/capec:Attack_Pattern "
			+ "where exists($ap/capec:CIA_Impact) "
			+"return fn:count($ap)";
		
		
		// query total number of attack patterns
		// query = "for $ap in $attacks//capec:Attack_Pattern "
		// + "return fn:count($ap)";

		// query total number of "complete" attack patterns
		// query = "let $ap := $attacks//capec:Attack_Pattern[@Pattern_Completeness= 'Complete'] "
		// + "return fn:count($ap)";

		// query total number of attack patterns have the "completeness" attribute
		// query = "let $ap := $attacks//capec:Attack_Pattern/@Pattern_Completeness "
		// + "return fn:count($ap)";

		// query total number of attack patterns have the "CIA Impact" element
		// query = "let $ap := $attacks//capec:Attack_Pattern/capec:CIA_Impact "
		// + "return fn:count($ap)";


		// multiple criteria
		// + "where ($ap/capec:CIA_Impact/capec:Confidentiality_Impact = '"+impact+"') "
		// + "and ($ap/@Pattern_Completeness= 'Complete') "
		// + "let $selected_ap := $ap "

		String result = session.execute(query); 
		System.out.println(result);
		return result;
		
	}

	/**
	 * Obtain Unified elements and put them into a list
	 * assume the separate is space " "
	 * @param result_list
	 * @return
	 */
	private LinkedList<String> getList(String all_results) {
		String[] result_list = all_results.split(" ");
		final Set<String> set = new HashSet(); 
		for(String result: result_list){
			set.add(result);
		}
		
		LinkedList<String> list = new LinkedList<String>();
		list.addAll(set);
		
		return list;
	}
	
	/**
	 * Unify the elements in a list
	 * @param result_list
	 * @return
	 */
	private Set<String> unify(String[] result_list) {
		final Set<String> set = new HashSet(); 
		for(String result: result_list){
			set.add(result);
		}
		
		return set;
	}
}
