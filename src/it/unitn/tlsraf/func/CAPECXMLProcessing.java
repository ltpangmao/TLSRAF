package it.unitn.tlsraf.func;

import it.unitn.tlsraf.ds.AttackPattern;
import it.unitn.tlsraf.ds.InfoEnum;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Set;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import net.xqj.basex.bin.m;

/**
 * This class deals with xml file generation, further classification etc. 
 * It works based on the query interfaces provided by CAPECXMLQuerying
 * @author litong30
 *
 */
public class CAPECXMLProcessing {

	private String d_social ="Social Engineering";
	private String d_supply ="Supply Chain";
	private String d_commu ="Communications";
	private String d_software ="Software";
	private String d_physical ="Physical Security";
	private String d_hardware ="Hardware";

	LinkedList<LinkedList<String>> all = new LinkedList<LinkedList<String>>();
	LinkedList<String> social_attacks = new LinkedList<String>(Arrays.asList(InfoEnum.AttackDomain.SOCIAL.toString(), "404","410","416"));
	LinkedList<String> supply_attacks = new LinkedList<String>(Arrays.asList(InfoEnum.AttackDomain.SUPPLY.toString(), "438","439","440","441"));
	LinkedList<String> commu_attacks = new LinkedList<String>(Arrays.asList(InfoEnum.AttackDomain.COMMU.toString(), "117","272"));
	LinkedList<String> software_attacks = new LinkedList<String>(Arrays.asList(InfoEnum.AttackDomain.SOFTWARE.toString(), "112","114","115","116","123","125","126","128","129","130","131","117","148","151","154","169"
			,"173","175","188","212","224","227","242","248"));
	LinkedList<String> physical_attacks = new LinkedList<String>(Arrays.asList(InfoEnum.AttackDomain.PHYSICAL.toString(), "390","507","547"));
	LinkedList<String> hardware_attacks = new LinkedList<String>(Arrays.asList(InfoEnum.AttackDomain.HARDWARE.toString(), "169","401"));
	
	
	// connection client
	BaseXClient session = null;
	// all prefixes
	private String query_pre = "XQUERY declare namespace capec = 'http://capec.mitre.org/capec-2'; "
			+ "let $attacks := doc('capec/All_attack_patterns.xml') "
			+ "let $domain := doc('capec/3000.xml') ";
	
	
	public CAPECXMLProcessing() {
		super();
		
		
		// add all lists
		all.add(social_attacks);
		all.add(supply_attacks);
		all.add(commu_attacks);
		all.add(software_attacks);
		all.add(physical_attacks);
		all.add(hardware_attacks);
		
		try {
			session = new BaseXClient("localhost", 1984, "admin", "admin");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	
	
	
	public static void main(String[] args) {
		CAPECXMLProcessing.executeCMD("/Users/litong30/basex/bin/basexserver");//open server
//		CAPECXMLProcessing.executeCMD("/Users/litong30/basex/bin/basexserverstop");// stop server
		
		try {
//			CAPECXMLProcessing xmlQuery = new CAPECXMLProcessing();

			// produce domain lists for attacks
//			xmlQuery.calculateDomainForAllAttacks();
//			xmlQuery.outputAttackDomainInfo();
			
			// produce methods & consequences lists for attacks
//			xmlQuery.outputConsequenceInfo();
			
			

//			all_cia_result = xmlQuery.getAllCIAElement();
//			cia_result = xmlQuery.getCIAImact("High");
			
//			layer_result = xmlQuery.getLayerAttacks(InfoEnum.Layer.ALL.toString());
			
			
//			Set<String> matchedID = unify(layer_result.split(" "));
			
			
//			int counter=0;
//			for (String domain:matchedID){
//				if(all_cia_result.contains(domain)){
//					System.out.print(domain);
//					counter++;
//				}
//			}
//			System.out.print(counter);
			
//			for (String id: matchedID){
//				System.out.println(id);
//			}
//			System.out.println(matchedID.length);
			
//			query += getCIAImact("High");
//			query += count();
//			query += queryDomainCompatibility("Social Engineering", "416");
			
//			System.out.println(session.execute(query));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private static void executeCMD(String command){
		Runtime rt = Runtime.getRuntime();
		Process pr;
		try {
			pr = rt.exec(command);
			BufferedReader input = new BufferedReader(new InputStreamReader(pr.getInputStream()));
			String line = null;
			while ((line = input.readLine()) != null) {
				System.out.println(line);
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
	/**
	 * Retrive all attacks from the data source, 
	 * classify each of the attacks into a specific domain
	 * @throws IOException
	 */
	private void calculateDomainForAllAttacks() throws IOException{
		String all_attacks ="";
		all_attacks = getAllAttacks();
		
		// analyze each attack detected in the current setting
		Set<String> matchedID = unify(all_attacks.split(" "));
		for(String id : matchedID){
			classifyAttack(id);
		}
	}
	
	
	/**
	 * output the calculated domain information to an xml file, which can be quickly queried by functions
	 * This function is designed for CAPEC document 
	 */
	private void outputAttackDomainInfo(){
		try{
			DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder docBuilder = docFactory.newDocumentBuilder();

			// root elements
			Document doc = docBuilder.newDocument();
			Element rootElement = doc.createElement("capec:Domain_Mappings");
			doc.appendChild(rootElement);
			rootElement.setAttribute("xmlns:capec", "http://capec.mitre.org/capec-2");
			rootElement.setAttribute("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance");
			rootElement.setAttribute("Catalog_Name", "CAPEC");
			rootElement.setAttribute("Catalog_Version", "2.6");
			rootElement.setAttribute("Catalog_Data", "2014-06-23");
			rootElement.setAttribute("xsi:schemaLocation","http://capec.mitre.org/capec-2 "
					+ "http://capec.mitre.org/data/xsd/ap_schema_v2.7.xsd  http://cybox.mitre.org/cybox-2 "
					+ "http://cybox.mitre.org/XMLSchema/core/2.1/cybox_core.xsd");

			for(LinkedList<String> domain_list: all){
				for (int i=1; i< domain_list.size();i++) {
					String id = domain_list.get(i);
					// staff elements
					Element attack = doc.createElement("capec:Attack_Pattern");
					rootElement.appendChild(attack);
	
					// set id and domain attributes to the attack element
					attack.setAttribute("domain", domain_list.getFirst());
					attack.setAttribute("id", id);
				}
			}
		
			TransformerFactory transformerFactory = TransformerFactory.newInstance();
			Transformer transformer = transformerFactory.newTransformer();
			DOMSource source = new DOMSource(doc);
			StreamResult result = new StreamResult(new File("attack_domains.xml"));

			// Output to console for testing
			// StreamResult result = new StreamResult(System.out);

			transformer.transform(source, result);

			System.out.println("File saved!");

		} catch (ParserConfigurationException pce) {
			pce.printStackTrace();
		} catch (TransformerException tfe) {
			tfe.printStackTrace();
		}
}

		
	
	/**
	 * Given a particular attack id, try to classify it into certain domains, if possible.
	 * This function can also apply to cases which involve multiple categories.
	 * @param id
	 * @throws IOException 
	 */
	private void classifyAttack(String id) throws IOException{
		boolean classified =false;
		for(LinkedList<String> domain_list: this.all){
			if(domain_list.contains(id)){
				classified = true;
				break;
			}
		}
		// if they cannot be well classified, try to classify it by checking its parent
		LinkedList<String> classify_result = new LinkedList<>();
		if(classified){
			System.out.println("has been classified in prelist");
		}
		else{
			classify_result = classifyByCheckingParent(id);
			
			if(classify_result.size()>0){
//				System.out.println(classify_result.size());
				for(String domain: classify_result){
					// add the attack to proper domain_list
					for(LinkedList<String> domain_list: this.all){
						if(domain_list.getFirst().equals(domain)){
							domain_list.add(id);
							System.out.println(id+" "+domain_list.getFirst());
						}
					}
				}
			}
			else{
				System.out.println(id+" does not belong to any domain");
			}
		}
	}
	
	/**
	 * Given a particular id, figure out all possbile domains that it belong to by looking for its parents
	 * Current function only applies to ids, where the maximum layer to the classifed is no more than 3
	 * otherwise, some middle ids are missing, although we don't really need them... 
	 * @param id
	 * @throws IOException 
	 */
	private LinkedList<String> classifyByCheckingParent(String target_id) throws IOException {
		// query parents
		String query = query_pre	
				+ "for $ap in $attacks//capec:Attack_Patterns/capec:Attack_Pattern[@ID = '"+target_id+"']"
				+ "/capec:Related_Attack_Patterns/capec:Related_Attack_Pattern[capec:Relationship_Nature = 'ChildOf'] "
				+ "return data($ap/capec:Relationship_Target_ID)";
		String parent = session.execute(query);
//		System.out.println(parent);
		
		//process parents
		LinkedList<String> domains = new LinkedList<String>();
		if(parent.equals("")){
			// will return empty "domains"
		}
		else{
			Set<String> matchedID = unify(parent.split(" "));
			for(String parent_id : matchedID){
				boolean classified = false;
				for(LinkedList<String> domain_list: this.all){
					if(domain_list.contains(parent_id)){
						classified = true;
						domains.add(domain_list.getFirst());
					}
				}
				if(!classified){
					// Recursively find 
					domains.addAll(classifyByCheckingParent(parent_id));
				}
			}
		}		
		return domains;
	}


	/**
	 * get all first-level domain attacks, which are directly specified in the category.
	 * @throws IOException
	 */
	private void calculateDomainAttacks() throws IOException {
		String query = query_pre	
				+ "let $ap1 := $domain//capec:Attack_Pattern_Catalog/capec:Categories/capec:Category[@Name = '"+d_social+"']"
				+ "/capec:Relationships/capec:Relationship/capec:Relationship_Target_ID "
				+ "return data($ap1)";
		String first_level_attack = session.execute(query);
		Set<String> matchedID = unify(first_level_attack.split(" "));
		
		System.out.println(matchedID);
	}

	
	/**
	 * Get all attacks
	 * @return
	 * @throws IOException
	 */
//	@Deprecated
	private String getAllAttacks() throws IOException {
		//TODO this method should be replaced by the similar class in CAPECXMLQuery  
		String query = query_pre
				+ "for $ap in $attacks//capec:Attack_Pattern "
				+ "return data($ap/@ID)";
		String result = session.execute(query); 
		return result;
	}
	
	
	/**
	 * Output all motivation & consequence information if an attack pattern has
	 */
	private void outputConsequenceInfo(){
		try{
			//obtain all attacks id
			String all_attacks = getAllAttacks();
			Set<String> attack_ids = unify(all_attacks.split(" "));

			//find all information for that attack
			CAPECXMLQuerying xmlQuery = new CAPECXMLQuerying();
			// This is the simplest and lowest way for data processing...
			// It is ok for some debug use, but definitely not for practical use.
			LinkedList<AttackPattern> all_detailed_attacks = new LinkedList<AttackPattern>();
			// load all attack information into memory...
			for(String attack_id: attack_ids){
				AttackPattern attack= xmlQuery.getAttackInfo(attack_id);
				all_detailed_attacks.add(attack);
			}
			
			
			
			//output document
			DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
			// root elements
			Document doc = docBuilder.newDocument();
			Element rootElement = doc.createElement("capec:Domain_Mappings");
			doc.appendChild(rootElement);
			rootElement.setAttribute("xmlns:capec", "http://capec.mitre.org/capec-2");
			rootElement.setAttribute("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance");
			rootElement.setAttribute("Catalog_Name", "CAPEC");
			rootElement.setAttribute("Catalog_Version", "2.6");
			rootElement.setAttribute("Catalog_Data", "2014-06-23");
			rootElement.setAttribute("xsi:schemaLocation","http://capec.mitre.org/capec-2 "
					+ "http://capec.mitre.org/data/xsd/ap_schema_v2.7.xsd  http://cybox.mitre.org/cybox-2 "
					+ "http://cybox.mitre.org/XMLSchema/core/2.1/cybox_core.xsd");
			
			int count = 0;
			// append elements
			for (AttackPattern single_attack : all_detailed_attacks) {
				if (!single_attack.methods.getFirst().contains("empty") || !single_attack.consequences.getFirst().contains("empty")) {
					count++;
					// Root elements
					Element attack = doc.createElement("capec:Attack_Pattern");
					rootElement.appendChild(attack);

					// set id and domain attributes to the attack element
					attack.setAttribute("name", single_attack.name);
					attack.setAttribute("id", single_attack.id);

					Element attack_description = doc.createElement("capec:Attack_Pattern_Description");
					attack_description.setTextContent(single_attack.description);
					attack.appendChild(attack_description);
					
					Element attack_prerequisite = doc.createElement("capec:Attack_Pattern_Prerequisite");
					attack_prerequisite.setTextContent(listToString(single_attack.prerequisites.toArray()));
					attack.appendChild(attack_prerequisite);

					
					Element attack_method = doc.createElement("capec:Attack_Pattern_Method");
					attack_method.setTextContent(listToString(single_attack.methods.toArray()));
					attack.appendChild(attack_method);

					Element attack_consequence = doc.createElement("capec:Attack_Pattern_Consequence");
					attack_consequence.setTextContent(listToString(single_attack.consequences.toArray()));
					attack.appendChild(attack_consequence);
//					System.out.println(attack.getNodeValue());
				}
			}
		
			TransformerFactory transformerFactory = TransformerFactory.newInstance();
			Transformer transformer = transformerFactory.newTransformer();
			DOMSource source = new DOMSource(doc);
			StreamResult result = new StreamResult(new File("attack_methods_consequences.xml"));

			// Output to console for testing
			// StreamResult result = new StreamResult(System.out);

			transformer.transform(source, result);

			System.out.println(count + " patterns are printed!");

		} catch (ParserConfigurationException pce) {
			pce.printStackTrace();
		} catch (TransformerException tfe) {
			tfe.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	
	
	
	private String listToString(Object[] array) {
		String list="";
		for(Object s: array){
			list+=s.toString()+"\n";
		}
		return list;
	}




	/**
	 * Get all attacks that match the layer criteria
	 * will not be used anymore I guess
	 * @param domain
	 * @return
	 * @throws IOException
	 */
	@Deprecated
	private String getLayerAttacks(String layer) throws IOException {
		String query = query_pre;
		
		if(layer.equals(InfoEnum.Layer.BUSINESS.toString())){
			query = query	
				+ "let $ap1 := $domain//capec:Attack_Pattern_Catalog/capec:Categories/capec:Category[@Name = '"+d_social+"']"
				+ "/capec:Relationships/capec:Relationship/capec:Relationship_Target_ID "
				+ "let $ap2 := $domain//capec:Attack_Pattern_Catalog/capec:Categories/capec:Category[@Name = '"+d_supply+"']"
				+ "/capec:Relationships/capec:Relationship/capec:Relationship_Target_ID "
				+ "let $all := ($ap1,$ap2)"
				+ "return data($all)";
		}
		else if(layer.equals(InfoEnum.Layer.APPLICATION.toString())){
			query = query	
					+ "let $ap1 := $domain//capec:Attack_Pattern_Catalog/capec:Categories/capec:Category[@Name = '"+d_software+"']"
					+ "/capec:Relationships/capec:Relationship/capec:Relationship_Target_ID "
					+ "let $ap2 := $domain//capec:Attack_Pattern_Catalog/capec:Categories/capec:Category[@Name = '"+d_commu+"']"
					+ "/capec:Relationships/capec:Relationship/capec:Relationship_Target_ID "
					+ "let $ap3 := $domain//capec:Attack_Pattern_Catalog/capec:Categories/capec:Category[@Name = '"+d_supply+"']"
					+ "/capec:Relationships/capec:Relationship/capec:Relationship_Target_ID "
					+ "let $all := ($ap1,$ap2,$ap3)"
					+ "return data($all)";
		}
		else if(layer.equals(InfoEnum.Layer.PHYSICAL.toString())){
			query = query	
					+ "let $ap1 := $domain//capec:Attack_Pattern_Catalog/capec:Categories/capec:Category[@Name = '"+d_hardware+"']"
					+ "/capec:Relationships/capec:Relationship/capec:Relationship_Target_ID "
					+ "let $ap2 := $domain//capec:Attack_Pattern_Catalog/capec:Categories/capec:Category[@Name = '"+d_physical+"']"
					+ "/capec:Relationships/capec:Relationship/capec:Relationship_Target_ID "
					+ "let $ap3 := $domain//capec:Attack_Pattern_Catalog/capec:Categories/capec:Category[@Name = '"+d_supply+"']"
					+ "/capec:Relationships/capec:Relationship/capec:Relationship_Target_ID "
					+ "let $all := ($ap1,$ap2,$ap3)"
					+ "return data($all)";
		}
		else if(layer.equals(InfoEnum.Layer.ALL.toString())){
			query = query	
					+ "let $ap := $domain//capec:Attack_Pattern_Catalog/capec:Categories/capec:Category"
					+ "/capec:Relationships/capec:Relationship/capec:Relationship_Target_ID "
					+ "return data($ap)";
		}
		else{
			CommandPanel.logger.warning("Incorrect layer for obtaining attack patterns!");
		}
		
		String result = session.execute(query); 
//		System.out.println(result);
		// a list of ID value, separated by " "
		return result;
	}
	
	
	
	
	
	/**
	 * Unify the elements in a list
	 * @param result_list
	 * @return
	 */
	private Set<String> unify(String[] result_list) {
		final Set<String> set = new HashSet<String>(); 
		for(String result: result_list){
			set.add(result);
		}
		
		return set;
	}
}
