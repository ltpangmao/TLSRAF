package it.unitn.tlsraf.ds;

import it.unitn.tlsraf.func.CommandPanel;
import it.unitn.tlsraf.func.Func;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import javax.sql.CommonDataSource;

public class SecurityGoal extends RequirementElement {
	private boolean criticality;
	private boolean non_deterministic;

	private String asset;
	private String security_attribute;
	// private String interval;
	private String importance;
	private Element interval;
	// for better processing the interval property
	public String interval_id;
		
	// for next layer duplication
	// TODO: this should be remove later, er, or may be not....
	public SecurityGoal next_layer_copy = null;

	// for best path generation
	public SecurityGoal parent = null;
	public RequirementLink parent_link = null;
	
	// threats to this security goal. Record their id, search for the threat element when necessary. 
	public LinkedList <String> threats = new LinkedList<String>();

	// accommodate the applicability analysis
	public boolean applicability = false; // assign a default value 
	
	public SecurityGoal() {
		super();
		this.setType(InfoEnum.RequirementElementType.SECURITY_GOAL.name());
	}

	public SecurityGoal(String name, String type, String layer, LinkedList<RequirementLink> inLinks, LinkedList<RequirementLink> outLinks) {
		super(name, type, layer, inLinks, outLinks);
	}

	public SecurityGoal(String name, String type, String layer) {
		super(name, type, layer);
	}

	public SecurityGoal(String importance, String security_attribute, String asset, Element interval, String type, String layer) {
		super((importance + " " + security_attribute + " [" + asset + ", " + interval.getName() + "]").replaceAll("\\_", " "), type, layer);
		this.setSecurityAttribute(security_attribute);
		this.setAsset(asset);
		this.setInterval(interval);
		this.setImportance(importance);
	}

	public boolean isCriticality() {
		return criticality;
	}

	public void setCriticality(boolean criticality) {
		this.criticality = criticality;
	}

	public boolean isNon_deterministic() {
		return non_deterministic;
	}

	public void setNon_deterministic(boolean non_deterministic) {
		this.non_deterministic = non_deterministic;
	}

	public String getAsset() {
		return asset;
	}

	public void setAsset(String asset) {
		this.asset = asset;
		// resetName();
	}

	public String getSecurityAttribute() {
		return security_attribute;
	}

	public void setSecurityAttribute(String security_attribute) {
		this.security_attribute = security_attribute;
		// resetName();
	}

	public Element getInterval() {
		return interval;
	}

	public void setInterval(Element interval) {
		this.interval = interval;
		// resetName();
	}

	public String getImportance() {
		return importance;
	}

	public void setImportance(String importance) {
		this.importance = importance;
		// resetName();
	}

	// avoid to use this function
//	public void resetName() {
//		this.setName(this.importance + " " + this.security_attribute + " [" + this.asset + ", " + this.interval.getName() + "]");
//	}

	
	/**
	 * Extract initial information of a security goal via its text description To be more precise, we have changed this method to extract information from "user data"
	 * 
	 * @deprecated
	 */
	// public void extractInfoFromName() {
	// String sg = this.getName();
	// // sg = sg.replaceAll("\\(S\\)", "");
	// // first part
	// String pre_sg = sg.substring(0, sg.indexOf('[')).trim();
	// List<String> pre_list = Arrays.asList(pre_sg.split("\\s+"));
	// this.setImportance(pre_list.get(0));
	// if (pre_list.size() == 2) {
	// this.setSecurityAttribute(pre_list.get(1));
	// } else if (pre_list.size() == 3) {
	// this.setSecurityAttribute(pre_list.get(1) + " " + pre_list.get(2));
	// } else {
	// }
	// // second part
	// String post_sg = sg.substring(sg.indexOf('[') + 1, sg.length() - 1);
	// List<String> post_list = Arrays.asList(post_sg.split(","));
	// this.setAsset(post_list.get(0).trim());
	// this.setInterval(post_list.get(1).trim());
	// }

	/**
	 * Directly import security goal from the user data
	 * 
	 * @param user_data
	 * @param requirementGraph
	 */
	public void extractInfoFromUserData(String user_data, RequirementGraph graph) {
		List<String> user_data_set = Arrays.asList(user_data.split("\","));
		for (String temp : user_data_set) {
			int separator = temp.indexOf(":");
			String key = temp.substring(0, separator).trim().toLowerCase();
			// this value here don't need to be formalized
			String value = temp.substring(separator + 2).replace("\"}", "").trim();
			// in case, there is "_" in the expression, we first replace it with blank space
			value.replaceAll("\\_", " ");
			// if this is an input annotation
			if (key.toLowerCase().contains("importance")) {
				this.setImportance(value);
			} else if (key.toLowerCase().contains("sec_property")) {
				this.setSecurityAttribute(value);
			} else if (key.toLowerCase().contains("asset")) {
				this.setAsset(value);
			} else if (key.toLowerCase().contains("interval_id")) {
				Element elem = graph.findElementById(value);
				if(elem!=null){
					this.setInterval(elem);
				}
				else{
					// now we actually don't really need the interval element as part of the security goal, only the id is enough
//					CommandPanel.logger.info(("Information of security goal interval (ID:"+value+") is missing!") );
					this.setInterval(null);
					this.interval_id=value;
				}
			} else if (key.toLowerCase().contains("threat_ids")) {
				String [] threat_ids = value.split(",");
				for(String id: threat_ids){
					this.threats.add(id);
				}
			} else {
			}
			// System.out.println(key+" "+value+" "+temp);
		}

	}

	/**
	 * As a security goal has a structured name in its graphic representation, which cannot be used directly in the DLV reasoning (all others can), we have this additional formal
	 * name to support related reasoning.
	 * 
	 * @return formal name
	 */
	@Override
	public String getFormalName() {
		// String expression = this.getImportance() + "_" + this.getSecurityAttribute() + "_" + this.getAsset() + "_"
		// + this.getInterval();
		// // expression = expression.replaceAll(" ", "_").toLowerCase();
		// expression = Func.prepareFormalExpression(expression);
		//
		// return expression;

		// directly use the id of the security goal
		return this.getId();
	}

	@Override
	public String getFormalExpressions() {
		// String expression = "sec_goal(" + this.getImportance() + "_" + this.getSecurityAttribute() + "_"
		// + this.getAsset() + "_" + this.getInterval() + ").\n";
		String expression = this.getSingleFormalExpression() + "\n";

		if (this.isCriticality() == true) {
			expression += "critical(" + this.getFormalName() + ").\n";
		}

		expression += "sec_attribute(" + this.getSecurityAttribute() + ").\n";
		expression += "asset(" + this.getAsset() + ").\n";
		expression += "importance(" + this.getImportance() + ").\n";
		// first check whether the interval is null
		if(this.getInterval()!=null){
			expression += "interval(" + this.getInterval().getId() + ").\n";
			expression += "has_properties(" + getFormalName() + "," + this.getImportance() + "," + this.getSecurityAttribute() + "," + this.getAsset() + "," + this.getInterval().getId()
					+ ").\n";
		}
		else{ // if interval element is missing, we just put a placeholder here
		expression += "has_properties(" + getFormalName() + "," + this.getImportance() + "," + this.getSecurityAttribute() + "," + this.getAsset() + "," + "interval"
				+ ").\n";
		}
		// also output the ownership of this security goal, which maybe redundant, but helpful in exhaustive security goals analysis.
		if (this.owner != null) {
			expression += "has(" + this.owner.getFormalName() + "," + this.getFormalName() + ").\n";
		} else if (this.owner_text != null) {
			expression += "has(" + owner_text + "," + this.getFormalName() + ").\n";
		} else {
//			expression += "Warning: the security goal " + this.getFormalName() + " doesn't have an owner!";
		}
		
		// produce threat-related facts
		for(String threat : this.threats){
			if(!threat.equals("")){
				expression += "threatened_by(" + this.getFormalName()+ "," + threat + ").\n";
			}
		}

		expression = expression.replaceAll(" ", "_");
		return expression.toLowerCase();
	}

	@Override
	public void printInfo() {
		System.out.println("ID:" + this.getId() + "\n" + "Name:" + this.getName() + "\n" + "Type:" + this.getType() + "\n" + "Layer:" + this.getLayer() + "\n" + "Remark:"
				+ this.getRemark() + "\n" + "Criticality:" + this.isCriticality() + "\n" + "Importance:" + this.getImportance() + "\n" + "Security Attribute:"
				+ this.getSecurityAttribute() + "\n" + "Asset:" + this.getAsset() + "\n" + "Interval:" + this.getInterval());
	}

	/**
	 * This method is specifically used to show the name of the element that appears in graphviz
	 * @return
	 */
	public String getNameForShow(){
		String expression = this.getImportance() + "_" + this.getSecurityAttribute() + "_" + this.getAsset() + "_" + this.getInterval().getName();
		expression = Func.prepareFormalExpression(expression);
		return expression;
		
//		return this.getId();
	}

}
