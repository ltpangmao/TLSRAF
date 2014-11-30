package it.unitn.tlsraf.ds;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class AntiGoal extends RequirementElement{
	private boolean criticality;

	private String threat; // threat type
	private String asset; // threatened assets
	private String target;	// target system requirements
	private Boolean protection;	// protection of the target
	
	// for next layer duplication
	// TODO: this should be remove later, er, or may be not....
	//	public SecurityGoal next_layer_copy = null;
	
	// for best path generation
//	public SecurityGoal parent = null;
//	public RequirementLink parent_link = null;
	

	public AntiGoal() {
		super();
		this.setType(InfoEnum.RequirementElementType.ANTI_GOAL.name());
	}

	public AntiGoal(String name, String type, String layer, LinkedList<RequirementLink> inLinks,
			LinkedList<RequirementLink> outLinks) {
		super(name, type, layer, inLinks, outLinks);
	}

	public AntiGoal(String name, String type, String layer) {
		super(name, type, layer);
	}

	public AntiGoal(String threat, String asset, String target, Boolean protection, String type,
			String layer) {
		super(("[" +threat + ", " +  asset + ", " + target + ", "+ protection + "]").replaceAll("\\_", " "),
				type, layer);
		this.setThreat(threat);
		this.setAsset(asset);
		this.setTarget(target);
		this.setProtection(protection);
	}

	public boolean isCriticality() {
		return criticality;
	}

	public void setCriticality(boolean criticality) {
		this.criticality = criticality;
	}

	public String getAsset() {
		return asset;
	}

	public void setAsset(String asset) {
		this.asset = asset;
		// resetName();
	}

	public String getThreat() {
		return threat;
	}

	public void setThreat(String threat) {
		this.threat = threat;
		// resetName();
	}

	public String getTarget() {
		return target;
	}

	public void setTarget(String target) {
		this.target = target;
		// resetName();
	}

	public Boolean getProtection() {
		return protection;
	}

	public void setProtection(Boolean protection) {
		this.protection = protection;
		// resetName();
	}

	// avoid to use this function
	public void resetName() {
		this.setName(("[" +threat + ", " +  asset + ", " + target + ", "+ protection + "]").replaceAll("\\_", " "));
	}

	/**
	 * This will be changed according to the format of the anti-goal
	 */
	public void extractInfoFromName() {
		// standard input: [threat, data, target, protection]
		String sg = this.getName();
		//remove the parenthesis
		sg = sg.replace("[", "");
		sg = sg.replace("]", "");
		sg = sg.trim();
		// separate the anti-goal
		List<String> list = Arrays.asList(sg.split(","));
		this.setThreat(list.get(0).trim());
		this.setAsset(list.get(1).trim());
		this.setTarget(list.get(2).trim());
		this.setProtection(Boolean.valueOf(list.get(3).trim()));
	}

	
	/**
	 * As a security goal has a structured name in its graphic representation,
	 * which cannot be used directly in the DLV reasoning (all others can), we
	 * have this additional formal name to support related reasoning.
	 * Actually, the formal name can be seen as a unique ID for each anti-goal
	 * @return formal name
	 */
	@Override
	public String getFormalName() {
		String expression = this.getThreat() + "_" + this.getAsset() + "_" + this.getTarget() + "_"
				+ this.getProtection();
		expression = expression.replaceAll(" ", "_");

		return expression.toLowerCase();
	}
	
	
	/**
	 * This method generates all the related predicates of the anti-goal
	 */
	@Override
	public String getFormalExpressions() {
		//String expression = "sec_goal(" + this.getImportance() + "_" + this.getSecurityAttribute() + "_"
			//	+ this.getAsset() + "_" + this.getInterval() + ").\n";
		String expression = this.getSingleFormalExpression() + "\n";
		
		if (this.isCriticality() == true) {
			expression += "is_critical_anti(" + this.getFormalName() + ").\n"; 
		}
		
		expression += "threat(" + this.getThreat() + ").\n";
		expression += "asset(" + this.getAsset() + ").\n";
		expression += "target(" + this.getTarget() + ").\n";
		expression += "protection(" + this.getProtection() + ").\n"; 
		expression += "has_properties(" + getFormalName() + "," + this.getThreat() + ","
				+ this.getAsset() + "," + this.getTarget() + "," + this.getProtection() + ").\n";
		
		expression = expression.replaceAll(" ", "_");
		return expression.toLowerCase();
	}



	@Override
	public void printInfo() {
		System.out.println("ID:" + this.getId() + "\n" + "Name:" + this.getName() + "\n" + "Type:" + this.getType()
				+ "\n" + "Layer:" + this.getLayer() + "\n" + "Remark:" + this.getRemark() + "\n" + "Criticality:"
				+ this.isCriticality() + "\n" + "Threat:" + this.getThreat() + "\n" + "Asset:"
				+ this.getAsset() + "\n" + "Target:" + this.getTarget() + "\n" + "Protected target:"
				+ this.getProtection());
	}

}
