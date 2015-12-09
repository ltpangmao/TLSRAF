package it.unitn.tlsraf.ds;

import it.unitn.tlsraf.func.Func;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class NewAntiGoal extends RequirementElement{

	private String threat; // threat type
	private String asset; // threatened assets
	private String target;	// target system requirements
	private String interval;	// interval of the target
	
	
	// for best path generation
	public NewAntiGoal parent = null;
	public RequirementLink parent_link = null;
	

	public NewAntiGoal() {
		super();
		this.setType(InfoEnum.RequirementElementType.ANTI_GOAL.name());
	}

	public NewAntiGoal(String name, String type, String layer, LinkedList<RequirementLink> inLinks,
			LinkedList<RequirementLink> outLinks) {
		super(name, type, layer, inLinks, outLinks);
	}

	public NewAntiGoal(String name, String type, String layer) {
		super(name, type, layer);
	}

	public NewAntiGoal(String threat, String asset, String target, String protection, String type,
			String layer) {
		super(("[" +threat + ", " +  asset + ", " + target + ", "+ protection + "]").replaceAll("\\_", " "),
				type, layer);
		this.setThreat(threat);
		this.setAsset(asset);
		this.setTarget(target);
		this.setInterval(protection);
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

	public String getInterval() {
		return interval;
	}

	public void setInterval(String interval) {
		this.interval = interval;
		// resetName();
	}


	/**
	 * This will be changed according to the format of the anti-goal
	 */
	public void extractInfoFromName() {
		// standard input: [threat, data, target, protection]
		String sg = this.getName();
		sg = sg.trim().toLowerCase();
		// separate the anti-goal
		List<String> list = Arrays.asList(sg.split(","));
		for(String temp: list){
			if (temp.contains("threat")){
				String threat = temp.substring(temp.indexOf(":")+1).trim();
				if (threat.contains("(")){
					threat = threat.substring(0,threat.indexOf("(")).trim();
				}
				this.setThreat(threat);
			} else if (temp.contains("asset")){
				this.setAsset(temp.substring(temp.indexOf(":")+1).trim());
			} else if (temp.contains("target")){
				this.setTarget(temp.substring(temp.indexOf(":")+1).trim());
			} else if (temp.contains("interval")){
				this.setInterval(temp.substring(temp.indexOf(":")+1).trim());
			} else{
				// exception
				System.out.println("There is an exception!");
			}
		}
		if(this.getFormalExpressions().indexOf(":")>0){
			System.out.println("Import error ':'!");
		}
//		System.out.println(this.getFormalExpressions()+"\n\n\n");
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
		return this.getId();
	}
	
	
	/**
	 * This method generates all the related predicates of the anti-goal
	 */
	@Override
	public String getFormalExpressions() {
		
		String expression = this.getSingleFormalExpression() + "\n";
		//anti_goal(id,threat,asset,target,interval)
		expression += "anti_goal_properties(" + this.getId() + "," + this.getThreat() + "," + this.getAsset() + ","
			+ this.getTarget() + "," + this.getInterval() + ").\n";
		
//		expression += "impose_threat(" + this.getThreat() + ").\n";
//		expression += "asset(" + this.getAsset() + ").\n";
//		expression += "target(" + this.getId() + "," + this.getTarget() + ").\n";
		
		expression = Func.prepareFormalExpression(expression);
		return expression;
	}



	@Override
	public void printInfo() {
		System.out.println("ID:" + this.getId() + "\n" + "Name:" + this.getName() + "\n" + "Type:" + this.getType()
				+ "\n" + "Threat:" + this.getThreat() + "\n" + "Asset:"
				+ this.getAsset() + "\n" + "Target:" + this.getTarget() + "\n" + "Interval:"
				+ this.getInterval());
	}

}
