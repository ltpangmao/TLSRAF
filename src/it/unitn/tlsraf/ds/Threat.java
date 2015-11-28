package it.unitn.tlsraf.ds;

import java.util.LinkedList;
import java.util.List;

public class Threat {

	private String id="";
	
	private String name="";
	private List<String> assets = new LinkedList<String>();
	private List<String> threat_types = new LinkedList<String>();
	private List<String> intervals = new LinkedList<String>();
	private List<String> scenarios = new LinkedList<String>();
	
	

	public Threat() {
		super();
	}
	

//	public Threat(String id, List<String> assets, List<String> threats, List<String> intervals, List<String> scenarios) {
//		super();
//		this.id = id;
//		this.assets = assets;
//		this.threat_types = threats;
//		this.intervals = intervals;
//		this.scenarios = scenarios;
//	}

	


	public Threat(String id, String name, List<String> assets, List<String> threat_types, List<String> intervals, List<String> scenarios) {
		super();
		this.id = id;
		this.name = name;
		this.assets = assets;
		this.threat_types = threat_types;
		this.intervals = intervals;
		this.scenarios = scenarios;
	}


	public String getId() {
		return id;
	}


	public void setId(String id) {
		this.id = id;
	}


	public List<String> getAssets() {
		return assets;
	}


	public void setAssets(List<String> assets) {
		this.assets = assets;
	}


	public List<String> getIntervals() {
		return intervals;
	}


	public void setIntervals(List<String> intervals) {
		this.intervals = intervals;
	}
	
	public String getName() {
		return name;
	}


	public void setName(String name) {
		this.name = name;
	}


	public List<String> getThreat_types() {
		return threat_types;
	}


	public void setThreat_types(List<String> threat_types) {
		this.threat_types = threat_types;
	}


	public List<String> getScenarios() {
		return scenarios;
	}


	public void setScenarios(List<String> scenarios) {
		this.scenarios = scenarios;
	}
	
	
	public String generateFormalExpressionsToFile(){
		String formal_expressions = "";
		// traverse all information set to produce related knowledge
		for (String threat_type : threat_types) {
			for (String asset : assets) {
				for (String interval : intervals) {
					formal_expressions += "threat(" + this.id + "," + threat_type + "," + asset + "," + interval + ").\n";
				}
			}
		}
		return formal_expressions;
	}
	
	public void test(){
		for(String scenario: scenarios){
			System.out.println(scenario+"\n\n\n\n\n\n\n");
		}
	}
	
	
}
