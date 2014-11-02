package it.unitn.tlsraf.ds;

import java.util.LinkedList;

/**
 * According to the specification of CAPEC
 * Define all fields as PUBLIC
 * @author litong30
 *
 */
public class AttackPattern {
	public String id;
	public String name;
	
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
		
		return s;
	}
}
