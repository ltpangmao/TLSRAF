/***
 * The reason to have this separate class rather than the previous one, is because:
 * This part of analysis is comparatively isolated from the previous functions
 * In particular, this analysis has less constraints on the data and can be processed in a simpler way. 
 * Thus, we have it separate, otherwise, the analysis of this part may influence/modify the code of previous functions, which we want to avoid.
 * 
 * So we will only use previous functions/interfaces, and do minimal modifications here, if necessary. 
 */

package it.unitn.tlsraf.ds;

import it.unitn.tlsraf.func.AppleScript;
import it.unitn.tlsraf.func.CommandPanel;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import javax.script.ScriptException;

public class AttackModel {
	private LinkedList<Element> elements = new LinkedList<Element>();
	private LinkedList<Link> links = new LinkedList<Link>();
	private String type;

	public AttackModel() {
		super();
		type = InfoEnum.ModelCategory.HOLISTIC_SECURITY_GOAL_MODEL.name();
	}

	public AttackModel(String type) {
		super();
		this.type = type;
	}

	public LinkedList<Element> getElements() {
		return elements;
	}

	public void setElements(LinkedList<Element> elements) {
		this.elements = elements;
	}

	public LinkedList<Link> getLinks() {
		return links;
	}

	public void setLinks(LinkedList<Link> links) {
		this.links = links;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public void importGraphInfo(String result) throws IOException {
		if (this.getType() == InfoEnum.ModelCategory.ATTACK_MODEL.name()) {
			List<String> elements = Arrays.asList(result.split("\n"));
			// first processing, which simply imports all information from the text file
			for (String element : elements) {
				if (element.startsWith("element")) {
					List<String> factors = Arrays.asList(element.split(";"));
					if (this.findElementById(factors.get(1)) == null) {
						// avoid adding redundant elements
						RequirementElement elem = parseAttackElementInfo(factors);
						this.getElements().add(elem);
					}
				}
			}
			for (String element : elements) {
				if (element.startsWith("link")) {
					List<String> factors = Arrays.asList(element.split(";"));
					if (this.findLinkById(factors.get(1)) == null) {
						// avoid adding redundant links
						RequirementLink link = parseAttackModelLinkInfo(factors);
						this.getLinks().add(link);
					}
					// if (link != null) link.printInfo();
				}
			}
		}

		// second around processing, which processes redundant
		// "graph sugar", and correct and_refine, trust, depend relations.
		for (Element elem : this.getElements()) {
			reprocessRequirementElement((RequirementElement) elem);
		}
	}

	/**
	 * parse the graphical information into corresponding model elements
	 * 
	 * @param factors
	 * @return
	 */
	private RequirementElement parseAttackElementInfo(List<String> factors) {
		/*
		 * this part is exclusively for requirement elements 0)notation,element; 1)id,51670; 2)shape,Hexagon; 3)name,Calculate price; 4)Layer, Layer 1 by default; 5)thickness,;
		 * 6)double stroke; 7)size: 117.945899963379 43.817626953125; 8)no fill; 9)0.0 corner radius 10) stroke pattern: 0 11) origin: 87.234039306641 1084.06665039062 12) owner:
		 * xx 13) Canvas, Actor association; 14) user data
		 */

		RequirementElement new_elem = new RequirementElement();
		// no additional constraints
//		if (!factors.get(13).equals("HSGM")) {
//			CommandPanel.logger.fine("Canvas HSGM is supposed to be processed");
//		}

		// anti goals
		// we only capture the overall information here
		if (factors.get(2).equals("Circle") && !factors.get(3).equals("empty")) {
			new_elem = new NewAntiGoal();
			new_elem.setId(factors.get(1));
			new_elem.setType(InfoEnum.RequirementElementType.NEW_ANTI_GOAL.name());
			// obtain the content of the element
			String sg_name = factors.get(3);
			new_elem.setName(sg_name.trim());
			((NewAntiGoal)new_elem).extractInfoFromName();
		} else if (checkCircle(factors.get(7))) {
			// process actors
		}
		// all others
		else {
			new_elem = new RequirementElement();
			new_elem.setId(factors.get(1));
			if (factors.get(2).equals("Hexagon")) {
				new_elem.setType(InfoEnum.RequirementElementType.TASK.name());
			} else if (factors.get(2).equals("Rectangle")) {
				new_elem.setType(InfoEnum.RequirementElementType.DOMAIN_ASSUMPTION.name());
			} else if (factors.get(3).equals("empty") & factors.get(2).equals("Circle") & factors.get(10).equals("0")) {
				new_elem.setType(InfoEnum.RequirementElementType.MIDDLE_POINT.name());
			} else {
//				new_elem.setType(InfoEnum.req_elem_type_map.get(factors.get(2)));
			}
			new_elem.setName(factors.get(3));
		}
		
		// layout info
		String[] temp2 = factors.get(11).split(" ");
		new_elem.origin_x = Double.parseDouble(temp2[0].replace(",","."));
		new_elem.origin_y = Double.parseDouble(temp2[1].replace(",","."));
		
		return new_elem;
	}

	/**
	 * Parse the graphical information into corresponding model elements Note: If the link is isolated, we exclude them from our analysis Note: to simply the analysis, we actually
	 * treat all links as either "refine" or "and-refine"
	 * 
	 * @param factors
	 * @return
	 */
	private RequirementLink parseAttackModelLinkInfo(List<String> factors) {
		// obtain the elements of the link.
		Element source = findElementById(factors.get(4));
		Element target = findElementById(factors.get(5));
		if (target == null || source == null) {
			return null;
		}

		/*
		 * this part is exclusively for requirement elements 0)link; 1)id,51690 2)arrow type,StickArrow; 3)line type, curved; 4)source/tail,51670; 5)destination/head,51490;
		 * 6)label,NoLabel;(The shape of that label is not considered, only the content of that label) 7)dash type,0; 8)thickness,1.0; 9)head scale,1.0 10) layer, Layer 1
		 */
		// first assign basic information to the link
		RequirementLink new_link = new RequirementLink();
		new_link.setId(factors.get(1));
		new_link.setSource(source);
		new_link.setTarget(target);
		source.getOutLinks().add(new_link);
		target.getInLinks().add(new_link);

		// identify the type of the link. Here we roughly have them as either "refine" or "and-refine" for simplification, facilitating the intended analysis.
		// refine
		if ((factors.get(2).equals("SharpArrow") || factors.get(2).equals("StickArrow") || factors.get(2).equals("Arrow"))
				& !new_link.getSource().getType().equals(InfoEnum.RequirementElementType.MIDDLE_POINT.name())) {
			new_link.setType(InfoEnum.RequirementLinkType.REFINE.name());
			// the target of this link should update the "refine_links" information as well
			new_link.getTarget().refine_links.add(new_link);
		}
		// for all and-refine links, the corresponding information should be updated after re-processing the elements
		// and refine - main
		else if (factors.get(2).equals("SharpArrow") & new_link.getSource().getType().equals(InfoEnum.RequirementElementType.MIDDLE_POINT.name())) {
			new_link.setType(InfoEnum.RequirementLinkType.AND_REFINE_ARROW.name());
			// mark as redundant
			new_link.setRemark(InfoEnum.LinkRemark.REDUNDANT.name());
		}
		// and refine - branch
		else if (factors.get(2).equals("NoHead") & factors.get(6).equals("NoLabel")) {
			new_link.setType(InfoEnum.RequirementLinkType.AND_REFINE.name());
		}
		// exception
		else {
			CommandPanel.logger.severe("Unknown links cannot be imported");
		}
		return new_link;
	}

	/**
	 * Reprocess imported elements to clarify the "Refineum" related stuff
	 * 
	 * @param elem
	 */
	private void reprocessRequirementElement(RequirementElement elem) {
		// Process the middle refineum
		if (elem.getType().equals(InfoEnum.RequirementElementType.MIDDLE_POINT.name())) {
			elem.setRemark(InfoEnum.ElementRemark.REFINEUM.name());
			// process refineum related "and_refine" links
			if (elem.getOutLinks().size() != 1) {
				CommandPanel.logger.severe("and_refine link processing error");
			} else {
				RequirementElement target = elem.getOutLinks().getFirst().getTarget();
				for (RequirementLink l : elem.getInLinks()) {
					l.setTarget(target);
					// use additional space to store info about and-refine
					// relations
					target.and_refine_links.add(l);
				}
			}
			return;
		}
	}

	// TODO: can be further abstracted to a parent class, the same for the following methods.
	public String generateFormalExpression(int scope) {
		String result = "";
		if (scope == InfoEnum.ALL_MODELS) {
			for (Element e : this.elements) {
				RequirementElement re = (RequirementElement) e;
				if (re.getFormalExpressions() != "") {
					result += re.getFormalExpressions()+"\n";
				}

				// Treat "refine" link in a special way. 
				// the formalization of links (especially, the "refine" links) should be dynamically generated according to our needs
				if (re.refine_links!=null && re.refine_links.size() > 0) {
					String content = "";
					for (int i = 0; i < re.refine_links.size(); i++) {
						content += re.refine_links.get(i).getSource().getId() + ",";
						// if this is the last one, then add the refined element
						if (i == re.refine_links.size() - 1) {
							content += re.getId();
						}
					}
					result += "refine_" + re.refine_links.size() + "(" + content + ").\n";
				}
			}
			for (Link l: this.links){
				// generate formal predicates for all "and-refine" links 
				if(l.getType().equals(InfoEnum.RequirementLinkType.AND_REFINE.name())){
					// normal and-refine formalism
					result += l.getFormalExpressions()+"\n";
				}
				// generate formal predicates for all "refine" links as "syntactic sugar" 
				else if(l.getType().equals(InfoEnum.RequirementLinkType.REFINE.name())){
					result += l.getFormalExpressions()+"\n";
				}
			}
		} else if (scope == InfoEnum.SELECTED_MODELS) {
			// obtain selected elements' id
			ArrayList<Long> selected_elements = null;
			try {
				// here the returned value won't be null
				selected_elements = AppleScript.getSelectedGraph();
				RequirementElement selected_element = null;
				for(Long id :selected_elements){
					selected_element = (RequirementElement)findElementById(Long.toString(id));
					// we here process "only" the selected elements, and its refine links 
					if(selected_element!=null){
						result += selected_element.getFormalExpressions();
						// further process related "refine" links
						if (selected_element.refine_links.size() > 0) {
							String content ="";
							for(int i=0; i<selected_element.refine_links.size(); i++){
								content += selected_element.refine_links.get(i).getSource().getId() + ",";
								// if this is the last one, then add the refined element
								if(i==selected_element.refine_links.size()-1){
									content += selected_element.getId();
								} 
							}	
							result += "refine_"+selected_element.refine_links.size()+"("+content+").\n";
						}
					}
				}
				// process all "and-refine" links even though they may not be used during the inference.
				for (Link l: this.links){
					// generate formal predicates for all "and-refine" links 
					if(l.getType().equals(InfoEnum.RequirementLinkType.AND_REFINE.name())){
						// normal and-refine formalism
						result += l.getFormalExpressions()+"\n";
					}
					// generate formal predicates for all "refine" links as "syntactic sugar" 
					else if(l.getType().equals(InfoEnum.RequirementLinkType.REFINE.name())){
						result += l.getFormalExpressions()+"\n";
					}
				}
			} catch (ScriptException e1) {
				e1.printStackTrace();
			}
		} else{
			// should be errors
		}

		result = result.toLowerCase();
		return result;
	}
	


	/*
	 * public String generateFormalExpressionToFile() throws FileNotFoundException, UnsupportedEncodingException { String result = generateFormalExpression();
	 * 
	 * String output = ""; if (this.getType() == InfoEnum.ModelCategory.ACTOR.name()) { output = InfoEnum.current_directory + "/dlv/models/actor_association_model.dl"; } else {
	 * System.out.println("Actor association model error"); } PrintWriter writer = new PrintWriter(output, "UTF-8"); writer.println(result); writer.close();
	 * 
	 * return output; }
	 */

	public Element findElementById(String id) {
		for (Element e : this.elements) {
			if (e != null && e.getId().equals(id))
				return e;
		}
		return null;
	}
	
	public Element findElementByFormalName(String fname) {
		for (Element e : this.elements) {
			if (e.getFormalName().equals(fname))
				return e;
		}
		return null;
	}

	public Link findLinkById(String id) {
		for (Link l : this.links) {
			if (l != null && l.getId().equals(id))
				return l;
		}
		return null;
	}

	private boolean checkCircle(String size) {
		size = size.trim();
		String s1 = size.substring(0, size.indexOf(" "));
		String s2 = size.substring(size.indexOf(" ") + 1);
		return s1.equals(s2);
	}

}
