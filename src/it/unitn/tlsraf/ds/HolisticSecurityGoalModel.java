/***
 * The reason to have this separate class rather than the previous one, is because:
 * This part of analysis is comparatively isolated from the previous functions
 * In particular, this analysis has less constraints on the data and can be processed in a simpler way. 
 * Thus, we have it separate, otherwise, the analysis of this part may influence/modify the code of previous functions, which we want to avoid.
 * 
 * So we will only use previous functions/interfaces, and do minimal modifications here, if necessary. 
 */

package it.unitn.tlsraf.ds;

import it.unitn.tlsraf.func.CommandPanel;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class HolisticSecurityGoalModel {
	private LinkedList<Element> elements = new LinkedList<Element>();
	private LinkedList<Link> links = new LinkedList<Link>();
	private String type;

	public HolisticSecurityGoalModel() {
		super();
		type = InfoEnum.ModelCategory.HOLISTIC_SECURITY_GOAL_MODEL.name();
	}

	public HolisticSecurityGoalModel(String type) {
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
		if (this.getType() == InfoEnum.ModelCategory.HOLISTIC_SECURITY_GOAL_MODEL.name()) {
			List<String> elements = Arrays.asList(result.split("\n"));
			// first processing, which simply imports all information from the text file
			for (String element : elements) {
				if (element.startsWith("element")) {
					List<String> factors = Arrays.asList(element.split(";"));
					if (this.findElementById(factors.get(1)) == null) {
						// avoid adding redundant elements
						RequirementElement elem = parseSecurityElementInfo(factors);
						this.getElements().add(elem);
					}
				}
			}
			for (String element : elements) {
				if (element.startsWith("link")) {
					List<String> factors = Arrays.asList(element.split(";"));
					if (this.findLinkById(factors.get(1)) == null) {
						// avoid adding redundant links
						RequirementLink link = parseSecurityGoalLinkInfo(factors);
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
	private RequirementElement parseSecurityElementInfo(List<String> factors) {
		/*
		 * this part is exclusively for requirement elements 0)notation,element; 1)id,51670; 2)shape,Hexagon; 3)name,Calculate price; 4)Layer, Layer 1 by default; 5)thickness,;
		 * 6)double stroke; 7)size: 117.945899963379 43.817626953125; 8)no fill; 9)0.0 corner radius 10) stroke pattern: 0 11) origin: 87.234039306641 1084.06665039062 12) owner:
		 * xx 13) Canvas, Actor association
		 */

		RequirementElement new_elem = new RequirementElement();
		if (!factors.get(13).equals("HSGM")) {
			CommandPanel.logger.fine("Canvas HSGM is supposed to be processed");
		}

		// security goals
		// we only capture the overall information here
		if (factors.get(3).contains("(S)") & factors.get(2).equals("Cloud")) {
			new_elem = new SecurityGoal();
			new_elem.setId(factors.get(1));
			new_elem.setType(InfoEnum.RequirementElementType.SECURITY_GOAL.name());

			String sg_name = factors.get(3);

			// remove"(S)" at the first beginning
			sg_name = sg_name.replaceAll("\\(S\\)", "");

			new_elem.setName(sg_name.trim());
			// This may be useful in elaborated analysis
			new_elem.setLayer(factors.get(4));
			// get value for security-specific attributes
			// if (Float.valueOf(factors.get(5)) > 1) {
			// comma is used as separator... 5,0
			if (factors.get(5).startsWith("5")) {
				((SecurityGoal) new_elem).setCriticality(true);
			} else {
				((SecurityGoal) new_elem).setCriticality(false);
			}
			// This part should not be used in holistic solution generation
			// // this value can be useful in the following analysis
			// new_elem.owner_text = factors.get(12);
			// ((SecurityGoal) new_elem).extractInfoFromName();
		} else if (checkCircle(factors.get(7))) {
			new_elem = new Actor();
			new_elem.setId(factors.get(1));
			new_elem.setName(factors.get(3));
			new_elem.setLayer(factors.get(4));
			new_elem.setType(InfoEnum.RequirementElementType.ACTOR.name());
		}
		// all others
		else {
			new_elem = new RequirementElement();
			new_elem.setId(factors.get(1));
			if (factors.get(3).startsWith("(S)") & factors.get(2).equals("Hexagon")) {
				new_elem.setType(InfoEnum.RequirementElementType.SECURITY_MECHANISM.name());
			} else if (factors.get(3).equals("empty") & factors.get(2).equals("Circle") & factors.get(10).equals("0")) {
				new_elem.setType(InfoEnum.RequirementElementType.MIDDLE_POINT.name());
			} else if (factors.get(3).equals("empty") & factors.get(2).equals("Circle") & factors.get(10).equals("1")) {
				new_elem.setType(InfoEnum.RequirementElementType.ACTOR_BOUNDARY.name());
				new_elem.setRemark(InfoEnum.ElementRemark.BOUNDARY.name());
			} else if (factors.get(2).equals("AndGate") || (factors.get(2).equals("Rectangle") & factors.get(9).equals("0.0"))) {// Why rectangle?
				new_elem.setType(InfoEnum.RequirementElementType.LABEL.name());
			} else {
				new_elem.setType(InfoEnum.req_elem_type_map.get(factors.get(2)));
			}

			if (factors.get(3).startsWith("(S)")) {
				String sm_name = factors.get(3);
				// remove"(S)" at the first beginning
				sm_name = sm_name.replaceAll("\\(S\\)", "");
				new_elem.setName(sm_name.trim());
			} else {
				new_elem.setName(factors.get(3));
			}
			new_elem.setLayer(factors.get(4));
		}
		return new_elem;
	}

	/**
	 * Parse the graphical information into corresponding model elements Note: If the link is isolated, we exclude them from our analysis Note: to simply the analysis, we actually
	 * treat all links as either "refine" or "and-refine"
	 * 
	 * @param factors
	 * @return
	 */
	private RequirementLink parseSecurityGoalLinkInfo(List<String> factors) {
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

		// identify the type of the link. Here we roughly have them as either "refine" or "and-refine" for simplification, regarding the intended analysis.
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
	public String generateFormalExpression() {
		String result = "";
		for (Element e : this.elements) {
			RequirementElement re = (RequirementElement) e;
			if (re.getFormalExpressions() != "") {
				// we here only use the id to represent elements, rather than the full description
				if (re.getType().equals(InfoEnum.RequirementElementType.SECURITY_GOAL.name())) {
					result += "sec_goal(" + re.getId() + ").\n";					
				} 
				else if (re.getType().equals(InfoEnum.RequirementElementType.SECURITY_MECHANISM.name())){
					result += "sec_mechanism(" + re.getId() + ").\n";
				}
				else if (re.getType().equals(InfoEnum.RequirementElementType.DOMAIN_ASSUMPTION.name())){
					result += "d_assumption(" + re.getId() + ").\n";
				}
				else if (re.getType().equals(InfoEnum.RequirementElementType.GOAL.name())){
					result += "goal(" + re.getId() + ").\n";
				}
				else if (re.getType().equals(InfoEnum.RequirementElementType.TASK.name())){
					result += "task(" + re.getId() + ").\n";
				}
				else {
					// don't consider other types of elements in this analysis
					result += "";
				}
			}

			// Here for all non-leaf nodes, each of them should have either "and-refine" or "refine" links
			// the formalization of links (especially, the "refine" links) should be dynamically generated according to our needs
			// customized refine formalism, we enumerate "refine" relations up to 5 alternatives.
			if (re.refine_links.size() > 0) {
				String content ="";
				for(int i=0; i<re.refine_links.size(); i++){
					content += re.refine_links.get(i).getSource().getId() + ",";
					// if this is the last one, then add the refined element
					if(i==re.refine_links.size()-1){
						content += re.getId();
					} 
				}	
				result += "refine_"+re.refine_links.size()+"("+content+").\n";
				
				// also have the normal refine predicates, i.e., refine(G2,G1), for additional processing
//				for (RequirementLink rl : re.refine_links) {
//					result += "refine(" + rl.getSource().getId() + "," + re.getId() + ").\n";
//				}
			}
			// normal and-refine formalism
			else if (re.and_refine_links.size() > 0) {
				// traverse all and-refinements
				for (RequirementLink rl : re.and_refine_links) {
					result += "and_refine(" + rl.getSource().getId() + "," + re.getId() + ").\n";
//					result += rl.getFormalExpressions() + "\n";
				}
			}
			else {
				// do nothing for all other links, i.e., only concern refinement in this case.
			}
		}

		// for (Link l : this.links) {
		// if (l.getFormalExpressions() != "")
		// result += l.getFormalExpressions() + "\n";
		// }

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
