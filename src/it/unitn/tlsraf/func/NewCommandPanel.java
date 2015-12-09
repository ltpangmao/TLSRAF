package it.unitn.tlsraf.func;

import it.unitn.tlsraf.ds.ActorAssociationGraph;
import it.unitn.tlsraf.ds.HolisticSecurityGoalModel;
import it.unitn.tlsraf.ds.InfoEnum;
import it.unitn.tlsraf.ds.RequirementGraph;

import java.awt.EventQueue;
import java.awt.Insets;
import java.util.LinkedList;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.script.ScriptException;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JToolBar;
import javax.swing.JComboBox;
import javax.swing.JToggleButton;
import javax.swing.JTabbedPane;
import javax.swing.JRadioButton;
import javax.swing.JLabel;
import javax.swing.JButton;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

import javax.swing.JSeparator;
import javax.swing.border.Border;

import java.awt.Font;

import javax.swing.JTextArea;

import java.awt.Color;

import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.SwingConstants;

import java.awt.ScrollPane;

public class NewCommandPanel{
	// static logger that is used over the whole project
	public static Logger logger;

	static public void setup() {
		// Get the global logger to configure it
		logger = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);
//		logger.setLevel(Level.SEVERE);
		// logger.setLevel(Level.WARNING);
		 logger.setLevel(Level.INFO);
	}
	
	// Set of models
	private ModelSet ms;
	public ModelSet getMs() {
		return ms;
	}

	public void setMs(ModelSet ms) {
		this.ms = ms;
	}
	

	private JFrame frmMuserControlPanel;
	private JTextField textField;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					// first initialize the global logger
//					NewCommandPanel.setup();
					CommandPanel.setup(); 
					// initialize the window
					NewCommandPanel window = new NewCommandPanel();
					window.frmMuserControlPanel.setVisible(true);
					window.frmMuserControlPanel.setResizable(false);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public NewCommandPanel() {
		initialize();
		ms = new ModelSet();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frmMuserControlPanel = new JFrame();
		frmMuserControlPanel.setTitle("MUSER Control Panel");
		frmMuserControlPanel.setBounds(100, 100, 503, 749);//1065
		frmMuserControlPanel.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frmMuserControlPanel.getContentPane().setLayout(null);
		
		final JComboBox<String> importSource = new JComboBox<String>();
		importSource.setName("Import Source");
		importSource.addItem("Selected elements");
		importSource.addItem("From files");
		importSource.setBounds(22, 23, 169, 27);
		frmMuserControlPanel.getContentPane().add(importSource);
		
		JLabel lblImportSource = new JLabel("Import Source");
		lblImportSource.setBounds(27, 7, 95, 16);
		frmMuserControlPanel.getContentPane().add(lblImportSource);
		
		final JComboBox<String> modelType = new JComboBox<String>();
		modelType.setName("Model Type");
		modelType.addItem("Requirements model");
		modelType.addItem("Resource schema");
		modelType.addItem("Dataflow diagram");
		modelType.addItem("Threat model");
//		modelType.addItem("Trust model");
		modelType.addItem("Holistic security goal model");
		modelType.addItem("Attack model");
		modelType.setBounds(193, 23, 169, 27);
		frmMuserControlPanel.getContentPane().add(modelType);
		
		JLabel lblModelType = new JLabel("Model Type");
		lblModelType.setBounds(193, 7, 95, 16);
		frmMuserControlPanel.getContentPane().add(lblModelType);
		
		final JTextArea alternative_list = new JTextArea();
		alternative_list.setLineWrap(true);
//		scrollPane.setColumnHeaderView(alternative_list);
//		alternative_list.setBounds(27, 293, 982, 335);
//		frmMuserControlPanel.getContentPane().add(alternative_list);

		
		JScrollPane scrollPane = new JScrollPane(alternative_list, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
				JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
		scrollPane.setBounds(27, 500, 450, 200);
		frmMuserControlPanel.getContentPane().add(scrollPane);
		
		
		JButton btnImport = new JButton("Import");
		btnImport.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				// Obtain parameters
				// for importing, we don't distinguish layers,
				String model = getCommand(modelType);
				String command = getCommand(importSource);
				Boolean canvas = null;
				if (command.equals(InfoEnum.Commands.IMP_SELECTION.name())) {
					canvas = true;
				} else if (command.equals(InfoEnum.Commands.IMP_FILE.name())) {
					canvas = false;
				} else {
					logger.warning("Import command error!");
				}
				
				// Execution
				try {
					if (model.equals(InfoEnum.ModelCategory.REQUIREMENT.name())) {
						Inference.importReqModel(ms, canvas);
						JOptionPane.showMessageDialog(frmMuserControlPanel, "Finish importing requirement models!");
					} else if (model.equals(InfoEnum.ModelCategory.HOLISTIC_SECURITY_GOAL_MODEL.name())) {
						HSGMInference.importHolisticSecurityGoalModel(ms.hsgm, canvas);
						JOptionPane.showMessageDialog(frmMuserControlPanel, "Finish importing holistic security goal models!");
					} else if (model.equals(InfoEnum.ModelCategory.DATA_FLOW.name())) {
//						ReferenceModelInference.importDataFlowModel(canvas);
						ReferenceModelInference.importDataFlowModelWithID(ms, canvas);
						JOptionPane.showMessageDialog(frmMuserControlPanel, "Finish importing data flow diagram!");
					} else if (model.equals(InfoEnum.ModelCategory.THREAT_MODEL.name())) {
						ReferenceModelInference.importThreatModel(ms, canvas);;
						JOptionPane.showMessageDialog(frmMuserControlPanel, "Finish importing threat model!");
					} else if (model.equals(InfoEnum.ModelCategory.RESOURCE_SCHEMA.name())) {
						ReferenceModelInference.importResourceSchema(ms.assets, canvas);;
						JOptionPane.showMessageDialog(frmMuserControlPanel, "Finish importing resource schema!");
					} else if (model.equals(InfoEnum.ModelCategory.ATTACK_MODEL.name())) {
						AttackModelInference.importAttackModel(ms.attack_model, canvas);
						JOptionPane.showMessageDialog(frmMuserControlPanel, "Finish importing attack models!");
					}
//					else if (model.equals(InfoEnum.ModelCategory.ACTOR.name())) {
//						Inference.importActorModel(ms.actor_model, canvas);
//						JOptionPane.showMessageDialog(frmMuserControlPanel, "Finish importing trust models!");
//					}
					  else {
						logger.warning("Command error!");
					}
				} catch (IOException e1) {
					e1.printStackTrace();
				} catch (ScriptException e1) {
					e1.printStackTrace();
				}
			}
		});
		btnImport.setBounds(22, 62, 86, 39);
		frmMuserControlPanel.getContentPane().add(btnImport);
		
		JButton btnDelete = new JButton("Delete");
		btnDelete.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				ms = new ModelSet();
//				ms.req_bus_model = new RequirementGraph(ms.req_bus_model.getType(), ms.req_bus_model.getLayer());
//				ms.req_app_model = new RequirementGraph(ms.req_app_model.getType(), ms.req_app_model.getLayer());
//				ms.req_phy_model = new RequirementGraph(ms.req_phy_model.getType(), ms.req_phy_model.getLayer());
//				
//				ms.actor_model = new ActorAssociationGraph(InfoEnum.ModelCategory.ACTOR.name());
//				ms.hsgm = new HolisticSecurityGoalModel(InfoEnum.ModelCategory.HOLISTIC_SECURITY_GOAL_MODEL.name());
//				ms.assets = new LinkedList<String>();
				
				JOptionPane.showMessageDialog(frmMuserControlPanel, "Delete all models!");
			}
		});
		btnDelete.setBounds(120, 62, 86, 39);
		frmMuserControlPanel.getContentPane().add(btnDelete);
		
		JLabel lblAnalysisType = new JLabel("Analysis Type");
		lblAnalysisType.setBounds(22, 113, 97, 16);
		frmMuserControlPanel.getContentPane().add(lblAnalysisType);
		
		final JComboBox<String> analysis_type = new JComboBox<String>();
		analysis_type.setName("Analysis Type");
		analysis_type.addItem("Security Goal");
		analysis_type.addItem("Anti-Goal");
		analysis_type.setBounds(22, 141, 115, 27);
		frmMuserControlPanel.getContentPane().add(analysis_type);
		

		
		JLabel lblLayer = new JLabel("Layer");
		lblLayer.setBounds(149, 113, 61, 16);
		frmMuserControlPanel.getContentPane().add(lblLayer);
		
		final JComboBox<String> layer = new JComboBox<String>();
		layer.setName("Layer");
		// although it is possible to run all inference rules for all layers, it is really useless to do so 
//		layer.addItem("All");
		layer.addItem("Business");
		layer.addItem("Application");
		layer.addItem("Physical");
		layer.setBounds(149, 141, 112, 27);
		frmMuserControlPanel.getContentPane().add(layer);
		
		JButton btnPrint = new JButton("Print");
		btnPrint.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String layer_choice = getCommand(layer);
				if (layer_choice.equals(InfoEnum.Layer.ALL.name())) {
					ms.req_bus_model.printModel();
					ms.req_app_model.printModel();
					ms.req_phy_model.printModel();
				} else if (layer_choice.equals(InfoEnum.Layer.BUSINESS.name())) {
					ms.req_bus_model.printModel();
				} else if (layer_choice.equals(InfoEnum.Layer.APPLICATION.name())) {
					ms.req_app_model.printModel();
				} else if (layer_choice.equals(InfoEnum.Layer.PHYSICAL.name())) {
					ms.req_phy_model.printModel();
				} else {
					NewCommandPanel.logger.severe("Layer selection error!");
				}
			}
		});
		btnPrint.setBounds(214, 62, 86, 39);
		frmMuserControlPanel.getContentPane().add(btnPrint);
		
		
		JButton btnSavetofile = new JButton("SaveToFile");
		btnSavetofile.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
			
				try {
					ms.req_bus_model.generateFormalExpressionToFile(InfoEnum.ALL_MODELS);					
					ms.req_app_model.generateFormalExpressionToFile(InfoEnum.ALL_MODELS);
					ms.req_phy_model.generateFormalExpressionToFile(InfoEnum.ALL_MODELS);
					ms.writeSupportLinksToFile();

				} catch (FileNotFoundException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (UnsupportedEncodingException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				JOptionPane.showMessageDialog(frmMuserControlPanel, "Finish writing support links to a file!");
			}
		});
		btnSavetofile.setBounds(312, 62, 86, 39);
		frmMuserControlPanel.getContentPane().add(btnSavetofile);
		
		
		final JComboBox<String> object = new JComboBox<String>();
		object.setName("Object");
		object.addItem("Selected models");
		object.addItem("All models");
		object.setBounds(273, 141, 117, 27);
		frmMuserControlPanel.getContentPane().add(object);
//		object.setSelectedItem("Selected models");
		
		JLabel lblObject = new JLabel("Object");
		lblObject.setBounds(281, 113, 61, 16);
		frmMuserControlPanel.getContentPane().add(lblObject);
		
		final JComboBox<String> refinementMode = new JComboBox<String>();
		refinementMode.setName("Refinement Mode");
		refinementMode.addItem("One-step");
		refinementMode.addItem("Exhaustive");
		refinementMode.setBounds(240, 243, 110, 28);
		frmMuserControlPanel.getContentPane().add(refinementMode);
		
		JLabel lblRefinementMode = new JLabel("Refinement Mode");
		lblRefinementMode.setBounds(240, 225, 125, 16);
		frmMuserControlPanel.getContentPane().add(lblRefinementMode);
		
		final JComboBox<String> refinementDimension = new JComboBox<String>();
		refinementDimension.setName("Refinement Dimension");
		refinementDimension.addItem("Attribute");
		refinementDimension.addItem("Asset");
		refinementDimension.addItem("Interval");
		refinementDimension.addItem("Threat(anti)");
		refinementDimension.addItem("Asset(anti)");
		refinementDimension.addItem("Target(anti)");
		refinementDimension.addItem("Protection(anti)");
		refinementDimension.setBounds(120, 243, 110, 28);
		frmMuserControlPanel.getContentPane().add(refinementDimension);
		
		JLabel lblRefinementDimension = new JLabel("Dimension");
		lblRefinementDimension.setBounds(128, 225, 78, 16);
		frmMuserControlPanel.getContentPane().add(lblRefinementDimension);
		
		JSeparator separator = new JSeparator();
		separator.setBounds(22, 98, 442, 12);
		frmMuserControlPanel.getContentPane().add(separator);
		
		final JComboBox<String> visualization = new JComboBox<String>();
		visualization.setName("Visualization");
		visualization.addItem("OmniGraffle");
		visualization.addItem("Graphviz");
		visualization.setBounds(360, 243, 110, 28);
		frmMuserControlPanel.getContentPane().add(visualization);
		
		JLabel lblVisualization = new JLabel("Visualization");
		lblVisualization.setBounds(377, 225, 95, 16);
		frmMuserControlPanel.getContentPane().add(lblVisualization);
		
		JLabel lblImportModel = new JLabel("Import Model");
		lblImportModel.setVisible(false);
		lblImportModel.setFont(new Font("Tahoma", Font.PLAIN, 14));
		lblImportModel.setBounds(377, 6, 97, 16);
		frmMuserControlPanel.getContentPane().add(lblImportModel);
		
		JLabel lblAnalyzeModel = new JLabel("Analyze Model");
		lblAnalyzeModel.setVisible(false);
		lblAnalyzeModel.setFont(new Font("Tahoma", Font.PLAIN, 14));
		lblAnalyzeModel.setBounds(374, 26, 125, 16);
		frmMuserControlPanel.getContentPane().add(lblAnalyzeModel);
	
		
		JButton btnStep_1 = new JButton("<html>Step 1:<br/>Refine</html>");
		btnStep_1.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String analysis_choice = getCommand(analysis_type);
				String layer_choice = getCommand(layer);
				String mode_choice = getCommand(refinementMode);
				String visualization_choice = getCommand(visualization);
				String object_choice = getCommand(object);
				// TODO: this dimension choice is defined as a standard command,
				// we simply use its lower-case content here
				String dimension_choice = getCommand(refinementDimension);
				try {
					if (analysis_choice.equals(InfoEnum.RequirementElementType.SECURITY_GOAL.name())) {
						if (mode_choice.equals(InfoEnum.Commands.REF_ALL_ONE_STEP.name())) {
							if (layer_choice.equals(InfoEnum.Layer.BUSINESS.name())) {
								Inference.securityGoalRefine(ms.req_bus_model, dimension_choice, Integer.valueOf(object_choice));
							} else if (layer_choice.equals(InfoEnum.Layer.APPLICATION.name())) {
								Inference.securityGoalRefine(ms.req_app_model, dimension_choice, Integer.valueOf(object_choice));
							} else if (layer_choice.equals(InfoEnum.Layer.PHYSICAL.name())) {
								Inference.securityGoalRefine(ms.req_phy_model, dimension_choice, Integer.valueOf(object_choice));
							} else {
								NewCommandPanel.logger.severe("Layer selection error!");
							}
							JOptionPane.showMessageDialog(frmMuserControlPanel, "Finish one-step refinement!");
						} else if (mode_choice.equals(InfoEnum.Commands.REF_ALL_EXHAUSTIVE.name())) {
							if (layer_choice.equals(InfoEnum.Layer.BUSINESS.name())) {
								Inference.exhaustiveSecurityGoalRefineAnalysis(ms, ms.req_bus_model, ms.actor_model,
										Integer.valueOf(visualization_choice), Integer.valueOf(object_choice));
							} else if (layer_choice.equals(InfoEnum.Layer.APPLICATION.name())) {
								Inference.exhaustiveSecurityGoalRefineAnalysis(ms, ms.req_app_model, ms.actor_model,
										Integer.valueOf(visualization_choice), Integer.valueOf(object_choice));
							} else if (layer_choice.equals(InfoEnum.Layer.PHYSICAL.name())) {
								Inference.exhaustiveSecurityGoalRefineAnalysis(ms, ms.req_phy_model, ms.actor_model,
										Integer.valueOf(visualization_choice), Integer.valueOf(object_choice));
							} else {
								NewCommandPanel.logger.severe("Layer selection error!");
							}
							JOptionPane.showMessageDialog(frmMuserControlPanel, "Finish exhaustive refinement!");
						}
					}
					else if(analysis_choice.equals(InfoEnum.RequirementElementType.ANTI_GOAL.name())){
						if (mode_choice.equals(InfoEnum.Commands.REF_ALL_ONE_STEP.name())) {
							if (layer_choice.equals(InfoEnum.Layer.BUSINESS.name())) {
								AntiGoalInference.antiGoalRefine(ms.req_bus_model, dimension_choice, Integer.valueOf(object_choice));
							} else if (layer_choice.equals(InfoEnum.Layer.APPLICATION.name())) {
								AntiGoalInference.antiGoalRefine(ms.req_app_model, dimension_choice, Integer.valueOf(object_choice));
							} else if (layer_choice.equals(InfoEnum.Layer.PHYSICAL.name())) {
								AntiGoalInference.antiGoalRefine(ms.req_phy_model, dimension_choice, Integer.valueOf(object_choice));
							} else {
								NewCommandPanel.logger.severe("Layer selection error!");
							}
							JOptionPane.showMessageDialog(frmMuserControlPanel, "Finish one-step refinement!");
						} else if (mode_choice.equals(InfoEnum.Commands.REF_ALL_EXHAUSTIVE.name())) {
							if (layer_choice.equals(InfoEnum.Layer.BUSINESS.name())) {
								AntiGoalInference.exhaustiveAntiGoalRefineAnalysis(ms.req_bus_model, ms.actor_model,
										Integer.valueOf(visualization_choice), Integer.valueOf(object_choice));
							} else if (layer_choice.equals(InfoEnum.Layer.APPLICATION.name())) {
								AntiGoalInference.exhaustiveAntiGoalRefineAnalysis(ms.req_app_model, ms.actor_model,
										Integer.valueOf(visualization_choice), Integer.valueOf(object_choice));
							} else if (layer_choice.equals(InfoEnum.Layer.PHYSICAL.name())) {
								AntiGoalInference.exhaustiveAntiGoalRefineAnalysis(ms.req_phy_model, ms.actor_model,
										Integer.valueOf(visualization_choice), Integer.valueOf(object_choice));
							} else {
								NewCommandPanel.logger.severe("Layer selection error!");
							}
							JOptionPane.showMessageDialog(frmMuserControlPanel, "Finish exhaustive refinement!");
						}
					}
				} catch (IOException e1) {
					e1.printStackTrace();
				} catch (ScriptException e1) {
					e1.printStackTrace();
				}
			}
		});
		btnStep_1.setBounds(22, 215, 95, 55);
		frmMuserControlPanel.getContentPane().add(btnStep_1);
		
		JButton btnStep_2 = new JButton("<html>Step 2:<br/>Simplify</html>");
		btnStep_2.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String layer_choice = getCommand(layer);
				String object_choice = getCommand(object);
				try {
					if (layer_choice.equals(InfoEnum.Layer.BUSINESS.name())) {
						Inference.threatBasedSecurityGoalSimplification(ms, ms.req_bus_model, Integer.valueOf(object_choice));
					} else if (layer_choice.equals(InfoEnum.Layer.APPLICATION.name())) {
						Inference.threatBasedSecurityGoalSimplification(ms, ms.req_app_model, Integer.valueOf(object_choice));
					} else if (layer_choice.equals(InfoEnum.Layer.PHYSICAL.name())) {
						Inference.threatBasedSecurityGoalSimplification(ms, ms.req_phy_model, Integer.valueOf(object_choice));
					} else {
						NewCommandPanel.logger.severe("Layer selection error!");
					}
					
					JOptionPane.showMessageDialog(frmMuserControlPanel, "Identify critical security goals!");
				} catch (IOException e1) {
					e1.printStackTrace();
				} catch (ScriptException e1) {
					e1.printStackTrace();
				}
			}
		});
		btnStep_2.setBounds(22, 275, 95, 55);
		frmMuserControlPanel.getContentPane().add(btnStep_2);
		
		JButton btnStep_3 = new JButton("<html>Step 3:<br/>Operationalize</html>");
		btnStep_3.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String layer_choice = getCommand(layer);
				String object_choice = getCommand(object);
				// merge the alternative calculation method into the
				LinkedList<String> alternatives = null;
				try {
					if (layer_choice.equals(InfoEnum.Layer.BUSINESS.name())) {
						Inference.securityGoalOperationalization(ms.req_bus_model, Integer.valueOf(object_choice));
//						alternatives = Inference.securityAlternativeSolutions(ms.req_bus_model, Integer.valueOf(object_choice));
					} else if (layer_choice.equals(InfoEnum.Layer.APPLICATION.name())) {
						Inference.securityGoalOperationalization(ms.req_app_model, Integer.valueOf(object_choice));
//						alternatives = Inference.securityAlternativeSolutions(ms.req_app_model, Integer.valueOf(object_choice));
					} else if (layer_choice.equals(InfoEnum.Layer.PHYSICAL.name())) {
						Inference.securityGoalOperationalization(ms.req_phy_model, Integer.valueOf(object_choice));
//						alternatives = Inference.securityAlternativeSolutions(ms.req_phy_model, Integer.valueOf(object_choice));
					} else {
						NewCommandPanel.logger.severe("Layer selection error!");
					}
					
					// we will not do the alternative analysis here, but in the end of the analysis
//					String result = "";
//					alternative_list.removeAll();
//					for (String s : alternatives) {
//						result += s+"\n";
//					}
//					alternative_list.setText(result);
					
					JOptionPane.showMessageDialog(frmMuserControlPanel, "Finish Operationalization of critical security goals!");
					
				} catch (IOException e1) {
					e1.printStackTrace();
				} catch (ScriptException e1) {
					e1.printStackTrace();
				}
			}
		});
		btnStep_3.setBounds(22, 335, 95, 55);
		frmMuserControlPanel.getContentPane().add(btnStep_3);
		
		
		
		JButton btnStep_41 = new JButton("<html>Step 4.1: Check primary context</html>");
		btnStep_41.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String layer_choice = getCommand(layer);
				String object_choice = getCommand(object);
				LinkedList<String> results = null;
				try {
					if (layer_choice.equals(InfoEnum.Layer.BUSINESS.name())) {
						results = Inference.checkSecurityPatternContext(ms.req_bus_model, Integer.valueOf(object_choice), true);
					} else if (layer_choice.equals(InfoEnum.Layer.APPLICATION.name())) {
						results = Inference.checkSecurityPatternContext(ms.req_app_model, Integer.valueOf(object_choice), true);
					} else if (layer_choice.equals(InfoEnum.Layer.PHYSICAL.name())) {
						results = Inference.checkSecurityPatternContext(ms.req_phy_model, Integer.valueOf(object_choice), true);
					} else {
						NewCommandPanel.logger.severe("Layer selection error!");
					}
				} catch (NumberFormatException | IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}

				// popup dialog shows the check results
				String hold = "";
				String not_hold = "";
				String undecidable = "";
				String temp = "";
				for (String s : results) {
					if (s.startsWith("hold")) {
						// extract the name of the pattern
						temp = s.substring(5, s.indexOf(","));
						hold += temp + " pattern is applicable in current context.\n";
					} else if (s.startsWith("not_hold")) {
						// extract the name of the pattern
						temp = s.substring(9, s.indexOf(","));
						not_hold += temp + " pattern is not applicable in current context.\n";
					} else if (s.startsWith("undecidable")) {
						// extract the name of the pattern
						temp = s.substring(12, s.indexOf(","));
						undecidable += temp + " pattern is undecidable in current context.\n";
					}
				}
				if (!hold.equals("")) {
					JOptionPane.showMessageDialog(frmMuserControlPanel, hold);
				}
				if (!not_hold.equals("")) {
					JOptionPane.showMessageDialog(frmMuserControlPanel, not_hold);
				}
				if (!undecidable.equals("")) {
					JOptionPane.showMessageDialog(frmMuserControlPanel, undecidable);
				}
				// popup dialog for asking manual check
				String question = "";
				for (String s : results) {
					if (s.startsWith("question")) {
						temp = s.substring(9, s.indexOf("_"));
						int check_result = JOptionPane.showConfirmDialog(frmMuserControlPanel, InfoEnum.pattern_context_question.get(s), temp + " pattern primary context check", JOptionPane.YES_NO_OPTION);
						try {
							if (check_result == JOptionPane.YES_OPTION) {
								// add the context to "domain_context"
								Inference.writeFile(InfoEnum.current_directory+"/dlv/context/domain_context.dl", "\n"+InfoEnum.pattern_context_question.get(s + "y"), true);
							} else {
								// add the negation of the context to "domain_context"
								Inference.writeFile(InfoEnum.current_directory+"/dlv/context/domain_context.dl", "\n"+InfoEnum.pattern_context_question.get(s + "n"), true);
							}
						} catch (IOException e1) {
							e1.printStackTrace();
						}
					}
				}
			}
		});
		btnStep_41.setBounds(125, 275, 163, 55);
		btnStep_41.setMargin(new Insets(0, 0, 0, 0));
		frmMuserControlPanel.getContentPane().add(btnStep_41);
		
		JButton btnStep_42 = new JButton("<html>Step 4.2: Check secondary context</html>");
		btnStep_42.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String layer_choice = getCommand(layer);
				String object_choice = getCommand(object);
				LinkedList<String> results = null;
				try {
					if (layer_choice.equals(InfoEnum.Layer.BUSINESS.name())) {
						results = Inference.checkSecurityPatternContext(ms.req_bus_model, Integer.valueOf(object_choice), false);
					} else if (layer_choice.equals(InfoEnum.Layer.APPLICATION.name())) {
						results = Inference.checkSecurityPatternContext(ms.req_app_model, Integer.valueOf(object_choice), false);
					} else if (layer_choice.equals(InfoEnum.Layer.PHYSICAL.name())) {
						results = Inference.checkSecurityPatternContext(ms.req_phy_model, Integer.valueOf(object_choice), false);
					} else {
						NewCommandPanel.logger.severe("Layer selection error!");
					}
				} catch (NumberFormatException | IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}

				// popup dialog shows the check results
				String hold = "";
				String not_hold = "";
				String undecidable = "";
				String temp = "";
				String temp_context = "";
				for (String s : results) {
					if (s.startsWith("hold")) {
						// extract the name of the pattern and corresponding context
						temp = s.substring(5, s.indexOf(","));
						temp_context = s.substring(s.indexOf(",")+1, s.indexOf(")"));
						hold += temp + " pattern: context "+temp_context +" holds in current context.\n";
					} else if (s.startsWith("not_hold")) {
						// extract the name of the pattern and corresponding context
						temp = s.substring(9, s.indexOf(","));
						temp_context = s.substring(s.indexOf(",")+1, s.indexOf(")"));
						not_hold += temp + " pattern: context "+temp_context +" does not hold in current context.\n";
					} else if (s.startsWith("undecidable")) {
						// extract the name of the pattern
						temp = s.substring(12, s.indexOf(","));
						temp_context = s.substring(s.indexOf(",")+1, s.indexOf(")"));
						undecidable += temp + " pattern: context "+temp_context +" cannot be decided in current context.\n";
					}
				}
				if (!hold.equals("")) {
					JOptionPane.showMessageDialog(frmMuserControlPanel, hold);
				}
				if (!not_hold.equals("")) {
					JOptionPane.showMessageDialog(frmMuserControlPanel, not_hold);
				}
				if (!undecidable.equals("")) {
					JOptionPane.showMessageDialog(frmMuserControlPanel, undecidable);
				}
				// popup dialog for asking manual check
				for (String s : results) {
					if (s.startsWith("question")) {
						temp = s.substring(9, s.indexOf("_"));
						int check_result = JOptionPane.showConfirmDialog(frmMuserControlPanel, InfoEnum.pattern_context_question.get(s), 
								temp + " pattern secondary context check", JOptionPane.YES_NO_OPTION);
						try {
							if (check_result == JOptionPane.YES_OPTION) {
								// add the context to "domain_context"
								Inference.writeFile(InfoEnum.current_directory+"/dlv/context/domain_context.dl", "\n"+InfoEnum.pattern_context_question.get(s + "y"), true);
							} else {
								// add the negation of the context to "domain_context"
								Inference.writeFile(InfoEnum.current_directory+"/dlv/context/domain_context.dl", "\n"+InfoEnum.pattern_context_question.get(s + "n"), true);
							}
						} catch (IOException e1) {
							e1.printStackTrace();
						}
					}
				}
			}
		});
		btnStep_42.setBounds(125, 335, 163, 55);
		btnStep_42.setMargin(new Insets(0, 0, 0, 0));
		frmMuserControlPanel.getContentPane().add(btnStep_42);

		
		
	
		JButton btnStep_5 = new JButton("<html>Step 5: Transfer security concern</html>");
		btnStep_5.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String layer_choice = getCommand(layer);
				String object_choice = getCommand(object);
				try {
					if (layer_choice.equals(InfoEnum.Layer.BUSINESS.name())) {
						Inference.transferSecurityAcrossLayers(ms.req_bus_model, ms.req_app_model, Integer.valueOf(object_choice));
					} else if (layer_choice.equals(InfoEnum.Layer.APPLICATION.name())) {
						Inference.transferSecurityAcrossLayers(ms.req_app_model, ms.req_phy_model, Integer.valueOf(object_choice));
					} else if (layer_choice.equals(InfoEnum.Layer.PHYSICAL.name())) {
					} else {
						NewCommandPanel.logger.severe("Layer selection error!");
					}
				} catch (NumberFormatException | ScriptException | IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				JOptionPane.showMessageDialog(frmMuserControlPanel, "Transfer security concerns to the application layer!");
			}
		});
		btnStep_5.setBounds(300, 275, 161, 55);
		btnStep_5.setMargin(new Insets(0, 0, 0, 0));
		frmMuserControlPanel.getContentPane().add(btnStep_5);
				
		JButton btnStepGenerate = new JButton("<html>Step 6: Generate security solutions</html>");
		btnStepGenerate.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				// merge the alternative calculation method into the
				LinkedList<String> alternatives = null;
				try {
						alternatives = HSGMInference.generateHolisticSecuritySolutions(ms.hsgm);
						String result = "";
						alternative_list.removeAll();
						// for the large set of inference result, we only show the first 100 elements
						if(alternatives.size()>100){
							for(int i=0; i<100; i++){
								result += alternatives.get(i)+"\n";
							}
						}
						else{
							for (String s : alternatives) {
								result += s+"\n";
							}
						}
						result += "There are "+ alternatives.size() +" holistic security solutions in total.";
						alternative_list.setText(result);
					JOptionPane.showMessageDialog(frmMuserControlPanel, "Generate all holistic security solutions!");
				} catch (IOException e1) {
					e1.printStackTrace();
				} catch (ScriptException e1) {
					e1.printStackTrace();
				}
			}
		});
		btnStepGenerate.setBounds(301, 335, 163, 55);
		frmMuserControlPanel.getContentPane().add(btnStepGenerate);
		
		JButton btnShowThreatScenarios = new JButton("Show threat scenarios");
		btnShowThreatScenarios.setVisible(false);
		btnShowThreatScenarios.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String threat_scenarios = SupportingFunctions.getThreatScenarios(ms);
				if(threat_scenarios==null){
					JOptionPane.showMessageDialog(frmMuserControlPanel, "No elements have been selected");
				}
				else{
					alternative_list.setText("Threat scenarios of the selected security goal: \n" + threat_scenarios);
				}
			}
		});
		btnShowThreatScenarios.setBounds(398, 54, 66, 46);
		frmMuserControlPanel.getContentPane().add(btnShowThreatScenarios);
		
		JButton btnGenerateSupportElements = new JButton("Generate Support Elements");
		btnGenerateSupportElements.setVisible(false);
		btnGenerateSupportElements.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				// this analysis has to target a specific layer, otherwise we should pop-up an alert to let users select layer
				String current_layer = getCommand(layer);
				if (current_layer.equals(InfoEnum.Layer.BUSINESS.name())) {
					SupportingFunctions.generateCrossLayerSupport(ms.req_bus_model, ms.req_app_model, InfoEnum.SELECTED_MODELS);
				} else if (current_layer.equals(InfoEnum.Layer.APPLICATION.name())) {
					SupportingFunctions.generateCrossLayerSupport(ms.req_app_model, ms.req_phy_model, InfoEnum.SELECTED_MODELS);
				} else if (current_layer.equals(InfoEnum.Layer.APPLICATION.name())) {
					JOptionPane.showMessageDialog(frmMuserControlPanel, "The physical layer is not supported by any other layer.");
				} else {
					CommandPanel.logger.severe("The \"getCommand\" has problems.");
				}
				JOptionPane.showMessageDialog(frmMuserControlPanel, "Support link has been generated!");
			}
		});
		btnGenerateSupportElements.setBounds(402, 167, 61, 46);
		frmMuserControlPanel.getContentPane().add(btnGenerateSupportElements);
		
		JButton btnCritical = new JButton("Tag criticality");
		btnCritical.setVisible(false);
		btnCritical.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				boolean result = SupportingFunctions.criticalityTagging(ms);
				if(result){
					JOptionPane.showMessageDialog(frmMuserControlPanel, "Selected elements have been highlighted!");
				}
			}
			
		});
		btnCritical.setBounds(402, 113, 61, 46);
		frmMuserControlPanel.getContentPane().add(btnCritical);
		
		JButton btnGenerateAttacks = new JButton("<html>3) Generate alternatives</html>");
		btnGenerateAttacks.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				// merge the alternative calculation method into the
				LinkedList<String> alternatives = null;
				try {
						alternatives = AttackModelInference.generateAttackPlans(ms.attack_model);
						String result = "";
						alternative_list.removeAll();
						// for the large set of inference result, we only show the first 100 elements
						if(alternatives.size()>200){
							for(int i=0; i<200; i++){
								result += alternatives.get(i)+"\n";
							}
						}
						else{
							for (String s : alternatives) {
								result += s+"\n";
							}
						}
						result += "There are "+ alternatives.size() +" alternative attacks in total.";
						alternative_list.setText(result);
					JOptionPane.showMessageDialog(frmMuserControlPanel, "Generate all alternative attacks!");
				} catch (IOException e1) {
					e1.printStackTrace();
				} catch (ScriptException e1) {
					e1.printStackTrace();
				}
			}
		});
		btnGenerateAttacks.setBounds(339, 428, 125, 60);
		frmMuserControlPanel.getContentPane().add(btnGenerateAttacks);
		
		JButton btnOperationalize = new JButton("<html>1) Identify relevant patterns</html>");
		btnOperationalize.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String object_choice = getCommand(object);
				try {
					AttackModelInference.identifyRelevantPattern(ms.attack_model,Integer.valueOf(object_choice));
					JOptionPane.showMessageDialog(frmMuserControlPanel, "Identify relevant attack patterns!");
				} catch (NumberFormatException | IOException | ScriptException e1) {
					e1.printStackTrace();
				}
			}
		});
		btnOperationalize.setBounds(27, 428, 154, 60);
		frmMuserControlPanel.getContentPane().add(btnOperationalize);
		
		JButton btnApplicability = new JButton("<html>2) Check pattern applicability</html>");
		btnApplicability.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String object_choice = getCommand(object);
				try {
					LinkedList<String> questions = AttackModelInference.identifyApplicablePattern(ms.attack_model,Integer.valueOf(object_choice));
					String new_facts = "";
					for(String question: questions){
						String[] question_contents = question.split("\\$");
						int result = JOptionPane.showConfirmDialog(frmMuserControlPanel, question_contents[0]);
						// add new datalog predicates according to the reply
						if(result == JOptionPane.YES_OPTION){
							new_facts += question_contents[1]+".\n";
						} else if(result == JOptionPane.NO_OPTION){
							new_facts += "no_"+question_contents[1]+".\n";
						} else{
							
						}
					}
					// Incrementally write the new facts to file. The file will be manually deleted when necessary
					String attack_file = InfoEnum.current_directory + "/dlv/attack/checked_context.dl";
					Inference.writeFile(attack_file, new_facts, true);
					JOptionPane.showMessageDialog(frmMuserControlPanel, "Identify applicable attack patterns!");
				} catch (NumberFormatException | IOException | ScriptException e1) {
					e1.printStackTrace();
				}
			}
		});
		btnApplicability.setBounds(182, 428, 154, 60);
		frmMuserControlPanel.getContentPane().add(btnApplicability);
		
		JLabel lblSecurityRequirementsAnalysis = new JLabel("Security Requirements Analysis");
		lblSecurityRequirementsAnalysis.setBounds(22, 198, 211, 16);
		frmMuserControlPanel.getContentPane().add(lblSecurityRequirementsAnalysis);
		
		JLabel lblHolisticAttackAnalysis = new JLabel("Holistic Attack Analysis");
		lblHolisticAttackAnalysis.setBounds(26, 411, 192, 16);
		frmMuserControlPanel.getContentPane().add(lblHolisticAttackAnalysis);
		
		JSeparator separator_1 = new JSeparator();
		separator_1.setBounds(22, 180, 442, 10);
		frmMuserControlPanel.getContentPane().add(separator_1);
		
		JSeparator separator_2 = new JSeparator();
		separator_2.setBounds(22, 404, 442, 12);
		frmMuserControlPanel.getContentPane().add(separator_2);
		
		
		
		
//		JScrollPane scrollPane = new JScrollPane(textArea, 
//				   JScrollPane.VERTICAL_SCROLLBAR_ALWAYS, JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
//		frmMuserControlPanel.getContentPane().add(scrollPane);
		
		
	}
	
	/*
	 * Interpret commands according to current settings
	 */
	private String getCommand(JComboBox<String> input_box) {
		//import source type
		if (input_box.getName().equals("Import Source")) {
			if (input_box.getSelectedItem().equals("Selected elements")) {
				return InfoEnum.Commands.IMP_SELECTION.name();
			} else if (input_box.getSelectedItem().equals("From files")) {
				return InfoEnum.Commands.IMP_FILE.name();
			}
		}
		// model type commands
		else if (input_box.getName().equals("Model Type")) {
			if (input_box.getSelectedItem().equals("Requirements model")) {
				return InfoEnum.ModelCategory.REQUIREMENT.name();
			} else if (input_box.getSelectedItem().equals("Holistic security goal model")){
				return InfoEnum.ModelCategory.HOLISTIC_SECURITY_GOAL_MODEL.name();
			} else if (input_box.getSelectedItem().equals("Threat model")){
				return InfoEnum.ModelCategory.THREAT_MODEL.name();
			} else if (input_box.getSelectedItem().equals("Dataflow diagram")){
				return InfoEnum.ModelCategory.DATA_FLOW.name();
			} else if (input_box.getSelectedItem().equals("Resource schema")){
				return InfoEnum.ModelCategory.RESOURCE_SCHEMA.name();
			} else if (input_box.getSelectedItem().equals("Attack model")) {
				return InfoEnum.ModelCategory.ATTACK_MODEL.name();
			}
//			else if (input_box.getSelectedItem().equals("Trust model")) {
//				return InfoEnum.ModelCategory.ACTOR.name();
//			} 
			
		}
		// analysis type commands
		else if (input_box.getName().equals("Analysis Type")) {
			if (input_box.getSelectedItem().equals("Security Goal")) {
				return InfoEnum.RequirementElementType.SECURITY_GOAL.name();
			} else if (input_box.getSelectedItem().equals("Anti-Goal")) {
				return InfoEnum.RequirementElementType.ANTI_GOAL.name();
			}
		}
		// layers
		else if (input_box.getName().equals("Layer")) {
			if (input_box.getSelectedItem().equals("All")) {
				return InfoEnum.Layer.ALL.name();
			} else if (input_box.getSelectedItem().equals("Business")) {
				return InfoEnum.Layer.BUSINESS.name();
			} else if (input_box.getSelectedItem().equals("Application")) {
				return InfoEnum.Layer.APPLICATION.name();
			} else if (input_box.getSelectedItem().equals("Physical")) {
				return InfoEnum.Layer.PHYSICAL.name();
			}
		}
		// objects
		else if (input_box.getName().equals("Object")) {
			if (input_box.getSelectedItem().equals("All models")) {
				return String.valueOf(InfoEnum.ALL_MODELS);
			} else if (input_box.getSelectedItem().equals("Selected models")) {
				return String.valueOf(InfoEnum.SELECTED_MODELS);
			}
		}
		// refinement commands
		else if (input_box.getName().equals("Refinement Mode")) {
			if (input_box.getSelectedItem().equals("One-step")) {
				return InfoEnum.Commands.REF_ALL_ONE_STEP.name();
			} else if (input_box.getSelectedItem().equals("Exhaustive")) {
				return InfoEnum.Commands.REF_ALL_EXHAUSTIVE.name();
			}
		} else if (input_box.getName().equals("Refinement Dimension")) {
			if (input_box.getSelectedItem().equals("Attribute")) {
				return InfoEnum.RefinementDimension.SECURITY_PROPERTY.name();
			} else if (input_box.getSelectedItem().equals("Asset")) {
				return InfoEnum.RefinementDimension.ASSET.name();
			} else if (input_box.getSelectedItem().equals("Interval")) {
				return InfoEnum.RefinementDimension.INTERVAL.name();
			} else if (input_box.getSelectedItem().equals("Threat(anti)")) {
				return InfoEnum.RefinementDimension.THREAT.name();
			} else if (input_box.getSelectedItem().equals("Asset(anti)")) {
				return InfoEnum.RefinementDimension.ASSET.name();
			} else if (input_box.getSelectedItem().equals("Target(anti)")) {
				return InfoEnum.RefinementDimension.TARGET.name();
			} else if (input_box.getSelectedItem().equals("Protection(anti)")) {
				return InfoEnum.RefinementDimension.PROTECTION.name();
			}

		} else if (input_box.getName().equals("Visualization")) {
			if (input_box.getSelectedItem().equals("OmniGraffle")) {
				return String.valueOf(InfoEnum.CANVAS);
			} else if (input_box.getSelectedItem().equals("Graphviz")) {
				return String.valueOf(InfoEnum.GRAPHVIZ);
			}
		} else {
			logger.warning("Command error!");
		}
		return null;
	}
}
