package it.unitn.tlsraf.func;

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
import java.io.IOException;

import javax.swing.JSeparator;
import javax.swing.border.Border;

import java.awt.Font;

import javax.swing.JTextArea;

import java.awt.Color;

import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.SwingConstants;

public class CommandPanel {
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
					// first initalize the global logger
					CommandPanel.setup();
					// initalize the window
					CommandPanel window = new CommandPanel();
					window.frmMuserControlPanel.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public CommandPanel() {
		initialize();
		ms = new ModelSet();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frmMuserControlPanel = new JFrame();
		frmMuserControlPanel.setTitle("MUSER Control Panel");
		frmMuserControlPanel.setBounds(100, 100, 437, 668);
		frmMuserControlPanel.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frmMuserControlPanel.getContentPane().setLayout(null);
		
		final JComboBox<String> importSource = new JComboBox<String>();
		importSource.setName("Import Source");
		importSource.addItem("Selected elements");
		importSource.addItem("From files");
		importSource.setBounds(27, 56, 169, 27);
		frmMuserControlPanel.getContentPane().add(importSource);
		
		JLabel lblImportSource = new JLabel("Import Source");
		lblImportSource.setBounds(29, 36, 95, 16);
		frmMuserControlPanel.getContentPane().add(lblImportSource);
		
		final JComboBox<String> modelType = new JComboBox<String>();
		modelType.setName("Model Type");
		modelType.addItem("Requirements model");
		modelType.addItem("Trust model");
		modelType.setBounds(198, 56, 169, 27);
		frmMuserControlPanel.getContentPane().add(modelType);
		
		JLabel lblModelType = new JLabel("Model Type");
		lblModelType.setBounds(205, 36, 95, 16);
		frmMuserControlPanel.getContentPane().add(lblModelType);
		
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
						// TODO: customize the size of the dialog
						JOptionPane.showMessageDialog(frmMuserControlPanel, "Finish importing requirement models!");
					} else if (model.equals(InfoEnum.ModelCategory.ACTOR.name())) {
						Inference.importActorModel(ms.actor_model, canvas);
						// TODO: customize the size of the dialog
						JOptionPane.showMessageDialog(frmMuserControlPanel, "Finish importing trust models!");
					} else {
						logger.warning("Command error!");
					}
				} catch (IOException e1) {
					e1.printStackTrace();
				} catch (ScriptException e1) {
					e1.printStackTrace();
				}
			}
		});
		btnImport.setBounds(27, 84, 86, 39);
		frmMuserControlPanel.getContentPane().add(btnImport);
		
		JButton btnDelete = new JButton("Delete");
		btnDelete.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				ms.req_bus_model = new RequirementGraph(ms.req_bus_model.getType(), ms.req_bus_model.getLayer());
				ms.req_app_model = new RequirementGraph(ms.req_app_model.getType(), ms.req_app_model.getLayer());
				ms.req_phy_model = new RequirementGraph(ms.req_phy_model.getType(), ms.req_phy_model.getLayer());
				JOptionPane.showMessageDialog(frmMuserControlPanel, "Delete all models!");
			}
		});
		btnDelete.setBounds(134, 84, 86, 39);
		frmMuserControlPanel.getContentPane().add(btnDelete);
		
		JLabel lblAnalysisType = new JLabel("Analysis Type");
		lblAnalysisType.setBounds(27, 177, 97, 16);
		frmMuserControlPanel.getContentPane().add(lblAnalysisType);
		
		final JComboBox<String> analysis_type = new JComboBox<String>();
		analysis_type.setName("Analysis Type");
		analysis_type.addItem("Security Goal");
		analysis_type.addItem("Anti-Goal");
		analysis_type.setBounds(20, 194, 115, 27);
		frmMuserControlPanel.getContentPane().add(analysis_type);
		

		
		JLabel lblLayer = new JLabel("Layer");
		lblLayer.setBounds(157, 177, 61, 16);
		frmMuserControlPanel.getContentPane().add(lblLayer);
		
		final JComboBox<String> layer = new JComboBox<String>();
		layer.setName("Layer");
		layer.addItem("All");
		layer.addItem("Business");
		layer.addItem("Application");
		layer.addItem("Physical");
		layer.setBounds(157, 194, 112, 27);
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
					CommandPanel.logger.severe("Layer selection error!");
				}
			}
		});
		btnPrint.setBounds(242, 84, 86, 39);
		frmMuserControlPanel.getContentPane().add(btnPrint);
		
		
		
		final JComboBox<String> object = new JComboBox<String>();
		object.setName("Object");
		object.addItem("All models");
		object.addItem("Selected models");
		object.setBounds(294, 194, 117, 27);
		frmMuserControlPanel.getContentPane().add(object);
		
		JLabel lblObject = new JLabel("Object");
		lblObject.setBounds(294, 177, 61, 16);
		frmMuserControlPanel.getContentPane().add(lblObject);
		
		final JComboBox<String> refinementMode = new JComboBox<String>();
		refinementMode.setName("Refinement Mode");
		refinementMode.addItem("One-step");
		refinementMode.addItem("Exhaustive");
		refinementMode.setBounds(134, 270, 125, 27);
		frmMuserControlPanel.getContentPane().add(refinementMode);
		
		JLabel lblRefinementMode = new JLabel("Refinement Mode");
		lblRefinementMode.setBounds(132, 254, 125, 16);
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
		refinementDimension.setBounds(271, 250, 140, 27);
		frmMuserControlPanel.getContentPane().add(refinementDimension);
		
		JLabel lblRefinementDimension = new JLabel("Refinement Dimension");
		lblRefinementDimension.setBounds(269, 233, 154, 16);
		frmMuserControlPanel.getContentPane().add(lblRefinementDimension);
		
		JSeparator separator = new JSeparator();
		separator.setBounds(27, 135, 384, 12);
		frmMuserControlPanel.getContentPane().add(separator);
		
		final JComboBox<String> visualization = new JComboBox<String>();
		visualization.setName("Visualization");
		visualization.addItem("OmniGraffle");
		visualization.addItem("Graphviz");
		visualization.setBounds(269, 299, 142, 27);
		frmMuserControlPanel.getContentPane().add(visualization);
		
		JLabel lblVisualization = new JLabel("Visualization");
		lblVisualization.setBounds(269, 281, 95, 16);
		frmMuserControlPanel.getContentPane().add(lblVisualization);
		
		JLabel lblImportModel = new JLabel("Import Model");
		lblImportModel.setFont(new Font("Tahoma", Font.PLAIN, 14));
		lblImportModel.setBounds(27, 6, 97, 16);
		frmMuserControlPanel.getContentPane().add(lblImportModel);
		
		JLabel lblAnalyzeModel = new JLabel("Analyze Model");
		lblAnalyzeModel.setFont(new Font("Tahoma", Font.PLAIN, 14));
		lblAnalyzeModel.setBounds(27, 149, 125, 16);
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
							if (layer_choice.equals(InfoEnum.Layer.ALL.name())) {
								Inference.securityGoalRefine(ms.req_bus_model, dimension_choice, Integer.valueOf(object_choice));
								Inference.securityGoalRefine(ms.req_app_model, dimension_choice, Integer.valueOf(object_choice));
								Inference.securityGoalRefine(ms.req_phy_model, dimension_choice, Integer.valueOf(object_choice));
							} else if (layer_choice.equals(InfoEnum.Layer.BUSINESS.name())) {
								Inference.securityGoalRefine(ms.req_bus_model, dimension_choice, Integer.valueOf(object_choice));
							} else if (layer_choice.equals(InfoEnum.Layer.APPLICATION.name())) {
								Inference.securityGoalRefine(ms.req_app_model, dimension_choice, Integer.valueOf(object_choice));
							} else if (layer_choice.equals(InfoEnum.Layer.PHYSICAL.name())) {
								Inference.securityGoalRefine(ms.req_phy_model, dimension_choice, Integer.valueOf(object_choice));
							} else {
								CommandPanel.logger.severe("Layer selection error!");
							}
							JOptionPane.showMessageDialog(frmMuserControlPanel, "Finish one-step refinement!");
						} else if (mode_choice.equals(InfoEnum.Commands.REF_ALL_EXHAUSTIVE.name())) {
							if (layer_choice.equals(InfoEnum.Layer.ALL.name())) {
								Inference.exhaustiveSecurityGoalRefineAnalysis(ms, ms.req_bus_model, ms.actor_model,
										Integer.valueOf(visualization_choice), Integer.valueOf(object_choice));
								Inference.exhaustiveSecurityGoalRefineAnalysis(ms, ms.req_app_model, ms.actor_model,
										Integer.valueOf(visualization_choice), Integer.valueOf(object_choice));
								Inference.exhaustiveSecurityGoalRefineAnalysis(ms, ms.req_phy_model, ms.actor_model,
										Integer.valueOf(visualization_choice), Integer.valueOf(object_choice));
							} else if (layer_choice.equals(InfoEnum.Layer.BUSINESS.name())) {
								Inference.exhaustiveSecurityGoalRefineAnalysis(ms, ms.req_bus_model, ms.actor_model,
										Integer.valueOf(visualization_choice), Integer.valueOf(object_choice));
							} else if (layer_choice.equals(InfoEnum.Layer.APPLICATION.name())) {
								Inference.exhaustiveSecurityGoalRefineAnalysis(ms, ms.req_app_model, ms.actor_model,
										Integer.valueOf(visualization_choice), Integer.valueOf(object_choice));
							} else if (layer_choice.equals(InfoEnum.Layer.PHYSICAL.name())) {
								Inference.exhaustiveSecurityGoalRefineAnalysis(ms, ms.req_phy_model, ms.actor_model,
										Integer.valueOf(visualization_choice), Integer.valueOf(object_choice));
							} else {
								CommandPanel.logger.severe("Layer selection error!");
							}
							JOptionPane.showMessageDialog(frmMuserControlPanel, "Finish exhaustive refinement!");
						}
					}
					else if(analysis_choice.equals(InfoEnum.RequirementElementType.ANTI_GOAL.name())){
						if (mode_choice.equals(InfoEnum.Commands.REF_ALL_ONE_STEP.name())) {
							if (layer_choice.equals(InfoEnum.Layer.ALL.name())) {
								AntiGoalInference.antiGoalRefine(ms.req_bus_model, dimension_choice, Integer.valueOf(object_choice));
								AntiGoalInference.antiGoalRefine(ms.req_app_model, dimension_choice, Integer.valueOf(object_choice));
								AntiGoalInference.antiGoalRefine(ms.req_phy_model, dimension_choice, Integer.valueOf(object_choice));
							} else if (layer_choice.equals(InfoEnum.Layer.BUSINESS.name())) {
								AntiGoalInference.antiGoalRefine(ms.req_bus_model, dimension_choice, Integer.valueOf(object_choice));
							} else if (layer_choice.equals(InfoEnum.Layer.APPLICATION.name())) {
								AntiGoalInference.antiGoalRefine(ms.req_app_model, dimension_choice, Integer.valueOf(object_choice));
							} else if (layer_choice.equals(InfoEnum.Layer.PHYSICAL.name())) {
								AntiGoalInference.antiGoalRefine(ms.req_phy_model, dimension_choice, Integer.valueOf(object_choice));
							} else {
								CommandPanel.logger.severe("Layer selection error!");
							}
							JOptionPane.showMessageDialog(frmMuserControlPanel, "Finish one-step refinement!");
						} else if (mode_choice.equals(InfoEnum.Commands.REF_ALL_EXHAUSTIVE.name())) {
							if (layer_choice.equals(InfoEnum.Layer.ALL.name())) {
								AntiGoalInference.exhaustiveAntiGoalRefineAnalysis(ms.req_bus_model, ms.actor_model,
										Integer.valueOf(visualization_choice), Integer.valueOf(object_choice));
								AntiGoalInference.exhaustiveAntiGoalRefineAnalysis(ms.req_app_model, ms.actor_model,
										Integer.valueOf(visualization_choice), Integer.valueOf(object_choice));
								AntiGoalInference.exhaustiveAntiGoalRefineAnalysis(ms.req_phy_model, ms.actor_model,
										Integer.valueOf(visualization_choice), Integer.valueOf(object_choice));
							} else if (layer_choice.equals(InfoEnum.Layer.BUSINESS.name())) {
								AntiGoalInference.exhaustiveAntiGoalRefineAnalysis(ms.req_bus_model, ms.actor_model,
										Integer.valueOf(visualization_choice), Integer.valueOf(object_choice));
							} else if (layer_choice.equals(InfoEnum.Layer.APPLICATION.name())) {
								AntiGoalInference.exhaustiveAntiGoalRefineAnalysis(ms.req_app_model, ms.actor_model,
										Integer.valueOf(visualization_choice), Integer.valueOf(object_choice));
							} else if (layer_choice.equals(InfoEnum.Layer.PHYSICAL.name())) {
								AntiGoalInference.exhaustiveAntiGoalRefineAnalysis(ms.req_phy_model, ms.actor_model,
										Integer.valueOf(visualization_choice), Integer.valueOf(object_choice));
							} else {
								CommandPanel.logger.severe("Layer selection error!");
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
		btnStep_1.setBounds(10, 246, 100, 55);
		frmMuserControlPanel.getContentPane().add(btnStep_1);
		
		JButton btnStep_2 = new JButton("<html>Step 2:<br/>Simplify</html>");
		btnStep_2.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String layer_choice = getCommand(layer);
				String object_choice = getCommand(object);
				try {
					if (layer_choice.equals(InfoEnum.Layer.ALL.name())) {
						Inference.securityGoalSimplification(ms.req_bus_model, ms.actor_model, Integer.valueOf(object_choice));
						Inference.securityGoalSimplification(ms.req_app_model, ms.actor_model, Integer.valueOf(object_choice));
						Inference.securityGoalSimplification(ms.req_phy_model, ms.actor_model, Integer.valueOf(object_choice));
					} else if (layer_choice.equals(InfoEnum.Layer.BUSINESS.name())) {
						Inference.securityGoalSimplification(ms.req_bus_model, ms.actor_model, Integer.valueOf(object_choice));
					} else if (layer_choice.equals(InfoEnum.Layer.APPLICATION.name())) {
						Inference.securityGoalSimplification(ms.req_app_model, ms.actor_model, Integer.valueOf(object_choice));
					} else if (layer_choice.equals(InfoEnum.Layer.PHYSICAL.name())) {
						Inference.securityGoalSimplification(ms.req_phy_model, ms.actor_model, Integer.valueOf(object_choice));
					} else {
						CommandPanel.logger.severe("Layer selection error!");
					}
					JOptionPane.showMessageDialog(frmMuserControlPanel, "Identify critical security goals!");
				} catch (IOException e1) {
					e1.printStackTrace();
				} catch (ScriptException e1) {
					e1.printStackTrace();
				}
			}
		});
		btnStep_2.setBounds(10, 319, 100, 55);
		frmMuserControlPanel.getContentPane().add(btnStep_2);

		//add scroll to text 
		final JTextArea alternative_list = new JTextArea();
		alternative_list.setEditable(false);
//		scrollPane.setColumnHeaderView(alternative_list);
		
		final JScrollPane scrollPane = new JScrollPane(alternative_list, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
				JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		scrollPane.setBounds(160, 339, 268, 286);
		frmMuserControlPanel.getContentPane().add(scrollPane);
		
		JButton btnStep_3 = new JButton("<html>Step 3:<br/>Operationalize</html>");
		btnStep_3.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String layer_choice = getCommand(layer);
				String object_choice = getCommand(object);
				// merge the alternative calculation method into the
				LinkedList<String> alternatives = null;
				try {
					if (layer_choice.equals(InfoEnum.Layer.ALL.name())) {
						Inference.securityGoalOperationalization(ms.req_bus_model, Integer.valueOf(object_choice));
						Inference.securityGoalOperationalization(ms.req_app_model, Integer.valueOf(object_choice));
						Inference.securityGoalOperationalization(ms.req_phy_model, Integer.valueOf(object_choice));
					} else if (layer_choice.equals(InfoEnum.Layer.BUSINESS.name())) {
						Inference.securityGoalOperationalization(ms.req_bus_model, Integer.valueOf(object_choice));
						alternatives = Inference.securityAlternativeSolutions(ms.req_bus_model, Integer.valueOf(object_choice));
					} else if (layer_choice.equals(InfoEnum.Layer.APPLICATION.name())) {
						Inference.securityGoalOperationalization(ms.req_app_model, Integer.valueOf(object_choice));
						alternatives = Inference.securityAlternativeSolutions(ms.req_app_model, Integer.valueOf(object_choice));
					} else if (layer_choice.equals(InfoEnum.Layer.PHYSICAL.name())) {
						Inference.securityGoalOperationalization(ms.req_phy_model, Integer.valueOf(object_choice));
						alternatives = Inference.securityAlternativeSolutions(ms.req_phy_model, Integer.valueOf(object_choice));
					} else {
						CommandPanel.logger.severe("Layer selection error!");
					}
					
					String result = "";
					alternative_list.removeAll();
					for (String s : alternatives) {
						result += s+"\n";
					}
					alternative_list.setText(result);
					
					JOptionPane.showMessageDialog(frmMuserControlPanel, "Finish Operationalization of critical security goals!");
					
				} catch (IOException e1) {
					e1.printStackTrace();
				} catch (ScriptException e1) {
					e1.printStackTrace();
				}
			}
		});
		btnStep_3.setBounds(10, 382, 125, 55);
		frmMuserControlPanel.getContentPane().add(btnStep_3);
		
		
		
		JButton btnStep_41 = new JButton("<html>Step 4.1: Check primary context</html>");
		btnStep_41.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String layer_choice = getCommand(layer);
				String object_choice = getCommand(object);
				LinkedList<String> results = null;
				try {
					if (layer_choice.equals(InfoEnum.Layer.ALL.name())) {
						// tackle each layer separately by default
					} else if (layer_choice.equals(InfoEnum.Layer.BUSINESS.name())) {
						results = Inference.checkSecurityPatternContext(ms.req_bus_model, Integer.valueOf(object_choice), true);
					} else if (layer_choice.equals(InfoEnum.Layer.APPLICATION.name())) {
						results = Inference.checkSecurityPatternContext(ms.req_app_model, Integer.valueOf(object_choice), true);
					} else if (layer_choice.equals(InfoEnum.Layer.PHYSICAL.name())) {
						results = Inference.checkSecurityPatternContext(ms.req_phy_model, Integer.valueOf(object_choice), true);
					} else {
						CommandPanel.logger.severe("Layer selection error!");
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
		btnStep_41.setBounds(10, 445, 145, 55);
		btnStep_41.setMargin(new Insets(0, 0, 0, 0));
		frmMuserControlPanel.getContentPane().add(btnStep_41);
		
		JButton btnStep_42 = new JButton("<html>Step 4.2: Check secondary cont..</html>");
		btnStep_42.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String layer_choice = getCommand(layer);
				String object_choice = getCommand(object);
				LinkedList<String> results = null;
				try {
					if (layer_choice.equals(InfoEnum.Layer.ALL.name())) {
						// tackle each layer separately by default
					} else if (layer_choice.equals(InfoEnum.Layer.BUSINESS.name())) {
						results = Inference.checkSecurityPatternContext(ms.req_bus_model, Integer.valueOf(object_choice), false);
					} else if (layer_choice.equals(InfoEnum.Layer.APPLICATION.name())) {
						results = Inference.checkSecurityPatternContext(ms.req_app_model, Integer.valueOf(object_choice), false);
					} else if (layer_choice.equals(InfoEnum.Layer.PHYSICAL.name())) {
						results = Inference.checkSecurityPatternContext(ms.req_phy_model, Integer.valueOf(object_choice), false);
					} else {
						CommandPanel.logger.severe("Layer selection error!");
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
		btnStep_42.setBounds(10, 515, 145, 55);
		btnStep_42.setMargin(new Insets(0, 0, 0, 0));
		frmMuserControlPanel.getContentPane().add(btnStep_42);
	
		JButton btnStep_5 = new JButton("<html>Step 5: Transfer security concern</html>");
		btnStep_5.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String layer_choice = getCommand(layer);
				String object_choice = getCommand(object);
				LinkedList<String> alternatives = null;
				try {
					if (layer_choice.equals(InfoEnum.Layer.ALL.name())) {
						Inference.transferSecurityAcrossLayers(ms.req_bus_model, ms.req_app_model, Integer.valueOf(object_choice));
						Inference.transferSecurityAcrossLayers(ms.req_app_model, ms.req_phy_model, Integer.valueOf(object_choice));
					} else if (layer_choice.equals(InfoEnum.Layer.BUSINESS.name())) {
						Inference.transferSecurityAcrossLayers(ms.req_bus_model, ms.req_app_model, Integer.valueOf(object_choice));
					} else if (layer_choice.equals(InfoEnum.Layer.APPLICATION.name())) {
						Inference.transferSecurityAcrossLayers(ms.req_app_model, ms.req_phy_model, Integer.valueOf(object_choice));
					} else if (layer_choice.equals(InfoEnum.Layer.PHYSICAL.name())) {
					} else {
						CommandPanel.logger.severe("Layer selection error!");
					}
				} catch (NumberFormatException | ScriptException | IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				JOptionPane.showMessageDialog(frmMuserControlPanel, "Transfer security concerns to the application layer!");
			}
		});
		btnStep_5.setBounds(10, 575, 145, 55);
		btnStep_5.setMargin(new Insets(0, 0, 0, 0));
		frmMuserControlPanel.getContentPane().add(btnStep_5);
		
		
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
			} else if (input_box.getSelectedItem().equals("Trust model")) {
				return InfoEnum.ModelCategory.ACTOR.name();
			}
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
