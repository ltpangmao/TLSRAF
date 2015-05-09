package it.unitn.tlsraf.otherfunc;

import it.unitn.tlsraf.ds.InfoEnum;
import it.unitn.tlsraf.func.AppleScript;
import it.unitn.tlsraf.func.CAPECModelGeneration;

import java.awt.BorderLayout;
import java.awt.EventQueue;

import javax.script.ScriptException;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JTextField;
import javax.swing.JButton;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

public class DraftGenerator extends JFrame {

	private JPanel contentPane;
	private JTextField addressText;
	private JTextField canvasText;
	private JTextField layerText;
	private JTextField txtPatternid;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					DraftGenerator frame = new DraftGenerator();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the frame.
	 */
	public DraftGenerator() {
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 450, 399);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);

		JLabel lblChooseTheDraft = new JLabel("Choose the draft file");
		lblChooseTheDraft.setBounds(38, 26, 175, 16);
		contentPane.add(lblChooseTheDraft);

		addressText = new JTextField();
		addressText.setBounds(38, 62, 218, 28);
		contentPane.add(addressText);
		addressText.setColumns(10);

		JButton btnChoose = new JButton("Choose");
		btnChoose.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser chooser = new JFileChooser();
				FileNameExtensionFilter filter1 = new FileNameExtensionFilter("Text file","txt");
//				FileNameExtensionFilter filter2 = new FileNameExtensionFilter("Jpeg file","jpg");
				chooser.addChoosableFileFilter(filter1);
//				chooser.addChoosableFileFilter(filter2);
				chooser.setFileFilter(filter1);
				int returnVal = chooser.showOpenDialog(getParent());
				if (returnVal == JFileChooser.APPROVE_OPTION) {
					addressText.setText(chooser.getSelectedFile().getPath());
				}
			}
		});
		btnChoose.setBounds(291, 63, 117, 29);
		contentPane.add(btnChoose);
		

		JButton btnGenerate = new JButton("Generate");
		btnGenerate.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String file = addressText.getText();
				
				//calculate position
				int x=0,y=0;
				int length = 3000;
				int x_distance = 200;
				int y_distance = 150;
				String position = "{"+x+","+y+"}";
						
				
				BufferedReader input;
				try {
					input = new BufferedReader(new FileReader(file));
				} catch (FileNotFoundException e1) {
					JOptionPane.showMessageDialog( getParent(), "File is not found!");
					return;
				}
				
				String line="";
				String tag="";
				String shape="";
				//Assume they are input correctly. Default value is assigned.
				String canvas = canvasText.getText();
				String layer = layerText.getText();
				
				try {
					while ((line = input.readLine()) != null) {
						if(line.startsWith("%")){
							//type declaration
							tag = line.substring(1);
							continue;
						}
						else if(line.equals("")){
							//skip empty lines
							continue;
						}
						else{
							//draw elements
							shape = InfoEnum.reverse_req_elem_type_map.get(tag);
							AppleScript.drawArbitraryRequirementElement(canvas, layer, shape, InfoEnum.NORMAL_SIZE, position, "0", line, "0", "1");
							//adjust distance
							if(x<length){
								x+=x_distance;
							}
							else{
								x=0;
								y+=y_distance;
							}
							position = "{"+x+","+y+"}";
						}
					}
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				JOptionPane.showMessageDialog( getParent(), "Successfully generate graphs!");
			}
		});
		btnGenerate.setBounds(291, 130, 117, 29);
		contentPane.add(btnGenerate);

		JLabel lblCanvas = new JLabel("Canvas");
		lblCanvas.setBounds(24, 135, 61, 16);
		contentPane.add(lblCanvas);

		canvasText = new JTextField();
		canvasText.setText("Test");
		canvasText.setBounds(79, 130, 77, 28);
		contentPane.add(canvasText);
		canvasText.setColumns(10);

		JLabel lblLayer = new JLabel("Layer");
		lblLayer.setBounds(24, 189, 61, 16);
		contentPane.add(lblLayer);

		layerText = new JTextField();
		layerText.setText("none");
		layerText.setBounds(79, 183, 134, 28);
		contentPane.add(layerText);
		layerText.setColumns(10);
		
		JLabel lblTargetAttackPattern = new JLabel("Target Attack Pattern");
		lblTargetAttackPattern.setBounds(38, 294, 156, 16);
		contentPane.add(lblTargetAttackPattern);
		
		txtPatternid = new JTextField();
		txtPatternid.setBounds(38, 322, 134, 28);
		contentPane.add(txtPatternid);
		txtPatternid.setColumns(10);
		
		JButton btnGenerateTree = new JButton("Generate tree");
		btnGenerateTree.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				CAPECModelGeneration model = new CAPECModelGeneration();
				model.generatePatternHierarchy(txtPatternid.getText());
				JOptionPane.showMessageDialog( getParent(), "Successfully generate graphs!");
			}
		});
		btnGenerateTree.setBounds(218, 323, 117, 29);
		contentPane.add(btnGenerateTree);
	}
}
