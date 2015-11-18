package it.unitn.tlsraf.otherfunc;

import it.unitn.tlsraf.ds.InfoEnum;
import it.unitn.tlsraf.func.AppleScript;
import it.unitn.tlsraf.func.CAPECModelGeneration;
import it.unitn.tlsraf.func.Inference;

import java.awt.EventQueue;

import javax.script.ScriptException;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class AuxiliaryPanel extends JFrame {

	private JPanel contentPane;
	private JTextField canvasText;
	private JTextField layerText;
	private JTextField tfElementID;
	private JTextField tfShowElementID;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					AuxiliaryPanel frame = new AuxiliaryPanel();
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
	public AuxiliaryPanel() {
		setTitle("Auxiliary Function Panel");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 450, 399);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);
		

		JButton btnGenerate = new JButton("Set layer");
		btnGenerate.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				
				String canvas = canvasText.getText();
				String layer = layerText.getText();
				
				// change the layer of the selected element
				ArrayList<Long> selected_elements = null;
				try {
					selected_elements = AppleScript.getSelectedGraph();
				} catch (ScriptException e1) {
					e1.printStackTrace();
				}
				for (Long target_id : selected_elements) {
					try {
//						AppleScript.changeAttribute("Resulting model", "none", target_id.toString(), "-1", "none", "PHYSICAL");
						AppleScript.changeAttribute(canvas, "none", target_id.toString(), "-1", "none", layer);
					} catch (ScriptException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				}
				JOptionPane.showMessageDialog(null, "Finish setting layers!");
			}
		});
		btnGenerate.setBounds(6, 145, 117, 29);
		contentPane.add(btnGenerate);

		JLabel lblCanvas = new JLabel("Canvas of selection");
		lblCanvas.setBounds(6, 38, 128, 16);
		contentPane.add(lblCanvas);

		canvasText = new JTextField();
		canvasText.setText("Model");
		canvasText.setBounds(146, 32, 128, 28);
		contentPane.add(canvasText);
		canvasText.setColumns(10);

		JLabel lblLayer = new JLabel("Intended layer");
		lblLayer.setBounds(135, 150, 116, 16);
		contentPane.add(lblLayer);

		layerText = new JTextField();
		layerText.setBounds(251, 144, 128, 28);
		contentPane.add(layerText);
		layerText.setColumns(10);
		
		JLabel lblOperations = new JLabel("Set element layer");
		lblOperations.setBounds(6, 117, 128, 16);
		contentPane.add(lblOperations);
		
		JLabel lblFindElementBy = new JLabel("Find Element by ID");
		lblFindElementBy.setBounds(6, 186, 128, 16);
		contentPane.add(lblFindElementBy);
		
		JLabel lblElementId = new JLabel("Element ID");
		lblElementId.setBounds(136, 219, 87, 16);
		contentPane.add(lblElementId);
		
		tfElementID = new JTextField();
		tfElementID.setBounds(251, 213, 128, 28);
		contentPane.add(tfElementID);
		tfElementID.setColumns(10);
		
		JButton btnFind = new JButton("Find");
		btnFind.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String canvas = canvasText.getText();
				String ID = tfElementID.getText();
				try {
					AppleScript.changeAttribute(canvas, "none", ID, "5", "none", "none");
				} catch (ScriptException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				JOptionPane.showMessageDialog(null, "Finish finding elements!");
			}
		});
		btnFind.setBounds(6, 214, 117, 29);
		contentPane.add(btnFind);
		
		JLabel lblfirstSpecifyTarget = new JLabel("*First specify target canvas");
		lblfirstSpecifyTarget.setBounds(6, 6, 217, 16);
		contentPane.add(lblfirstSpecifyTarget);
		
		JButton btnShowId = new JButton("Show ID");
		btnShowId.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try {
					ArrayList<Long> result = AppleScript.getSelectedGraph();
					//here, we only show the first one to accommodate our current needs, surely this can be further revised later
					tfShowElementID.setText(result.get(0).toString());
				} catch (ScriptException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				JOptionPane.showMessageDialog(null, "Finish showing elements!");
			}
		});
		btnShowId.setBounds(6, 286, 117, 29);
		contentPane.add(btnShowId);
		
		JLabel lblFindElementId = new JLabel("Show Element's ID");
		lblFindElementId.setBounds(6, 258, 117, 16);
		contentPane.add(lblFindElementId);
		
		JLabel lblElementId_1 = new JLabel("Element ID");
		lblElementId_1.setBounds(135, 291, 76, 16);
		contentPane.add(lblElementId_1);
		
		tfShowElementID = new JTextField();
		tfShowElementID.setBounds(245, 285, 134, 28);
		contentPane.add(tfShowElementID);
		tfShowElementID.setColumns(10);
	}
}
