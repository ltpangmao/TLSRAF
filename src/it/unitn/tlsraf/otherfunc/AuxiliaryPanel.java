package it.unitn.tlsraf.otherfunc;

import it.unitn.tlsraf.ds.InfoEnum;
import it.unitn.tlsraf.func.AppleScript;
import it.unitn.tlsraf.func.CAPECModelGeneration;

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

public class AuxiliaryPanel extends JFrame {

	private JPanel contentPane;
	private JTextField canvasText;
	private JTextField layerText;

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
		btnGenerate.setBounds(6, 38, 117, 29);
		contentPane.add(btnGenerate);

		JLabel lblCanvas = new JLabel("Canvas of selection");
		lblCanvas.setBounds(123, 38, 128, 16);
		contentPane.add(lblCanvas);

		canvasText = new JTextField();
		canvasText.setBounds(251, 32, 128, 28);
		contentPane.add(canvasText);
		canvasText.setColumns(10);

		JLabel lblLayer = new JLabel("Intended layer");
		lblLayer.setBounds(123, 63, 116, 16);
		contentPane.add(lblLayer);

		layerText = new JTextField();
		layerText.setBounds(251, 57, 128, 28);
		contentPane.add(layerText);
		layerText.setColumns(10);
		
		JLabel lblOperations = new JLabel("Operations");
		lblOperations.setBounds(19, 10, 92, 16);
		contentPane.add(lblOperations);
	}
}
