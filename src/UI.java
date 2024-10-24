import javax.swing.*;
import java.awt.*; //BorderLayout
public class UI{
    public static void main(String args[ ]){
// Crearea ferestrei principale Frame
        JFrame frame = new JFrame("Chat Frame");
        frame.setSize(400,400);
// Crearea unei bare de meniu MenuBar si adaugare componente
        JMenuBar mb = new JMenuBar( );
        JMenu m1 = new JMenu("FILE");
        JMenu m2 = new JMenu("Help");
        mb.add(m1);
        mb.add(m2);
        JMenuItem m11 = new JMenuItem("Open");
        JMenuItem m22 =new JMenuItem("Save as");
        m1.add(m11);
        m1.add(m22);
        JPanel panel = new JPanel( );
        JLabel label = new JLabel("Enter Text");
        JTextField tf = new JTextField(10);// accepts upto 10 characters
        JButton send = new JButton("Send");
        JButton reset = new JButton("Reset");
        panel.add(label); //Componente adaugate folosind implicit FlowLayout la JPanel
        panel.add(tf);
        panel.add(send);
        panel.add(reset);
//Text Area plasat in centru
        JTextArea ta = new JTextArea( );
//adaugare componente in frame folosind implicit BorderLayout
        frame.add(BorderLayout.SOUTH, panel);
        frame.add(BorderLayout.NORTH, mb);
        frame.add(BorderLayout.CENTER, ta);
        frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        frame.setVisible(true); }
}
