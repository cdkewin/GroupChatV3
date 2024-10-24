import javax.swing.*;
import javax.xml.crypto.Data;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.*;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.SQLOutput;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;


import javax.swing.*;
import java.io.*;
import java.net.*;

public class Client {
    public static void main(String[] args) throws IOException {
        Login_Frame loginpage = new Login_Frame();

        synchronized (loginpage) {
            loginpage.display();
            try {
                loginpage.waitForLogin();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        if (loginpage.isConfirmed()) {
            System.out.println("Login confirmed, redirecting to the chat platform...");

            ClientFrame clientFrame = new ClientFrame(loginpage.getUserField().getText());
            JFrame frame = clientFrame.getFrame();
            JTextArea ta = clientFrame.getTa();
            JTextField tf = clientFrame.getTf();
            JButton send = clientFrame.getSend();

            try (Socket cln = new Socket("localhost", 1234);
                 DataOutputStream out = new DataOutputStream(cln.getOutputStream());
                 DataInputStream in = new DataInputStream(cln.getInputStream())) {

                Thread readThread = new Thread(new Reader_Client(in, ta));
                Thread writeThread = new Thread(new Writer_Client(out, ta, tf, send, loginpage.getUserField().getText()));

                readThread.start();
                writeThread.start();

                readThread.join(); // Wait for the read thread to finish
                writeThread.join(); // Wait for the write thread to finish

            } catch (IOException | InterruptedException e) {
                e.printStackTrace();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }
}
class Login_Frame {
    private JFrame frame;
    private JTextField userField;
    private JPasswordField pwField;
    private JButton login;
    private boolean confirmed=false;

    public synchronized void waitForLogin() throws InterruptedException {
        while (!confirmed) {
            wait();
        }
    }
    public Login_Frame() {
        frame = new JFrame("Client login Page");
        frame.setSize(400, 400);

        JPanel panel = new JPanel(new GridLayout(3,2));

        userField = new JTextField(10);
        userField.setSize(40, 20);
        Label user=new Label("Username");

        pwField = new JPasswordField(10);
        pwField.setSize(40, 20);
        Label pw=new Label("Password");

        login=new JButton("Login");
        login.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String username =userField.getText();
                String password =pwField.getText();
                byte[]salt_write= null;
                byte[]salt_read= null;
                //Test if the password is not already in DB

                try {
                    Pw_Reader obj=new Pw_Reader();
                    String hashed=obj.hashWithSalt(password);
                    salt_write=obj.getSalt();

                    Pw_Reader.writeSaltToFile(salt_write);
                    salt_read=obj.readSaltFromFile();

                    if(obj.verifyPassword(password,hashed, salt_read)){
                        confirmed=true;

                        synchronized (Login_Frame.this) {
                            Login_Frame.this.notify();
                        }
                        System.out.println("Confirmed from if");
                        frame.dispose();
                    }
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
            }
        });

        panel.add(user);
        panel.add(userField);
        panel.add(pw);
        panel.add(pwField);
        panel.add(login);

        frame.add(panel);
        frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        frame.setVisible(true);
    }
    public boolean isConfirmed(){
        return confirmed;
    }
    public JFrame getFrame() {
        return frame;
    }
    public JTextField getUserField() {
        return userField;
    }
    public JTextField getPwField() {
        return pwField;
    }
    public void display() {

    }
}
class Pw_Reader{
    private String username;
    private String password;
    private static byte[] salt = new byte[16];
    Pw_Reader() throws IOException {

        //System.out.println("FROM HASHES: "+out);
    }
    public static String hashWithSalt(String password) throws Exception {
        SecureRandom random = new SecureRandom();

        random.nextBytes(salt);

        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(salt);

        byte[] hashedPassword = md.digest(password.getBytes());
        System.out.println(Base64.getEncoder().encodeToString(hashedPassword));
        return Base64.getEncoder().encodeToString(hashedPassword);
    }
    public static boolean verifyPassword(String inputPassword, String storedHash, byte[] salt) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(salt);

        byte[] hashedInputPassword = md.digest(inputPassword.getBytes());
        String newHash = Base64.getEncoder().encodeToString(hashedInputPassword);
        return newHash.equals(storedHash);
    }
    byte[] getSalt(){
        return salt;
    }
    public static void writeSaltToFile(byte[] salt) {
        try (FileWriter fw = new FileWriter("C:\\Users\\StefanNastas\\IdeaProjects\\GroupChat_003\\src\\hashes.txt", true);
             BufferedWriter bw = new BufferedWriter(fw)) {
            String saltEncoded = Base64.getEncoder().encodeToString(salt);
            bw.write(saltEncoded);
            bw.newLine();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    public static byte[] readSaltFromFile() {
        byte[] salt = null;
        try (BufferedReader br = new BufferedReader(new FileReader("C:\\Users\\StefanNastas\\IdeaProjects\\GroupChat_003\\src\\hashes.txt"))) {
            String line;
            while ((line = br.readLine()) != null) {
                salt = Base64.getDecoder().decode(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return salt;
    }
}
class ClientFrame {
    private String username;
    private JFrame frame;
    private JTextArea ta;
    private JTextField tf;
    private JButton send;
    private JButton reset;

    public ClientFrame(String username) {

        this.username=username;
        frame = new JFrame("Chat Frame");
        frame.setSize(400, 400);

        JPanel panel = new JPanel();
        JLabel label = new JLabel("Enter Text");
        tf = new JTextField(10);
        send = new JButton("Send");
        reset = new JButton("Reset");
        panel.add(label);
        panel.add(tf);
        panel.add(send);
        panel.add(reset);

        ta = new JTextArea();

        frame.add(BorderLayout.SOUTH, panel);
        frame.add(BorderLayout.CENTER, ta);
        frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        frame.setVisible(true);
    }

    public JFrame getFrame() {
        return frame;
    }

    public JTextArea getTa() {
        return ta;
    }

    public JTextField getTf() {
        return tf;
    }

    public JButton getSend() {
        return send;
    }

    public String getUsername() {
        return username;
    }
}

class Reader_Client implements Runnable {
    private DataInputStream in;
    private JTextArea ta;
    public Reader_Client(DataInputStream in, JTextArea ta) {
        this.in = in;
        this.ta=ta;
    }

    @Override
    public void run() {
        String msg;
        try {
            while ((msg = in.readUTF()) != null) {
                System.out.println(msg);
                ta.append(msg+"\n");
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

// Writer thread class
class Writer_Client implements Runnable {
    private String username;
    private DataOutputStream out;
    private JTextArea ta;
    private JTextField tf;
    private JButton send;
    public Writer_Client(DataOutputStream out, JTextArea ta, JTextField tf, JButton send, String username) {
        this.out = out;
        this.ta=ta;
        this.tf=tf;
        this.send=send;
        this.username=username;

        send.addActionListener(new ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            sendMessage();
        }
    });
    }
    private void sendMessage() {
        String userInput = tf.getText();
        System.out.println(userInput);
        if (!userInput.isEmpty()) {
            try {
                out.writeUTF(username+": "+userInput);
                ta.append(username+ " : " + userInput + "\n");
                tf.setText(""); // clear text field after sending
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    @Override
    public void run() {

    }
}
