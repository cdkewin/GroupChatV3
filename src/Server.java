//Chat Application in Java using sockets and (tbc) threads

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.beans.PropertyChangeListener;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

import java.io.*;
import java.net.*;
import javax.swing.*;


public class Server {
    public static void main(String[] args) throws IOException {
        Login_Frame_Server loginpage = new Login_Frame_Server();
//        JTextField username=loginpage.getUserField();
//        JTextField password=loginpage.getPwField();


        synchronized (loginpage) {
            loginpage.display();
            try {
                loginpage.waitForLogin();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        if (loginpage.isConfirmed()) {
            System.out.println("IS CONFIRMED");

            ServerFrame serverFrame = new ServerFrame(loginpage.getUserField().getText());
            JFrame frame = serverFrame.getFrame();
            JTextArea ta = serverFrame.getTa();
            JTextField tf = serverFrame.getTf();
            JButton send = serverFrame.getSend();

            System.out.println("Server started. Waiting for a client...");
            try (ServerSocket srv = new ServerSocket(1234);
                 Socket cln = srv.accept()) {

                System.out.println("Client connected.");

                DataOutputStream out = new DataOutputStream(cln.getOutputStream());
                DataInputStream in = new DataInputStream(cln.getInputStream());

                Thread readThread = new Thread(new Reader_Server(in, ta));
                Thread writeThread = new Thread(new Writer_Server(out, ta, tf, send, loginpage.getUserField().getText()));

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

class Login_Frame_Server {
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
    public Login_Frame_Server() {
        frame = new JFrame("Login Page");
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
                    Pw_Reader_Server obj=new Pw_Reader_Server();
                    String hashed=obj.hashWithSalt(password);
                    salt_write=obj.getSalt();

                    Pw_Reader_Server.writeSaltToFile(salt_write);
                    salt_read=obj.readSaltFromFile();

                    if(obj.verifyPassword(password,hashed, salt_read)){
                        confirmed=true;

                        synchronized (Login_Frame_Server.this) {
                            Login_Frame_Server.this.notify();
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

class Pw_Reader_Server{
    private String username;
    private String password;
    private static byte[] salt = new byte[16];
    Pw_Reader_Server() throws IOException {

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
class ServerFrame {
    private String username;
    private JFrame frame;
    private JTextArea ta;
    private JTextField tf;
    private JButton send;
    private JButton reset;

    public ServerFrame(String username) {
        this.username = username;

        frame = new JFrame("Chat Frame");
        frame.setSize(400, 400);

        // Initialize the JTextArea here
        ta = new JTextArea();
        ta.setEditable(false); // Make it non-editable for displaying received messages

        // Set the layout for better component positioning
        frame.setLayout(new BorderLayout());

        JPanel panel = new JPanel();
        JLabel label = new JLabel("Enter Text");
        tf = new JTextField(10);
        send = new JButton("Send");
        reset = new JButton("Reset");

        panel.add(label);
        panel.add(tf);
        panel.add(send);
        panel.add(reset);

        // Add components to the frame
        frame.add(BorderLayout.SOUTH, panel);
        frame.add(BorderLayout.CENTER, new JScrollPane(ta)); // Wrap JTextArea in JScrollPane for scrolling

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


class Reader_Server implements Runnable {
    private DataInputStream in;
    private JTextArea ta;
    public Reader_Server(DataInputStream in, JTextArea ta) {
        this.in = in;
        this.ta=ta;
    }
    public void run() {
        String msg;
        try {
            while ((msg = in.readUTF()) != null) {
                System.out.println(msg+" : ");
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
class Writer_Server implements Runnable {
    private String username;
    private DataOutputStream out;
    private JTextArea ta;
    private JTextField tf;
    private JButton send;
    public Writer_Server(DataOutputStream out, JTextArea ta, JTextField tf, JButton send, String username) {
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

        tf.addActionListener(new ActionListener() {
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
                out.writeUTF(username+ " : "+userInput);
                ta.append(username +" : "+ userInput + "\n");
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
