import javax.crypto.Cipher;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;


public class AsymmetricEncryption {
    //Generation of key pairs (public+private keys)
    public static KeyPair generateRSAKKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(3072);
        return keyPairGenerator.generateKeyPair();
    }
    //Using RSA cipher along with the public key of the RECIPIENT to
    // encrypt the message
    public static byte[] encrypt(String msg, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(msg.getBytes(StandardCharsets.UTF_8));
    }
    //Decryption of the byte array resulting as ciphertext from above method
    public static String decrypt_byte(byte[] cipherText, PrivateKey privatekey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privatekey);
        byte[] decrypt= cipher.doFinal(cipherText);
        return new String(decrypt);
    }
    public static String decrypt_string(String encrmsg, PrivateKey privatekey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(encrmsg);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privatekey);
        return new String(cipher.doFinal(bytes));
    }
    public static void saveKeyPair(String filePath, KeyPair keyPair) throws IOException {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filePath))) {
            oos.writeObject(keyPair);
        }
    }

    public static KeyPair loadKeyPair(String filePath) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filePath))) {
            return (KeyPair) ois.readObject();
        }
    }
}
