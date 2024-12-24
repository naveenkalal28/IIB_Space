package Sample1;
import java.io.File;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;

public class MainClass {

//    public static String getKeys(String filepath) throws Exception {
//    	File file = new File(filepath);
//    	Scanner sc = new Scanner(file);
//    	return sc.next();
//
//    	String pubkey =  null;
//    	String priKey = null;
//    	String publickeyFilePath= "";
//    	String privatekeyFilePath ="";
//    	
//    	
//    	pubkey = getKeys(publickeyFilePath);
//    	priKey=getKeys(privatekeyFilePath);
//    	
//    }
    public static void main(String[] args) {
    	
    	
      Scanner sc = new Scanner(System.in);
       System.out.println("Enter the data to encrypt: ");
       String message = sc.nextLine();

    	
        // Generate key pair once
        KeyPair keypair = getKeyPair();
        //System.out.println("keypair " + keypair);
        PublicKey publicKey = keypair.getPublic();
       //System.out.println("publicKey " + publicKey);
        PrivateKey privateKey = keypair.getPrivate();
        //System.out.println("privateKey " + privateKey);
        
        // Encrypt the data
        String encryptedData = getEncryptedData(publicKey, message);
        System.out.println("Encrypted Data: " + encryptedData);

        // Decrypt the data
        
        String decryptedData = getDecryptedData(privateKey, encryptedData);
        System.out.println("Decrypted Data: " + decryptedData);
    }


    //public static String getKeys(String filepath) throws  
    public static KeyPair getKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String getEncryptedData(PublicKey publicKey, String message) {
        byte[] bytedata = message.getBytes();

        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = cipher.doFinal(bytedata);
            return Base64.getEncoder().encodeToString(encryptedBytes);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String getDecryptedData(PrivateKey privateKey, String encryptedData) {
        byte[] encryptedArrayData = Base64.getDecoder().decode(encryptedData);
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedData = cipher.doFinal(encryptedArrayData);
            return new String(decryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
