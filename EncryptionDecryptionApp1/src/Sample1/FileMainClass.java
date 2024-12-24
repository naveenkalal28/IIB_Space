package Sample1;

import java.io.File;
import java.io.FileNotFoundException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class FileMainClass {

	public static String getkeyFile(String Filepath) throws FileNotFoundException {
		File file = new File(Filepath);
		Scanner sc = new Scanner(file);
		return sc.next();
	}
	
	public static void main(String[] args){
		String PubFilePath="C:\\deleteKeysFolder\\publicKey.crt";
		String PriFilePath = "C:\\deleteKeysFolder\\privateKey.crt";
		
		String PubKey = null;
		String PriKey = null;
		
		try {
			PubKey =getkeyFile(PubFilePath);
			PriKey = getkeyFile(PriFilePath);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
		
		byte[] PublicKeyBytes = Base64.getDecoder().decode(PubKey.getBytes());
		byte[] PrivateKeyBytes = Base64.getDecoder().decode(PriKey.getBytes());
		
	try {
		KeyFactory keyfactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec x509encodedkeyspec = new X509EncodedKeySpec(PublicKeyBytes);
		PublicKey publickey = keyfactory.generatePublic(x509encodedkeyspec);
		
		KeyFactory privatekeyFactory = keyfactory.getInstance("RSA");
		PKCS8EncodedKeySpec pkcs8encodedspec =new PKCS8EncodedKeySpec(PrivateKeyBytes);
		PrivateKey privatekey=keyfactory.generatePrivate(pkcs8encodedspec);
		
		
		
		Scanner sc = new Scanner(System.in);
		System.out.println("Enter the data to encrypt:");
		String message=sc.next();
		
		String encryptedData = MainClass.getEncryptedData(publickey, message);
		System.out.println("Encrypted data: "+encryptedData);
		String decryptedData = MainClass.getDecryptedData(privatekey, encryptedData);
		System.out.println("Decrypted data: "+decryptedData);
		
		
	} catch (Exception e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}

		
		
	}
	
}
