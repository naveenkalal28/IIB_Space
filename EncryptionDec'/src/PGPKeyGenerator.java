

//import org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import org.bouncycastle.*;

import java.io.*;
import java.security.*;
import java.util.Date;

public class PGPKeyGenerator {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        String identity = "mailto:test@example.com";
        String passphrase = "strong_passphrase";
        String originalMessage = "This is a secret message.";

        // Generate a key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        // Create PGP key pair
        PGPKeyPair pgpKeyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, keyPair, new Date());

        // Digest calculator
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);

        // Create a PGP secret key
        PGPSecretKey secretKey = new PGPSecretKey(
                PGPSignature.DEFAULT_CERTIFICATION,
                pgpKeyPair,
                identity,
                sha1Calc,
                null,
                null,
                new JcaPGPContentSignerBuilder(pgpKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc)
                        .setProvider("BC").build(passphrase.toCharArray())
        );

        // Extract public and private keys
        PGPPublicKey publicKey = secretKey.getPublicKey();
        PGPPrivateKey privateKey = secretKey.extractPrivateKey(
                new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passphrase.toCharArray())
        );

        // Encrypt the message
        String encryptedMessage = encryptMessage(originalMessage, publicKey);

        // Decrypt the message
        String decryptedMessage = decryptMessage(encryptedMessage, privateKey);

        // Display the results
        System.out.println("Original Message: " + originalMessage);
        System.out.println("Encrypted Message: " + encryptedMessage);
        System.out.println("Decrypted Message: " + decryptedMessage);
    }

    // Encryption method
    public static String encryptMessage(String message, PGPPublicKey publicKey) throws Exception {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ArmoredOutputStream armoredOut = new ArmoredOutputStream(byteOut);

        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
                        .setWithIntegrityPacket(true)
                        .setSecureRandom(new SecureRandom())
                        .setProvider("BC")
        );
        encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider("BC"));

        OutputStream encryptedOut = encryptedDataGenerator.open(armoredOut, new byte[4096]);

        PGPCompressedDataGenerator compressor = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
        OutputStream compressedOut = compressor.open(encryptedOut);

        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
        OutputStream literalOut = literalDataGenerator.open(compressedOut, PGPLiteralData.BINARY, "", new Date(), new byte[4096]);

        byte[] messageBytes = message.getBytes("UTF-8");
        literalOut.write(messageBytes);
        literalOut.close();
        compressor.close();
        encryptedOut.close();
        armoredOut.close();

        return new String(byteOut.toByteArray(), "UTF-8");
    }

    // Decryption method
    public static String decryptMessage(String encryptedMessage, PGPPrivateKey privateKey) throws Exception {
        InputStream encryptedIn = new ByteArrayInputStream(encryptedMessage.getBytes("UTF-8"));
        PGPObjectFactory objectFactory = new PGPObjectFactory(PGPUtil.getDecoderStream(encryptedIn), new JcaKeyFingerprintCalculator());

        PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList) objectFactory.nextObject();
        PGPPublicKeyEncryptedData encryptedData = (PGPPublicKeyEncryptedData) encryptedDataList.get(0);

        InputStream clearIn = encryptedData.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privateKey));
        PGPObjectFactory plainFactory = new PGPObjectFactory(clearIn, new JcaKeyFingerprintCalculator());
        PGPCompressedData compressedData = (PGPCompressedData) plainFactory.nextObject();

        InputStream compressedIn = new BufferedInputStream(compressedData.getDataStream());
        PGPObjectFactory literalFactory = new PGPObjectFactory(compressedIn, new JcaKeyFingerprintCalculator());
        PGPLiteralData literalData = (PGPLiteralData) literalFactory.nextObject();

        ByteArrayOutputStream literalOut = new ByteArrayOutputStream();
        Streams.pipeAll(literalData.getInputStream(), literalOut);

        return new String(literalOut.toByteArray(), "UTF-8");
    }
   
	
	
	
}





















