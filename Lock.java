// This is Lock
//possible modules needed taken from: https://www.javainterviewpoint.com/java-aes-256-gcm-encryption-and-decryption/
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.io.*;
import java.nio.file.Paths;
import java.util.Scanner;
import java.nio.file.Files;
import java.io.File;  // Import the File class
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.KeyFactory;

public class Lock {
	public static void main(String[] args) throws Exception {
    if (args.length != 5) {
      System.out.println("usage: java Lock <directory> <action public key> <action private key> <the action subject>");
      return;
    } else {
      //Validate  that  the  subject  in  the  action  public  key  file  matches  the  subject  given  in  the  -sargument.
      //Generate a random AES key for encryption and tagging, encrypt that key with the unlockingparty’s public key, write that cipher text to a file calledkeyfile.
      //Sign the keyfile with the locker’s private key, write that signature to a file calledkeyfile.sig.
      //Encrypt all files in the given directory using AES in CBC-GCM mode, replacing the plaintext files with the cipher text files.
    	String directory = args[0];
      String publicKeyPath = args[1];
      String privateKeyPath = args[2];
			String subject = args[3];
      
      //Checks that the subjects are the same
      File publicKeyFile = new File(publicKeyPath);
      Scanner publicKeyScanner = new Scanner(publicKeyFile);
      String Filesubject = publicKeyScanner.nextLine();
      if (Filesubject != subject) {
        System.out.println("usage: Subject Not Matching");
        return;
      }
      
      //Decodes Public Key
      String PublicKey = publicKeyScanner.nextLine();
      byte[] decodedPublicKey = Base64.getDecoder().decode(PublicKey);
      KeyFactory kf = KeyFactory.getInstance("RSA"); // or "EC" or whatever
      PrivateKey DecodedPublicKey = kf.generatePrivate(new PKCS8EncodedKeySpec(decodedPublicKey));
      publicKeyScanner.close();

      //Decodes Private Key
      File privateKeyFile = new File(privateKeyPath);
      Scanner privateKeyScanner = new Scanner(privateKeyFile);
      String Filesubject2 = privateKeyScanner.nextLine();
      String PrivateKey = privateKeyScanner.nextLine();
      byte[] decodedPrivateKey = Base64.getDecoder().decode(PrivateKey);
      
      // Converts from bytes to privatekey class
      PrivateKey DecodedPrivateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(decodedPrivateKey));
      privateKeyScanner.close();
      
      //Creates AES Key
      KeyGenerator keyGen = KeyGenerator.getInstance("AES");
      keyGen.init(256); // for example
      SecretKey AESKey = keyGen.generateKey();
      byte[] AESKEYBYTES = AESKey.getEncoded();
      
      //Creates Cipher and ecodes with the Decoded public key
      Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
      cipher.init(Cipher.ENCRYPT_MODE, DecodedPublicKey);
      
      // Writes Cipher To File
      File KeyFile = new File("keyfile");
      KeyFile.createNewFile();
      FileOutputStream fosKeyFile = new FileOutputStream("keyfile", true);
      fosKeyFile.write(cipher.doFinal(AESKEYBYTES));// Encoded Key
      fosKeyFile.close();

      //Creates Digital Signiture and signs keyfile
      Signature signature = Signature.getInstance("SHA256withRSA");
	    signature.initSign(DecodedPrivateKey); //updates with private key
    
      byte[] keyfilebytes = Files.readAllBytes(Paths.get("keyfile"));
      signature.update(keyfilebytes);
      
      //Creates Sig file and writes signiture to sig file
      File KeyFileSig = new File("keyfile.sig");
      KeyFileSig.createNewFile();
      byte[] digitalSignature = signature.sign();
      FileWriter myWriter = new FileWriter("keyfile.sig");
      myWriter.write(Base64.getEncoder().encodeToString(digitalSignature));
      myWriter.close();
      
      //write all files to directory
      File dir = new File(directory);
      if (dir.isDirectory()) {
        String[] pathnames;
      	pathnames = dir.list();
        for (String pathname : pathnames) {
          File dirFile = new File(pathname);
          String newFile = dirFile.getName() + ".ci"; // Not sure what this will be.
          File newFileCreate = new File(newFile);
          newFileCreate.createNewFile();
          FileWriter cipherFile = new FileWriter(newFileCreate);
		  FileInputStream in = new FileInputStream(pathname);
          byte[] ibuf = new byte[1024];
          int len;		  
          while ((len = in.read(ibuf)) != -1) {
              byte[] obuf = cipher.update(ibuf, 0, len);
              if ( obuf != null ) {
                cipherFile.write(Base64.getEncoder().encodeToString(obuf));
              }
          }
          cipherFile.close();
          in.close();
        }
      }
    }
  }
}