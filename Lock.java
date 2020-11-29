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

public class lock {
	public static void main(String[] args) throws Exception {
    if (args.length != 4) {
      System.out.println("usage: java lock <directory> <action public key> <action private key> <the action subject>");
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
      if (!publicKeyFile.exists()) {
        System.out.println("Error: Public Key File Does Not Exist");
        return;
      }
      Scanner publicKeyScanner = new Scanner(publicKeyFile);
      String Filesubject = publicKeyScanner.nextLine();
      if (Filesubject != subject) {
        System.out.println("Error: Subject Not Matching");
        return;
      }
      
      //Decodes Public Key
      String pubAlgo = publicKeyScanner.nextLine(); // not used
      String PublicKey = publicKeyScanner.nextLine(); // this will stop when it hits a newline and the encoded key may have the newline char value causing the private key to be piecemeal
      byte[] decodedPublicKey = Base64.getDecoder().decode(PublicKey);
      KeyFactory kf = KeyFactory.getInstance("RSA"); // or "EC" or whatever
      PublicKey DecodedPublicKey = kf.generatePublic(new PKCS8EncodedKeySpec(decodedPublicKey));
      publicKeyScanner.close();

      //Decodes Private Key
      File privateKeyFile = new File(privateKeyPath);
      if (!privateKeyFile.exists()) {
        System.out.println("Error: Private Key File Does Not Exist");
        return;
      }
      Scanner privateKeyScanner = new Scanner(privateKeyFile);
      String Filesubject2 = privateKeyScanner.nextLine();
      // Check if subject is same
      if (Filesubject2 != subject) {
        System.out.println("Error: Subject Not Matching");
        return;
      }
      String privAlgo = privateKeyScanner.nextLine(); // not used
      String PrivateKey = privateKeyScanner.nextLine(); // this will stop when it hits a newline and the encoded key may have the newline char value causing the private key to be piecemeal
      byte[] decodedPrivateKey = Base64.getDecoder().decode(PrivateKey);
      
      // Converts from bytes to privatekey class
      PrivateKey DecodedPrivateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(decodedPrivateKey));
      privateKeyScanner.close();
      
      // Checking if DecodedPublicKey and DecodedPrivateKey are null
      if (DecodedPublicKey == null || DecodedPrivateKey == null) {
        System.out.println("Error: Decoded Key Is Null");
        return;
      }
      
      //Creates AES Key
      KeyGenerator keyGen = KeyGenerator.getInstance("AES");
      keyGen.init(128); // for example
      SecretKey AESKey = keyGen.generateKey();
      
      Cipher cipherAES = Cipher.getInstance("AES/GCM/PKCS5Padding");
      cipherAES.init(Cipher.ENCRYPT_MODE, DecodedPublicKey);
      byte[] AESKEYBYTES = AESKey.getEncoded();
      
      // Writes AES Cipher To File
      File KeyFile = new File("keyfile");
      // Delete file if exists
      if (!KeyFile.createNewFile()) {
        KeyFile.delete();
        KeyFile.createNewFile();
      }
    
      FileOutputStream fosKeyFile = new FileOutputStream("keyfile", true);
      fosKeyFile.write(cipherAES.doFinal(AESKEYBYTES));// Encoded Key 
      fosKeyFile.close();

      //Creates Digital Signiture and signs keyfile
      Signature signature = Signature.getInstance("SHA256withRSA");
	    signature.initSign(DecodedPrivateKey); //updates with private key
    
      byte[] keyfilebytes = Files.readAllBytes(Paths.get("keyfile"));
      signature.update(keyfilebytes);
      
      //Creates Sig file and writes signiture to sig file
      File KeyFileSig = new File("keyfile.sig");
      // Error checking here
      if (!KeyFileSig.createNewFile()) {
        KeyFileSig.delete();
        KeyFileSig.createNewFile();
      }
  
      byte[] digitalSignature = signature.sign();
      FileWriter myWriter = new FileWriter("keyfile.sig");
      myWriter.write(Base64.getEncoder().encodeToString(digitalSignature));
      myWriter.close();
      
      
      //Creates Cipher and encodes with the AES key
      Cipher cipher = Cipher.getInstance("AES/GCM/PKCS5Padding");
      cipher.init(Cipher.ENCRYPT_MODE, AESKey);
      
      //write all files to directory
      File dir = new File(directory);
      if (dir.isDirectory()) {
        EncryptDirectory(dir, cipher);
      } else {
        System.out.println("Error: Directory Invalid");
      	return;
      }
    }
  }
  static public void EncryptDirectory(File dir, Cipher cipher) throws Exception {
   String[] pathnames;
      pathnames = dir.list();
      for (String pathname : pathnames) {
        File dirFile = new File(pathname);
        if (dirFile.isDirectory()) {
          EncryptDirectory(dirFile, cipher);
        } else {
          String newFile = dirFile.getName() + ".ci"; // Not sure what this will be.
          // Error checking if file exists
          File newFileCreate = new File(newFile);
          if (!newFileCreate.createNewFile()) {
            newFileCreate.delete();
            newFileCreate.createNewFile();
          }
      		FileOutputStream cipherFile = new FileOutputStream(newFileCreate);
          FileInputStream in = new FileInputStream(pathname);
          byte[] ibuf = new byte[1024];
          int len;		  
          while ((len = in.read(ibuf)) != -1) {
              byte[] obuf = cipher.update(ibuf, 0, len);
              if ( obuf != null ) {
                cipherFile.write(obuf);
              }
          }
          cipherFile.write(cipher.doFinal());         
          cipherFile.close();
          in.close();
          if (!dirFile.delete()) {
            System.out.println("Error in deleting directory.");
          }
        }  
      } 
    }
}