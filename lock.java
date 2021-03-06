// This is Lock
//possible modules needed taken from: https://www.javainterviewpoint.com/java-aes-256-gcm-encryption-and-decryption/
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
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
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.GCMParameterSpec;

public class lock {
  public static void main(String[] args) throws Exception {
    if (args.length != 8) {
      System.out.println("usage: java lock -d <directory> -p <action public key> -r <action private key> -s <the action subject>");
      return;
    } else {
      //Validate  that  the  subject  in  the  action  public  key  file  matches  the  subject  given  in  the  -sargument.
      //Generate a random AES key for encryption and tagging, encrypt that key with the unlockingparty’s public key, write that cipher text to a file calledkeyfile.
      //Sign the keyfile with the locker’s private key, write that signature to a file calledkeyfile.sig.
      //Encrypt all files in the given directory using AES in CBC-GCM mode, replacing the plaintext files with the cipher text files.

      //update for flag checking
      String directory = "";
      String publicKeyPath = "";
      String privateKeyPath = "";
      String subject = "";

      boolean s = false, p = false, r = false, d = false;

      for (int i = 0; i < 8; i=i+2) {
        if (args[i].equals("-s")) { // subject flag
					subject = args[i+1];
          s = true;
          continue;
				}
				if (args[i].equals("-p")) { // public key flag
					publicKeyPath = args[i+1];
          p = true;
          continue;
				}
				if (args[i].equals("-r")) { // private key flag
					privateKeyPath = args[i+1];
          r = true;
          continue;
				}
        if (args[i].equals("-d")) { // directory flag
          d = true;
          directory = args[i+1];
        }
      }

      if (!(s && p && r && d)) {
        System.out.println("Error: Each flag is required.");
        System.out.println("usage: java lock -d <directory> -p <action public key> -r <action private key> -s <the action subject>");
        return;
      }

      if (publicKeyPath.equals(privateKeyPath)) {
        System.out.println("Error: Public key and private key cannot be the same");
        return;
      }

      File directoryFile = new File(directory);
      if (!directoryFile.exists()) {
        System.out.println("Error: Directory Does not Exist");
        return;
      } else if (!directoryFile.isDirectory()) {
        System.out.println("Error: Given directory is not a directory");
        return;
      }
      directory = directoryFile.getAbsolutePath();
      /**
       String directory = "C:\\Users\\kylej\\OneDrive\\Desktop\\WHOO";
       String subject = "stuff";
       String publicKeyPath = "C:\\Users\\kylej\\OneDrive\\Desktop\\CryptoProject\\public2";
       String privateKeyPath = "C:\\Users\\kylej\\OneDrive\\Desktop\\CryptoProject\\private";
       **/
      //Checks that the subjects are the same
      File publicKeyFile = new File(publicKeyPath);
      if (!publicKeyFile.exists()) {
        System.out.println("Error: Public Key File Does Not Exist");
        return;
      }
      Scanner publicKeyScanner = new Scanner(publicKeyFile);
      String FileSubject = publicKeyScanner.nextLine();
      if (!FileSubject.equals(subject)) {
        System.out.println(FileSubject + " is not the same as " + subject);
        System.out.println("Error: Subject Not Matching");
        return;
      }
      //Decodes Public Key
      String pubAlgo = publicKeyScanner.nextLine(); // not used
      String PublicKey = publicKeyScanner.nextLine(); // this will stop when it hits a newline and the encoded key may have the newline char value causing the private key to be piecemeal
      byte[] decodedPublicKey = Base64.getDecoder().decode(PublicKey);
      KeyFactory kf = KeyFactory.getInstance("RSA"); // or "EC" or whatever
      PublicKey DecodedPublicKey = kf.generatePublic(new X509EncodedKeySpec(decodedPublicKey));
      publicKeyScanner.close();

      //Decodes Private Key
      File privateKeyFile = new File(privateKeyPath);
      if (!privateKeyFile.exists()) {
        System.out.println("Error: Private Key File Does Not Exist");
        return;
      }
      Scanner privateKeyScanner = new Scanner(privateKeyFile);
      String FileSubject2 = privateKeyScanner.nextLine();

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

      // Initialization vector
      byte[] iv = new byte[16];
      new SecureRandom().nextBytes(iv);
      GCMParameterSpec spec = new GCMParameterSpec(128, iv);

      Cipher cipherAES = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      cipherAES.init(Cipher.ENCRYPT_MODE, DecodedPublicKey);
      byte[] AESKEYBYTES = AESKey.getEncoded();
      // Writes AES Cipher To File
      File KeyFile = new File(directory + "/keyfile");
      // Delete file if exists
      if (!KeyFile.createNewFile()) {
        KeyFile.delete();
        KeyFile.createNewFile();
      }

      FileOutputStream fosKeyFile = new FileOutputStream(directory + "/keyfile", true);
      byte [] FinalAESKEYBYTES = cipherAES.doFinal(AESKEYBYTES);
      fosKeyFile.write(FinalAESKEYBYTES);// Encoded Key
      fosKeyFile.write(iv);
      fosKeyFile.close();

      //Creates Digital Signiture and signs keyfile
      Signature signature = Signature.getInstance("SHA256withRSA");
      signature.initSign(DecodedPrivateKey); //updates with private key

      signature.update(FinalAESKEYBYTES);

      //Creates Sig file and writes signiture to sig file
      File KeyFileSig = new File(directory + "/keyfile.sig");
      // Error checking here
      if (!KeyFileSig.createNewFile()) {
        KeyFileSig.delete();
        KeyFileSig.createNewFile();
      }

      byte[] digitalSignature = signature.sign();
      FileWriter myWriter = new FileWriter(directory + "/keyfile.sig");
      myWriter.write(Base64.getEncoder().encodeToString(digitalSignature));
      myWriter.close();

      //Creates Cipher and encodes with the AES key
      //Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      //cipher.init(Cipher.ENCRYPT_MODE, AESKey, spec);
      //write all files to directory
      File dir = new File(directory);
      if (dir.isDirectory()) {
        EncryptDirectory(dir, AESKey, spec);
      } else {
        System.out.println("Error: Directory Invalid");
        return;
      }

      System.out.println("Directory successfully encrypted. Exiting.");
    }
  }

  //Update 3DEC2020 now the method parameters take a a secret key (AES) and the IV (spec)
  static public void EncryptDirectory(File dir, SecretKey AESKey, GCMParameterSpec spec) throws Exception {
    String[] pathnames;
    pathnames = dir.list();
    for (String pathname : pathnames) {
      File dirFile = new File(dir.getAbsolutePath() + "/"+ pathname);
      if (dirFile.isDirectory()) {
        EncryptDirectory(dirFile, AESKey, spec);
      } else if (pathname.equals("keyfile") || pathname.equals("keyfile.sig")) {
        continue;
      } else {
        String newFile = dir.getAbsolutePath() + "/" + dirFile.getName() + ".ci"; // Not sure what this will be.
        // Error checking if file exists
        File newFileCreate = new File(newFile);
        if (!newFileCreate.createNewFile()) {
          newFileCreate.delete();
          newFileCreate.createNewFile();
        }
        FileOutputStream cipherFile = new FileOutputStream(newFileCreate);
        FileInputStream in = new FileInputStream(dir.getAbsolutePath() + "/"+ pathname);
        byte[] ibuf = new byte[1024];
        int len;
        // Update 3DEC2020 now instantiating cipher in the method before encrypting
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, AESKey, spec);
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
          System.out.println("Error in deleting file.");
          return;
        }
      }
    }
  }
}
