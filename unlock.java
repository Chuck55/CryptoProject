import java.nio.Buffer;
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
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.KeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.GCMParameterSpec;

public class unlock {
    public static void main(String[] args) throws Exception {
        if (args.length != 8) {
            System.out.println("usage: java unlock -d <directory> -p <action public key> -r <action private key> -s <the action subject>");
            return;
        }
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
          System.out.println("usage: java unlock -d <directory> -p <action public key> -r <action private key> -s <the action subject>");
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
        } else if  (!directoryFile.isDirectory()) {
            System.out.println("Error: Given directory is not a directory");
            return ;
        }
        directory = directoryFile.getAbsolutePath();

        File publicKeyFile = new File(publicKeyPath);
        if (!publicKeyFile.canRead()){
            System.out.println("Error: Can't read the public key file.");
            return;
        }

        Scanner publicKeyScanner = new Scanner(publicKeyFile);
        String Filesubject = publicKeyScanner.nextLine();
        if (!Filesubject.equals(subject)) {
            System.out.println("Filesubject: " + Filesubject + ", subject: " + subject);
	          System.out.println("Error: Subject Not Matching");
            return;
        }

        //Decodes Public Key
        String pubAlgo = publicKeyScanner.nextLine(); // not used
        String PublicKey = publicKeyScanner.nextLine(); // this will stop when it hits a newline or eof
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
        String Filesubject2 = privateKeyScanner.nextLine();

        String privAlgo = privateKeyScanner.nextLine(); // not used
        String PrivateKey = privateKeyScanner.nextLine(); // this will stop when it hits a newline or eof
        byte[] decodedPrivateKey = Base64.getDecoder().decode(PrivateKey);

        // Converts from bytes to privatekey class
        PrivateKey DecodedPrivateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(decodedPrivateKey));
        privateKeyScanner.close();

        // Checking if DecodedPublicKey and DecodedPrivateKey are null
        if (DecodedPublicKey == null || DecodedPrivateKey == null) {
            System.out.println("Error: Decoded Key Is Null");
            return;
        }

        //now we have usable private and public Key objects
        //the keyfile signature is in the directory passed so append /keyfile.sig to the directory to open
        File fileKeySig = new File(directory + "/keyfile.sig");
        if (!fileKeySig.canRead()){
            System.out.println("Error: Can't read the keyfile.sig file.");
            return;
        }
        //extract the signature. it has been encoded as a string and we need it as a byte array before validating the signature
        Scanner keySigScanner = new Scanner(fileKeySig);
        //gets the string
        String keySigString = keySigScanner.nextLine();
        // decodes to a byte array
        byte[] keySigByteArray = Base64.getDecoder().decode(keySigString);

        //extract the AES key from keyfile
        // byte[] keyfilebytes = Files.readAllBytes(Paths.get(directory + "\\keyfile"));
        FileInputStream keyfile = new FileInputStream(directory + "/keyfile");
        byte[] keyfilebytes = new byte[256];
        keyfile.read(keyfilebytes);
        byte[] iv = new byte[16];
        keyfile.read(iv);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        keyfile.close();

        //create a signature object
        Signature sign = Signature.getInstance("SHA256withRSA");
        //initialize to verify with the public key
        sign.initVerify(DecodedPublicKey);
        // update with the keyfile bytes
        sign.update(keyfilebytes);
        //verify the signature
        boolean bool = sign.verify(keySigByteArray);

        if(!bool) {
            System.out.println("Error: Keyfile signature failed"); // validation failure point
            return;
        }

        SecretKey AESKey;
        try {
          // right now keyfilebytes, the secret AES key, is encrypted with recipients public key, we must decrypt it
          // it's also encoded so will need to turn into a SecretKey
          Cipher cipherAES = Cipher.getInstance("RSA/ECB/PKCS1Padding");
          cipherAES.init(Cipher.DECRYPT_MODE, DecodedPrivateKey); //uses private key to decrypt the secret key
          // run all through the cipher
          byte[] AESKEYBYTES = cipherAES.doFinal(keyfilebytes); // decrypt the aes key to byte array
          //convert byte[] to SecretKey
          AESKey = new SecretKeySpec(AESKEYBYTES, 0, AESKEYBYTES.length, "AES");
        } catch (Exception e) {
          System.out.println("Error: Decryption failed");
          return;
        }

        // delete keyfile and keyfile.sig

        File myObj = new File(directory + "/keyfile");
        if (!myObj.delete()) {
            System.out.println("Error: Failed to delete keyfile"); // validation failure
            return;
        }

        File myObj2 = new File(directory +"/keyfile.sig");
        if (!myObj2.delete()) {
            System.out.println("Error: Failed to delete the keyfile.sig"); // validation failure
            return;
	      }
        // update 3DEC2020 no longer instantiating the decrypt cipher in main. now done in decryptdirectory
        //Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        //cipher.init(Cipher.DECRYPT_MODE, AESKey, spec);

        File dir = new File(directory);
        if (dir.isDirectory()) {
            DecryptDirectory(dir, AESKey, spec);
        } else {
            System.out.println("Error: Directory Invalid");
            return;
        }

        System.out.println("Directory successfully decrypted. Exiting.");
    }
    // at this point the AES key extracted AESKEYBYTES can be used to decrypt the files
    // decrypt the directory replacing the cipher text files with the plain text files

    static public void DecryptDirectory(File dir, SecretKey AESKey, GCMParameterSpec spec) throws Exception {
        String[] pathnames;
        pathnames = dir.list();
        for (String pathname : pathnames) {
            File dirFile = new File(dir.getAbsolutePath() + "/"+ pathname);
            if (dirFile.isDirectory()) {
                DecryptDirectory(dirFile, AESKey, spec);
            } else {
                String newPTFilename = dirFile.getName().substring(0, dirFile.getName().length()-3); // cuts off the last 3 letters, namely the ".ci"
                // Error checking if file exists
                File newPTFileCreate = new File(dir.getAbsolutePath() + "/"+ newPTFilename);
                if (!newPTFileCreate.createNewFile()) {
                    newPTFileCreate.delete();
                    newPTFileCreate.createNewFile();
                }
                FileOutputStream PTFile = new FileOutputStream(newPTFileCreate);
                FileInputStream CI_in = new FileInputStream(dirFile);
                byte[] ibuf = new byte[1024];
                int len;
                //Update 3DEC2020 instantiate a new cipher for each file
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, AESKey, spec);
                while ((len = CI_in.read(ibuf)) != -1) {
                    byte[] obuf = cipher.update(ibuf, 0, len);
                    if ( obuf != null ) {
                        PTFile.write(obuf);
                    }
                }
                PTFile.write(cipher.doFinal());
                PTFile.close();
                CI_in.close();
                if (!dirFile.delete()) {
                    System.out.println("Error in deleting file.");
                    return;
                }
            }
        }
    }
}
