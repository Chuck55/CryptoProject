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

public class unlock {
    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            System.out.println("usage: java unlock <directory> <action public key> <action private key> <the action subject>");
            return;
        }
        // TODO verify subject of public key file matches the subject given in the -s argument

        String directory = args[0];
        System.out.println("arg0 is: " + directory);
        String publicKeyPath = args[1];
        System.out.println("arg1 is: " + publicKeyPath);
        String privateKeyPath = args[2];
        System.out.println("arg2 is: " + privateKeyPath);
        String subject = args[3];
        System.out.println("arg3 is: " + subject);

        File directoryFile = new File(directory);
        if (!directoryFile.exists()) {
            System.out.println("Directory Does not Exist");
        } else if  (!directoryFile.isDirectory()) {
            System.out.println("Given directory is not a directory");
        }
        directory = directoryFile.getAbsolutePath();

        File publicKeyFile = new File(publicKeyPath);
        if (!publicKeyFile.canRead()){
            System.out.println("Can't read the public key file.");
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
        // no need to check if subject is same as this is the callers private key
        /*
        if (Filesubject2 != subject) {
            System.out.println("Error: Subject Not Matching");
            return;
        }
        */

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

        // TODO verify the integrity of the keyfile using the locking party's public key and keyfile.sig

        //the keyfile signature is in the directory passed so append /keyfile.sig to the directory to open
        File fileKeySig = new File(directory + "\\keyfile.sig");
        if (!fileKeySig.canRead()){
            System.out.println("Can't read the keyfile.sig file.");
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
        FileInputStream keyfile = new FileInputStream(directory + "\\keyfile");
        byte[] keyfilebytes = new byte[256];
        keyfile.read(keyfilebytes);
        byte[] iv = new byte[16];
        keyfile.read(iv);
        IvParameterSpec ivspec = new IvParameterSpec(iv);
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
            System.out.println("keyfile signature failed"); // validation failure point
        }
        // right now keyfilebytes, the secret AES key, is encrypted with recipients public key, we must decrypt it
        // it's also encoded so will need to turn into a SecretKey
        Cipher cipherAES = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipherAES.init(Cipher.DECRYPT_MODE, DecodedPrivateKey); //uses private key to decrypt the secret key
        // run all through the cipher
        byte[] AESKEYBYTES = cipherAES.doFinal(keyfilebytes); // decrypt the aes key to byte array
        //convert byte[] to SecretKey
        SecretKey AESKey = new SecretKeySpec(AESKEYBYTES, 0, AESKEYBYTES.length, "AES");

        // TODO delete keyfile and keyfile.sig

        File myObj = new File(directory + "\\keyfile");
        if (myObj.delete()) {
            System.out.println("Deleted the file: " + myObj.getName());
        } else {
            System.out.println("Failed to delete the file."); // validation failure
            return;
        }

        File myObj2 = new File(directory +"\\keyfile.sig");
        if (myObj2.delete()) {
            System.out.println("Deleted the file: " + myObj2.getName());
        } else {
            System.out.println("Failed to delete the file."); // validation failure
        }

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, AESKey, ivspec);

        File dir = new File(directory);
        if (dir.isDirectory()) {
            DecryptDirectory(dir, cipher);
        } else {
            System.out.println("Error: Directory Invalid");
            return;
        }
    }
    // at this point the AES key extracted AESKEYBYTES can be used to decrypt the files
    // TODO decrypt the directory replacing the cipher text files with the plain text files

    static public void DecryptDirectory(File dir, Cipher cipher) throws Exception {
        String[] pathnames;
        pathnames = dir.list();
        for (String pathname : pathnames) {
            File dirFile = new File(dir.getAbsolutePath() + "\\"+ pathname);
            if (dirFile.isDirectory()) {
                DecryptDirectory(dirFile, cipher);
            } else {
                String newPTFilename = dirFile.getName().substring(0, dirFile.getName().length()-3); // cuts off the last 3 letters, namely the ".ci"
                // Error checking if file exists
                File newPTFileCreate = new File(newPTFilename);
                if (!newPTFileCreate.createNewFile()) {
                    newPTFileCreate.delete();
                    newPTFileCreate.createNewFile();
                }
                FileOutputStream PTFile = new FileOutputStream(newPTFileCreate);
                FileInputStream CI_in = new FileInputStream(dirFile);
                byte[] ibuf = new byte[1024];
                int len;
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
                    System.out.println("Error in deleting directory.");
                }
            }
        }
    }
}
