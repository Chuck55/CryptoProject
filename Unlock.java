//This is Unlock
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

public class UnLock {
	public static void main(String[] args) throws Exception {
    if (args.length != 5) {
      System.out.println("usage: java UnLock <directory> <action public key> <action private key> <the action subject>");
      return;
    } else {
      //Validate  that  the  subject  in  the  action  public  key  file  matches  the  subject  given  in  the  -sargument.
      //Verify the integrity of the keyfile using the locking party’s public key and keyfile.sig.
      //Fetch the AES key from keyfile.
      //Delete keyfile and keyfile.sig at this point.
      //Decrypt the encrypted files in the directory, replacing the cipher text files with the plain textfiles.
      String directory = args[0];
      String publicKeyPath = args[1];
      String privateKeyPath = args[2];
			string subject = args[3];
      File publicKeyFile = new File(publicKeyPath);
      Scanner publicKeyScanner = new Scanner(publicKeyFile);
      String Filesubject = publicKeyScanner.nextLine();
      if (FileSubject != subject) {
        System.out.println("usage: Subject Not Matching");
        return;
      }
    }
  }
}
