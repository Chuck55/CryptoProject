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

public class keygen {
	public static void main(String[] args) throws Exception {
    if (args.length != 3) {
      System.out.println("usage: java keygen <subject> <public key file> <private key file>");
      return;
    } else {
      String subject = args[0];
      String publicPath = args[1];
      String privatePath = args[2];

      File publicFile = new File(publicPath);
      File privateFile = new File(privatePath);

      publicFile.createNewFile();
      privateFile.createNewFile();
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      Key privateKey = keyPair.getPrivate();
      Key publicKey = keyPair.getPublic();

      FileWriter publicWriter = new FileWriter(publicFile);
      publicWriter.write(subject);
      publicWriter.write("\n");
      publicWriter.write("RSA 2048");
      publicWriter.write("\n");
      publicWriter.close();
      if (publicKey != null) {
        FileOutputStream fosPublic = new FileOutputStream(publicFile, true);
        fosPublic.write(publicKey.getEncoded());
        fosPublic.close();
      }
      FileWriter privateWriter = new FileWriter(privateFile);
      privateWriter.write(subject);
      privateWriter.write("\n");
      privateWriter.write("RSA 2048");
      privateWriter.write("\n");
      privateWriter.close();
      if (privateKey != null) {
        FileOutputStream fosPrivate = new FileOutputStream(privateFile, true);
        fosPrivate.write(privateKey.getEncoded());
        fosPrivate.close();
      }
    }
  }
}
