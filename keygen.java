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
    if (args.length != 6) {
      System.out.println("usage: java keygen -s <subject> -pub <public key file> -priv <private key file>");
      return;
    } else {
			String subject = "";
      String publicPath = "";
      String privatePath = "";
			// update to use flags that can be out of order
			for (int i = 0; i < 6; i=i+2) {
				if (args[i].equals("-s")) { // subject flag
					subject = args[i+1];
					continue;
				}
				if (args[i].equals("-pub")) { // public key flag
					publicPath = args[i+1];
					continue;
				}
				if (args[i].equals("-priv")) { // private key flag
					privatePath = args[i+1];
				}
			}

      File publicFile = new File(publicPath);
      File privateFile = new File(privatePath);

      if (!publicFile.createNewFile()) {
        publicFile.delete();
        publicFile.createNewFile();
      }
      if (!privateFile.createNewFile()) {
        publicFile.delete();
        privateFile.createNewFile();
      }
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
        FileWriter myWriterpublic = new FileWriter(publicFile, true);
        myWriterpublic.write(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        myWriterpublic.close();
      }
      FileWriter privateWriter = new FileWriter(privateFile);
      privateWriter.write(subject);
      privateWriter.write("\n");
      privateWriter.write("RSA 2048");
      privateWriter.write("\n");
      privateWriter.close();
      if (privateKey != null) {
        FileWriter myWriterPrivate = new FileWriter(privateFile, true);
        myWriterPrivate.write(Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        myWriterPrivate.close();
      }
    }
  }
}
