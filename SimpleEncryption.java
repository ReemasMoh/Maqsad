import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class SimpleEncryption {
    public static void main(String[] args) throws Exception {
        // Create a secret key
        KeyGenerator keyG = KeyGenerator.getInstance("AES");
        keyG.init(128);
        SecretKey secretKey = keyG.generateKey();

        String data = "UserCard=4111111111111111";

        // Encrypt
        Cipher encryptor = Cipher.getInstance("AES");
        encryptor.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] enc = encryptor.doFinal(data.getBytes());
        System.out.println("Encrypted: " + Base64.getEncoder().encodeToString(enc));

        // Decrypt
        encryptor.init(Cipher.DECRYPT_MODE, secretKey);
        String decryptedData = new String(encryptor.doFinal(enc));
        System.out.println("Decrypted: " + decryptedData);

    }
}
