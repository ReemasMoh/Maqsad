import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class SimpleEncryption {

    private static SecretKey generateKey() throws Exception {
        KeyGenerator keyG = KeyGenerator.getInstance("AES");
        keyG.init(128);
        return keyG.generateKey();
    }

    public static String encrypt(SecretKey key, String data) throws Exception {
        Cipher encryptor = Cipher.getInstance("AES");
        encryptor.init(Cipher.ENCRYPT_MODE, key);
        byte[] enc = encryptor.doFinal(data.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(enc);
    }

    public static String decrypt(SecretKey key, String encryptedData) throws Exception {
        Cipher encryptor = Cipher.getInstance("AES");
        encryptor.init(Cipher.DECRYPT_MODE, key);
        byte[] enc = Base64.getDecoder().decode(encryptedData);
        return new String(encryptor.doFinal(enc), "UTF-8");
    }
    
    public static void main(String[] args) throws Exception {
        SecretKey secretKey = generateKey();
        String data = "UserCard=4111111111111111";

        String encrypted = encrypt(secretKey, data);
        System.out.println("Encrypted: " + encrypted);

        String decrypted = decrypt(secretKey, encrypted);
        System.out.println("Decrypted: " + decrypted);
    }
}
