import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterInputStream;

public class AESWithCompressionAndFHSS {

    // Frequency hopping frequencies (MHz)
    private static final int[] FREQUENCIES = {100, 200, 300};
    private static int currentFrequencyIndex = 0;

    /**
     * Simulate a frequency hop (for logging/demo purposes).
     */
    private static void hopFrequency() {
        currentFrequencyIndex = (currentFrequencyIndex + 1) % FREQUENCIES.length;
        System.out.println("Hopping to frequency: " + FREQUENCIES[currentFrequencyIndex] + " MHz");
    }

    /**
     * Generates a random 128-bit AES key.
     */
    public static SecretKey generateSecretKey() {
        byte[] keyBytes = new byte[16];
        new SecureRandom().nextBytes(keyBytes);
        return new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * Compresses data using DEFLATE.
     */
    public static byte[] compress(byte[] data) throws Exception {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             DeflaterOutputStream dos = new DeflaterOutputStream(baos)) {
            dos.write(data);
            dos.finish();
            return baos.toByteArray();
        }
    }

    /**
     * Decompresses data previously compressed with compress().
     */
    public static byte[] decompress(byte[] compressedData) throws Exception {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(compressedData);
             InflaterInputStream iis = new InflaterInputStream(bais);
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int len;
            while ((len = iis.read(buffer)) > 0) {
                baos.write(buffer, 0, len);
            }
            return baos.toByteArray();
        }
    }

    /**
     * Encrypts plaintext with AES/CBC/PKCS5Padding. Prepend IV to ciphertext.
     */
    public static byte[] encrypt(byte[] plaintext, SecretKey key) throws Exception {
        hopFrequency(); // log FHSS hop
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[cipher.getBlockSize()];
        new SecureRandom().nextBytes(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        byte[] ciphertext = cipher.doFinal(plaintext);

        // Prepend IV
        ByteArrayOutputStream out = new ByteArrayOutputStream(iv.length + ciphertext.length);
        out.write(iv);
        out.write(ciphertext);
        return out.toByteArray();
    }

    /**
     * Decrypts ciphertext previously returned by encrypt().
     */
    public static byte[] decrypt(byte[] ivPlusCiphertext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        int blockSize = cipher.getBlockSize();

        byte[] iv = new byte[blockSize];
        byte[] ciphertext = new byte[ivPlusCiphertext.length - blockSize];

        System.arraycopy(ivPlusCiphertext, 0, iv, 0, blockSize);
        System.arraycopy(ivPlusCiphertext, blockSize, ciphertext, 0, ciphertext.length);

        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(ciphertext);
    }

    public static void main(String[] args) throws Exception {
        String plaintext = "This is a sample plaintext for encryption.";

        // Generate AES key
        SecretKey key = generateSecretKey();

        // Compress
        byte[] compressed = compress(plaintext.getBytes("UTF-8"));

        // Encrypt (with FHSS hop log)
        byte[] encrypted = encrypt(compressed, key);

        // Decrypt
        byte[] decryptedCompressed = decrypt(encrypted, key);

        // Decompress
        byte[] result = decompress(decryptedCompressed);

        System.out.println("Original : " + plaintext);
        System.out.println("Recovered: " + new String(result, "UTF-8"));
    }
}
