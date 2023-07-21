import lombok.extern.slf4j.Slf4j;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

/**
 * @author travistran
 */
@Slf4j
public class TravisAES {

    private static final String AES = "AES";
    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String KEY_ALGORITHM = "PBKDF2WithHmacSHA1";
    private static final int IV_SIZE = 128;
    private static final int IV_LENGTH = IV_SIZE / 4;
    private int keySize = 256;
    private int iterationCount = 1989;
    private DataTypeEnum dataType = DataTypeEnum.BASE64;
    private Cipher cipher;
    private int saltLength;

    public TravisAES() {
        try {
            cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            saltLength = this.keySize / 4;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            log.error(e.getMessage(), e);
        }
    }

    public TravisAES(int keySize, int iterationCount) {
        this.keySize = keySize;
        this.iterationCount = iterationCount;
        try {
            cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            saltLength = this.keySize / 4;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            log.error(e.getMessage(), e);
        }
    }

    private static byte[] generateRandom(int length) {
        SecureRandom random = new SecureRandom();
        byte[] randomBytes = new byte[length];
        random.nextBytes(randomBytes);
        return randomBytes;
    }

    private static byte[] fromBase64(String str) {
        return DatatypeConverter.parseBase64Binary(str);
    }

    private static String toBase64(byte[] ba) {
        return DatatypeConverter.printBase64Binary(ba);
    }

    private static byte[] fromHex(String str) {
        return DatatypeConverter.parseHexBinary(str);
    }

    private static String toHex(byte[] ba) {
        return DatatypeConverter.printHexBinary(ba);
    }

    public String encrypt(String salt, String iv, String passPhrase, String plainText) {
        try {
            SecretKey key = generateKey(salt, passPhrase);
            byte[] encrypted = doFinal(Cipher.ENCRYPT_MODE, key, iv, plainText.getBytes(StandardCharsets.UTF_8));
            String cipherText;
            if (dataType.equals(DataTypeEnum.HEX)) {
                cipherText = toHex(encrypted);
            } else {
                cipherText = toBase64(encrypted);
            }
            return cipherText;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }

    public String encrypt(String passphrase, String plainText) {
        try {
            String salt = toHex(generateRandom(keySize / 8));
            String iv = toHex(generateRandom(IV_SIZE / 8));
            String cipherText = encrypt(salt, iv, passphrase, plainText);
            return salt + iv + cipherText;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }

    public String decrypt(String salt, String iv, String passPhrase, String cipherText) {
        try {
            SecretKey key = generateKey(salt, passPhrase);
            byte[] encrypted;
            if (dataType.equals(DataTypeEnum.HEX)) {
                encrypted = fromHex(cipherText);
            } else {
                encrypted = fromBase64(cipherText);
            }
            byte[] decrypted = doFinal(Cipher.DECRYPT_MODE, key, iv, encrypted);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }

    public String decrypt(String passPhrase, String cipherText) {
        try {
            String salt = cipherText.substring(0, saltLength);
            String iv = cipherText.substring(saltLength, saltLength + IV_LENGTH);
            String ct = cipherText.substring(saltLength + IV_LENGTH);
            return decrypt(salt, iv, passPhrase, ct);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }

    private byte[] doFinal(int encryptMode, SecretKey key, String iv, byte[] bytes) {
        try {
            cipher.init(encryptMode, key, new IvParameterSpec(fromHex(iv)));
            return cipher.doFinal(bytes);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException |
                 BadPaddingException e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }

    private SecretKey generateKey(String salt, String passphrase) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_ALGORITHM);
            KeySpec spec = new PBEKeySpec(passphrase.toCharArray(), fromHex(salt), iterationCount, keySize);
            return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), AES);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }

    public DataTypeEnum getDataType() {
        return dataType;
    }

    public void setDataType(DataTypeEnum dataType) {
        this.dataType = dataType;
    }

    public enum DataTypeEnum {
        HEX,
        BASE64,
    }
}
