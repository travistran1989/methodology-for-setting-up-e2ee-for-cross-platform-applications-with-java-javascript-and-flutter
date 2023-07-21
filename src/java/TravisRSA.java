import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @author travistran
 */
@Slf4j
@Getter
@Setter
public class TravisRSA implements Serializable {

    private static final String RSA = "RSA";
    private static final String RSA_ECB_PKCS1PADDING = "RSA/ECB/PKCS1Padding";
    private static final String RSA_ECB_OAEPWITHSHA1ANDMGF1PADDING = "RSA/ECB/OAEPWithSHA1AndMGF1Padding";
    private DataTypeEnum dataType = DataTypeEnum.BASE64;
    private ModeEnum mode = ModeEnum.PKCS1;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public TravisRSA() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA);
            keyGen.initialize(2048);
            KeyPair pair = keyGen.generateKeyPair();
            privateKey = pair.getPrivate();
            publicKey = pair.getPublic();
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    public TravisRSA(int keySize) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA);
            keyGen.initialize(keySize);
            KeyPair pair = keyGen.generateKeyPair();
            privateKey = pair.getPrivate();
            publicKey = pair.getPublic();
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    public static String getBase64PublicKey(PublicKey publicKey) {
        return toBase64(publicKey.getEncoded());
    }

    public static String getBase64PrivateKey(PrivateKey privateKey) {
        return toBase64(privateKey.getEncoded());
    }

    public static PublicKey getPublicKey(String base64PublicKey) {
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(fromBase64(base64PublicKey));
            return KeyFactory.getInstance(RSA).generatePublic(keySpec);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return null;
    }

    public static PrivateKey getPrivateKey(String base64PrivateKey) {
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(fromBase64(base64PrivateKey));
            return KeyFactory.getInstance(RSA).generatePrivate(keySpec);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return null;
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

    public byte[] encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = getCipher();
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
    }

    public byte[] decrypt(byte[] cipherText, PrivateKey privateKey) throws Exception {
        Cipher cipher = getCipher();
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(cipherText);
    }

    public String encrypt(String plainText, String base64PublicKey) throws Exception {
        byte[] cipherText = encrypt(plainText, getPublicKey(base64PublicKey));
        if (DataTypeEnum.BASE64.equals(dataType)) {
            return toBase64(cipherText);
        } else {
            return toHex(cipherText);
        }
    }

    public String decrypt(String cipherText, String base64PrivateKey) throws Exception {
        byte[] cipherBytes;
        if (DataTypeEnum.BASE64.equals(dataType)) {
            cipherBytes = fromBase64(cipherText);
        } else {
            cipherBytes = fromHex(cipherText);
        }
        return new String(decrypt(cipherBytes, getPrivateKey(base64PrivateKey)), StandardCharsets.UTF_8);
    }

    public String encrypt(String plainText) throws Exception {
        return encrypt(plainText, getBase64PublicKey(publicKey));
    }

    public String decrypt(String cipherText) throws Exception {
        return decrypt(cipherText, getBase64PrivateKey(privateKey));
    }

    private Cipher getCipher() throws Exception {
        if (ModeEnum.OAEP.equals(mode)) {
            return Cipher.getInstance(RSA_ECB_OAEPWITHSHA1ANDMGF1PADDING, new BouncyCastleProvider());
        } else {
            return Cipher.getInstance(RSA_ECB_PKCS1PADDING);
        }
    }

    public enum ModeEnum {
        PKCS1,
        OAEP,
    }

    public enum DataTypeEnum {
        HEX,
        BASE64,
    }
}
