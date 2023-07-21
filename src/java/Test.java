import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.Phonenumber;
import lombok.experimental.ExtensionMethod;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import pibase.spring.core.util.encryption.TravisAES;
import pibase.spring.core.util.encryption.TravisRSA;

import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author travistran
 */
@Slf4j
public class Test {

    public static void main(String[] args) throws Exception {
        encryption();
    }

    public static void encryption() throws Exception {
        log.info("First: Mobile login then get PublicKey from response");
        TravisRSA sRsa = new TravisRSA();
        String sPrivateKey = TravisRSA.getBase64PrivateKey(sRsa.getPrivateKey());
        log.info("sPrivateKey: {}", sPrivateKey);
        String sPublicKey = TravisRSA.getBase64PublicKey(sRsa.getPublicKey());
        log.info("sPublicKey: {}", sPublicKey);

//        String sPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhugDOY1w1mJ3jo09ahsHuNh/hGdJIfzURymXoRfbjvyPpqv7asguvsOrd20s+oaDP6TqX1anNvKdOsXEooo0xO2TTjlMJZ5I7z9llw4HdC1opxtRDcdyqONbXNeMKSh8df4bSrR5EaL+AJ+0ehVytC0Uoxm2sJIk3cn1NQydXL+AToTfY6UaZepsO1CWXU/sbp8w9FgsKHz2g8yWkvVHICI7XzjzMPRnN1ceFckbybghaNC8cIrywrnoS2AJIQ1mCWdJ4sbahInJVEVA0xmBlqT/JzDTdXtF3wLs46MKnyPk+8UlkXHoLlh5N5y4GkUrEWPl/jBZ2EEgDSizXV8PrQIDAQAB";

        log.info("Second: Mobile generate a SecretKey then encrypt request payload using AES algorithm with\n" +
            "the SecretKey. After that, use the PublicKey to encrypt the SecretKey using RSA algorithm.\n" +
            "At the end, Mobile combine two encrypted data into following structure:\n" +
            "{\n" +
            "\"secret\": \"encrypted data of the SecretKey\",\n" +
            "\"data\": \"encrypted data of the request payload\"\n" +
            "}");
        String mSecretKey = "randomPassword";
        log.info("mSecretKey: {}", mSecretKey);

//        String mSecretKey = "UaZ{jKTSKE98";

        TravisAES mAes = new TravisAES();
        String mEncryptedRequestPayload = mAes.encrypt(mSecretKey, "{" +
            "\"id\":\"6450acd78cc2725a65268ef3\"," +
            "\"token\":\"1234\"," +
            "\"deviceId\":\"6450acd78cc2725a65268ef3\"" +
            "}");
        log.info("mEncryptedRequestPayload: {}", mEncryptedRequestPayload);
        TravisRSA mRsa = new TravisRSA();
        String mEncryptedSecret = mRsa.encrypt(mSecretKey, sPublicKey);
        log.info("mEncryptedSecret: {}", mEncryptedSecret);
        // This is the actual request payload that mobile put to the request body.
        Map<String, String> mRequestPayload = new HashMap<>();
        mRequestPayload.put("secret", mEncryptedSecret);
        mRequestPayload.put("data", mEncryptedRequestPayload);
        log.info("mRequestPayload: {}", mRequestPayload);

        log.info("Third: Server decode the data and return encrypted response data to Mobile");
        // Decrypt to get the SecretKey of the mobile
        String sDecryptedSecret = sRsa.decrypt(mRequestPayload.get("secret"), sPrivateKey);

        log.info("sDecryptedSecret: {}", sDecryptedSecret);
        // Decrypt to get the plain payload of the mobile
        TravisAES sAes = new TravisAES();
        String plainPayload = sAes.decrypt(sDecryptedSecret, mRequestPayload.get("data"));
        log.info("plainPayload: {}", plainPayload);
        // Encrypt the plainPayload as a response message to return back to the mobile
        String sEncryptedResponse = sAes.encrypt(sDecryptedSecret, plainPayload);
        log.info("sEncryptedResponse: {}", sEncryptedResponse);

//        String sEncryptedResponse = "AECB68BFCCF07D2FFBA50008F43080D1847026FB6387FE0CB079E25088DBB6FC064D236F844AFA771139AB09B1FDEBAEsCDMhurqHBN2dRCeC+I2RNu6rSOGroTrgzzxqtwPigybcRaZu9/c/NzWRvSfLatZdc909GheeHT+BYHaSQdpG2bU7cmVgK/wdFuNzC0t6XouZg206NTi4NO1pIbbkSU8";

        log.info("Fourth: Mobile decrypt the response body to get the server message");
        String mResponseMessage = mAes.decrypt(mSecretKey, sEncryptedResponse);
        log.info("mResponseMessage: {}", mResponseMessage);
    }

}
