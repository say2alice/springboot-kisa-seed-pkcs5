package kisa.crypto.demo;

import kisa.crypto.demo.core.KisaSeedCbcCore;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Provider;
import java.security.Security;
import java.util.Base64;

@SpringBootTest
class SeedDemoAppTests {
    private static final Logger log = LoggerFactory.getLogger(SeedDemoAppTests.class);

    private static final Charset UTF_8 = StandardCharsets.UTF_8;

    private final byte[] userKey = "EcSXmC9Uz3Q9/a2EdC9Xtg==".getBytes();
    private final byte[] decodedKey = Base64.getDecoder().decode("EcSXmC9Uz3Q9/a2EdC9Xtg==");
    private final byte[] initVec = "CASINICASTEST000".getBytes();

    private final SecretKeySpec secKey = new SecretKeySpec(decodedKey, "SEED");
    private final IvParameterSpec ivSpec = new IvParameterSpec(initVec);

    @Test
    public void SeedCryptoTest() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Provider provider = Security.getProvider("BC");

        String rawMessage = "테스트 데이터";
        log.debug("원본 데이터 => {}", rawMessage);

        String encodedEncryptedMessage = encrypt(rawMessage);
        log.debug("암호화된 데이터 => {}", encrypt(rawMessage));
        log.debug("복호화된 데이터 => {}\n", decrypt(encodedEncryptedMessage));

        try {
            Cipher cipher = Cipher.getInstance("SEED/CBC/PKCS5Padding", provider);

            String srcString = "이상하군..";
            String encString = seedEncrypt(cipher, srcString, "utf-8");

            log.debug("seed enc => {}", encString);
            log.debug("seed dec => {}\n", seedDecrypt(cipher, encString, "utf-8"));

            log.debug("seed dec => {}", seedDecrypt(cipher, "2WcgInahsPi83SMc8PVu/Q==", "euc-kr"));
            log.debug("seed dec => {}", seedDecrypt(cipher, "GKmeiByNjbRfODw+YoZX9w==", "euc-kr"));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String encrypt(String rawMessage) {
        return Base64.getEncoder().encodeToString(
                KisaSeedCbcCore.SEED_CBC_Encrypt(
                        userKey,
                        initVec,
                        rawMessage.getBytes(UTF_8),
                        0,
                        rawMessage.getBytes().length
                )
        );
    }

    private String decrypt(String b64edEncryptMessage) {
        byte[] decodedEncryptedMessage =  Base64.getDecoder().decode(b64edEncryptMessage);

        return new String(
                KisaSeedCbcCore.SEED_CBC_Decrypt(
                        userKey,
                        initVec,
                        decodedEncryptedMessage,
                        0,
                        decodedEncryptedMessage.length
                ), UTF_8
        );
    }

    private String seedEncrypt(Cipher cipher, String srcString, String characterSet)
            throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
        byte[] decryptedMessage;
        cipher.init(Cipher.ENCRYPT_MODE, secKey, ivSpec);
        decryptedMessage = cipher.doFinal(srcString.getBytes(characterSet));

        return Base64.getEncoder().encodeToString(decryptedMessage);
    }

    private String seedDecrypt(Cipher cipher, String encString, String characterSet)
            throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
        byte[] decodedEncryptedMessage = Base64.getDecoder().decode(encString);
        cipher.init(Cipher.DECRYPT_MODE, secKey, ivSpec);

        return new String(cipher.doFinal(decodedEncryptedMessage), characterSet);
    }

}
