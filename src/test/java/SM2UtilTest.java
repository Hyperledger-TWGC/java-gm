import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Assert;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;


@FixMethodOrder(MethodSorters.JVM)
public class SM2UtilTest {

    static String pubFileName = "pub.pem";
    static String privFileName = "priv.pem";
    static String encryptedprivFileName = "encryptedpriv.pem";
    static String reqFileName = "req.pem";
    static String exceptionHappened = "Exception happened";
    static String keyEqualHint = "key should be equal";
    static String passwd = RandomStringUtils.random(18);
    static int randomData = 128;
    static byte[] message = RandomStringUtils.random(randomData).getBytes();
    PublicKey pubKey;
    PrivateKey privKey;
    KeyPair keyPair;

    public static void saveCSRInPem(KeyPair keyPair, X500Principal subject, String csrFile) throws IOException, OperatorCreationException {
        PKCS10CertificationRequest csr = SM2Util.generateCSR(keyPair, subject);
        String csrPem = SM2Util.pemFrom(csr);
        Files.write(Paths.get(csrFile), csrPem.getBytes());
    }

    public static void savePemFormatKeyFile(PrivateKey privateKey, String filename) throws IOException, OperatorCreationException {
        String privateKeyPem = SM2Util.pemFrom(privateKey, "");
        Files.write(Paths.get(filename), privateKeyPem.getBytes());
    }

    public static void savePemFormatPubKeyFile(PublicKey publicKey, String filename) throws IOException {
        String pubKeyPem = SM2Util.pemFrom(publicKey);
        Files.write(Paths.get(filename), pubKeyPem.getBytes());
    }

    public static void saveKeyPairInPem(KeyPair keyPair, String pubFileName, String privFileName) throws IOException, OperatorCreationException {
        savePemFormatKeyFile(keyPair.getPrivate(), privFileName);
        savePemFormatPubKeyFile(keyPair.getPublic(), pubFileName);
    }

    @Before
    @Test
    public void generateFile() {
        File pubFile = new File(pubFileName);
        File privFile = new File(privFileName);
        File reqFile = new File(reqFileName);
        try {
            if (!pubFile.exists()) {
                this.keyPair = SM2Util.generatekeyPair();
                saveKeyPairInPem(this.keyPair, pubFileName, privFileName);
                saveCSRInPem(SM2Util.generatekeyPair(), new X500Principal("C=CN"), reqFileName);
            } else {
                System.out.println("Skip file generation deal to interact testing.");
            }
            this.pubKey = SM2Util.loadPublicFromFile(pubFileName);
            Assert.assertNotNull(this.pubKey);
            this.privKey = SM2Util.loadPrivFromFile(privFileName, "");
            Assert.assertNotNull(this.privKey);
            if (!pubFile.exists()) {
                Assert.assertEquals(keyEqualHint, this.keyPair.getPublic(), this.pubKey);
                Assert.assertEquals(keyEqualHint, this.keyPair.getPrivate(), this.privKey);
            }
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail(exceptionHappened);
        }
        Assert.assertEquals(true, pubFile.exists());
        Assert.assertEquals(true, privFile.exists());
        Assert.assertEquals(true, reqFile.exists());
    }
    //encrypt and decrypt
    @Test
    public void encryptAndDecrypt() {
        try {
            byte[] encrypted = SM2Util.encrypt(this.pubKey, message);
            byte[] rs = SM2Util.decrypt(this.privKey, encrypted);
            Assert.assertEquals(new String(message), new String(rs));
            byte[] encrypted2 = SM2Util.encrypt(this.pubKey, "msg".getBytes());
            rs = SM2Util.decrypt(this.privKey, encrypted2);
            Assert.assertNotEquals(new String(message), new String(rs));
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail(exceptionHappened);
        }
    }

    //sign and verify
    @Test
    public void signAndverify() {
        try {
            Signature signature = SM2Util.generateSignature();
            byte[] signbyte = SM2Util.sign(signature, this.privKey, message);
            boolean rs = SM2Util.verify(signature, this.pubKey, message, signbyte);
            Assert.assertTrue(rs);
            rs = SM2Util.verify(signature, this.pubKey, message, message);
            Assert.assertFalse(rs);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail(exceptionHappened);
        }
    }

    //private key Derive from private key
    @Test
    public void derivePublicFromPrivate() {
        PublicKey deriveKey = SM2Util.derivePublicFromPrivate(this.privKey);
        Assert.assertEquals(keyEqualHint, this.pubKey, deriveKey);
    }

    //key with password
    @Test
    public void keyPairWithPasswd() {
        try {
            KeyPair keyPair = SM2Util.generatekeyPair();
            String privateKeyPem = SM2Util.pemFrom(keyPair.getPrivate(), passwd);
            Files.write(Paths.get(encryptedprivFileName), privateKeyPem.getBytes());
            PrivateKey key = SM2Util.loadPrivFromFile(encryptedprivFileName, passwd);
            Assert.assertNotNull(key);
            Assert.assertEquals(keyEqualHint, keyPair.getPrivate(), key);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail(exceptionHappened);
        }
    }

}