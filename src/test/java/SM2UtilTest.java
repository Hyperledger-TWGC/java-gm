import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Assert;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;


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
                SM2Util instance = new SM2Util();
                this.keyPair = instance.generatekeyPair();
                saveKeyPairInPem(this.keyPair, pubFileName, privFileName);
                saveCSRInPem(this.keyPair, new X500Principal("C=CN"), reqFileName);
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
    public void encryptAndDecryptC1C3C2() {
        try {
            SM2Util instance = new SM2Util();
            byte[] encrypted = instance.encrypt(this.pubKey, message);
            byte[] rs = instance.decrypt(this.privKey, encrypted);
            Assert.assertEquals(new String(message), new String(rs));
            byte[] encrypted2 = instance.encrypt(this.pubKey, "msg".getBytes());
            rs = instance.decrypt(this.privKey, encrypted2);
            Assert.assertNotEquals(new String(message), new String(rs));
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail(exceptionHappened);
        }
    }

    //encrypt and decrypt
    @Test
    public void encryptAndDecryptC1C2C3() {
        try {
            SM2Util instance = new SM2Util();
            instance.setSm2Engine(new SM2Engine(SM2Engine.Mode.C1C2C3));
            byte[] encrypted = instance.encrypt(this.pubKey, message);
            byte[] rs = instance.decrypt(this.privKey, encrypted);
            Assert.assertEquals(new String(message), new String(rs));
            byte[] encrypted2 = instance.encrypt(this.pubKey, "msg".getBytes());
            rs = instance.decrypt(this.privKey, encrypted2);
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
            SM2Util instance = new SM2Util();
            byte[] signbyte = instance.sign(this.privKey, message);
            boolean rs = instance.verify(this.pubKey, message, signbyte);
            Assert.assertTrue(rs);
            rs = instance.verify(this.pubKey, message, message);
            Assert.assertFalse(rs);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail(exceptionHappened);
        }
    }

    //sign and verify
    //ref https://github.com/bcgit/bc-java/blob/r1rv67/prov/src/main/java/org/bouncycastle/jcajce/provider/asymmetric/GM.java
    @Test
    public void signAndverifyHash256Sample() {
        try {
            if (Security.getProvider("BC") == null) {
                Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            }
            Signature signature = Signature.getInstance("SHA256WITHSM2", "BC");
            SM2Util instance = new SM2Util();
            instance.setSignature(signature);
            byte[] signbyte = instance.sign(this.privKey, message);
            boolean rs = instance.verify(this.pubKey, message, signbyte);
            Assert.assertTrue(rs);
            rs = instance.verify(this.pubKey, message, message);
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
            SM2Util instance = new SM2Util();
            KeyPair keyPair = instance.generatekeyPair();
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