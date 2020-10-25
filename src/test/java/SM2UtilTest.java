import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import javax.security.auth.x500.X500Principal;

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
    static String reqFileName = "req.pem";

    public static void saveCSRInPem(KeyPair keyPair, X500Principal subject, String csrFile) throws IOException, OperatorCreationException {
        PKCS10CertificationRequest csr = SM2Util.generateCSR(keyPair, subject);
        String csrPem = SM2Util.pemFrom(csr);
        Files.write(Paths.get(csrFile), csrPem.getBytes());
    }

    public static void savePemFormatKeyFile(PrivateKey privateKey, String filename) throws IOException {
        String privateKeyPem = SM2Util.pemFrom(privateKey);
        Files.write(Paths.get(filename), privateKeyPem.getBytes());
    }

    public static void savePemFormatPubKeyFile(PublicKey publicKey, String filename) throws IOException {
        String pubKeyPem = SM2Util.pemFrom(publicKey);
        Files.write(Paths.get(filename), pubKeyPem.getBytes());
    }

    public static void saveKeyPairInPem(KeyPair keyPair, String pubFileName, String privFileName) throws IOException {
        savePemFormatKeyFile(keyPair.getPrivate(), privFileName);
        savePemFormatPubKeyFile(keyPair.getPublic(), pubFileName);
    }
    @Before
    @Test
    public void generateFile() {
        File pubFile = new File(pubFileName);
        File privFile = new File(privFileName);
        File reqFile = new File(reqFileName);
        if (pubFile.exists()) {
            System.out.println("Skip file generation deal to interact testing.");
        } else {
            Throwable t = null;
            try {
                KeyPair keyPair = SM2Util.generatekeyPair();
                saveKeyPairInPem(keyPair, pubFileName, privFileName);
                saveCSRInPem(SM2Util.generatekeyPair(), new X500Principal("C=CN"), reqFileName);
                PublicKey pubKey = SM2Util.loadPublicFromFile(pubFileName);
                Assert.assertNotNull(pubKey);
                Assert.assertEquals("Public key should be equal", keyPair.getPublic(), pubKey);
                PrivateKey privKey = SM2Util.loadPrivFromFile(privFileName);
                Assert.assertNotNull(privKey);
                Assert.assertEquals("Priv key should be equal", keyPair.getPrivate(), privKey);
            } catch (Exception e) {
                t = e;
                e.printStackTrace();
            }
            Assert.assertNull(t);
        }
        Assert.assertEquals(true, pubFile.exists());
        Assert.assertEquals(true, privFile.exists());
        Assert.assertEquals(true, reqFile.exists());
    }
    //encrypt and decrypt
    @Test
    public void encryptAndDecrypt() {
        Throwable t = null;
        try {
            PublicKey pubKey = SM2Util.loadPublicFromFile(pubFileName);
            PrivateKey privKey = SM2Util.loadPrivFromFile(privFileName);
            byte[] message = "hello,world!".getBytes();
            byte[] encrypted = SM2Util.encrypt(pubKey, message);
            byte[] rs = SM2Util.decrypt(privKey, encrypted);
            Assert.assertEquals(new String(message), new String(rs));
        } catch (Exception e) {
            t = e;
            e.printStackTrace();
        }
        Assert.assertNull(t);
    }

    //sign and verify
    @Test
    public void signAndverify() {
        Throwable t = null;
        try {
            PublicKey pubKey = SM2Util.loadPublicFromFile(pubFileName);
            PrivateKey privKey = SM2Util.loadPrivFromFile(privFileName);
            Signature signature = SM2Util.generateSignature();
            byte[] message = "hello,world!".getBytes();
            byte[] signbyte = SM2Util.sign(signature, privKey, message);
            boolean rs = SM2Util.verify(signature, pubKey, message, signbyte);
            Assert.assertTrue(rs);
        } catch (Exception e) {
            t = e;
            e.printStackTrace();
        }
        Assert.assertEquals(null, t);
    }
}