import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Assert;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import twgc.gm.random.CertSNAllocator;
import twgc.gm.random.RandomSNAllocator;
import twgc.gm.sm2.SM2Util;
import twgc.gm.sm2.SM2X509CertFactory;
import twgc.gm.sm2.pool.SM2EnginePool;


@FixMethodOrder(MethodSorters.JVM)
public class SM2UtilTest {

    static String pubFileName = "pub.pem";
    static String privFileName = "priv.pem";
    static String encryptedprivFileName = "encryptedpriv.pem";
    static String reqFileName = "req.pem";
    static String certFileName = "cert.pem";
    static String exceptionHappened = "Exception happened";
    static String keyEqualHint = "key should be equal";
    static String passwd = RandomStringUtils.random(18);
    static int randomData = 128;
    static byte[] message = RandomStringUtils.random(randomData).getBytes();
    PublicKey pubKey;
    PrivateKey privKey;
    X509Certificate x509Certificate;
    KeyPair keyPair;

    public static void saveCSRInPem(PKCS10CertificationRequest csr, String csrFile) throws IOException, OperatorCreationException {
        String csrPem = SM2Util.pemFrom(csr);
        Files.write(Paths.get(csrFile), csrPem.getBytes());
    }

    public static void saveCertificateInPem(X509Certificate x509Certificate, String certFileName) throws Exception {
        String certStr = SM2Util.pemFrom(x509Certificate);
        Files.write(Paths.get(certFileName), certStr.getBytes());
    }

    public static X509Certificate genCertificate(KeyPair keyPair, PKCS10CertificationRequest csr, X500Name x500Name) throws Exception {
        long certExpire = 20L * 365 * 24 * 60 * 60 * 1000;
        CertSNAllocator snAllocator = new RandomSNAllocator();
        SM2X509CertFactory rootCertFactory = new SM2X509CertFactory(keyPair, x500Name);
        Date now = new Date();
        return rootCertFactory.rootCACert(csr.getEncoded(),
                "test@twgc.com",
                snAllocator.nextSerialNumber(),
                now,
                new Date(now.getDate() + certExpire));
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
        File certFile = new File(certFileName);
        try {
            if (!pubFile.exists()) {
                SM2Util instance = new SM2Util();
                this.keyPair = instance.generatekeyPair();
                saveKeyPairInPem(this.keyPair, pubFileName, privFileName);

                X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
                X500Name x500Name = builder.addRDN(BCStyle.CN, "Root CA").build();
                // gen csr && save
                PKCS10CertificationRequest csr = SM2Util.generateCSR(keyPair, new X500Principal(String.valueOf(x500Name)));
                saveCSRInPem(csr, reqFileName);
                // gen cert && save
                X509Certificate x509Certificate = genCertificate(keyPair, csr, x500Name);
                saveCertificateInPem(x509Certificate, certFileName);
            } else {
                System.out.println("Skip file generation deal to interact testing.");
            }
            this.pubKey = SM2Util.loadPublicFromFile(pubFileName);
            Assert.assertNotNull(this.pubKey);
            this.privKey = SM2Util.loadPrivFromFile(privFileName, "");
            Assert.assertNotNull(this.privKey);
            this.x509Certificate = SM2Util.loadX509CertificateFromFile(certFileName);
            Assert.assertNotNull(this.x509Certificate);
            Assert.assertEquals("SM3WITHSM2", this.x509Certificate.getSigAlgName());
            if (!pubFile.exists()) {
                Assert.assertEquals(keyEqualHint, this.keyPair.getPublic(), this.pubKey);
                Assert.assertEquals(keyEqualHint, this.keyPair.getPrivate(), this.privKey);
            }
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail(exceptionHappened);
        }
        Assert.assertTrue(pubFile.exists());
        Assert.assertTrue(privFile.exists());
        Assert.assertTrue(reqFile.exists());
        Assert.assertTrue(certFile.exists());
    }

    //encrypt and decrypt
    @Test
    public void encryptAndDecryptC1C3C2() {
        SM2EnginePool sm2EnginePool = new SM2EnginePool(1, SM2Engine.Mode.C1C3C2);
        SM2Engine sm2Engine = null;
        try {
            SM2Util instance = new SM2Util();
            sm2Engine = sm2EnginePool.borrowObject();
            byte[] encrypted = instance.encrypt(sm2Engine, this.pubKey, message);
            byte[] rs = instance.decrypt(sm2Engine, this.privKey, encrypted);
            Assert.assertEquals(new String(message), new String(rs));
            byte[] encrypted2 = instance.encrypt(sm2Engine, this.pubKey, "msg".getBytes());
            rs = instance.decrypt(sm2Engine, this.privKey, encrypted2);
            Assert.assertNotEquals(new String(message), new String(rs));
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail(exceptionHappened);
        } finally {
            if (sm2Engine != null) {
                sm2EnginePool.returnObject(sm2Engine);
            }
        }
    }

    //encrypt and decrypt
    @Test
    public void encryptAndDecryptC1C2C3() {
        SM2EnginePool sm2EnginePool = new SM2EnginePool(1, SM2Engine.Mode.C1C2C3);
        SM2Engine sm2Engine = null;
        try {
            SM2Util instance = new SM2Util();
            sm2Engine = sm2EnginePool.borrowObject();
            byte[] encrypted = instance.encrypt(sm2Engine, this.pubKey, message);
            byte[] rs = instance.decrypt(sm2Engine, this.privKey, encrypted);
            Assert.assertEquals(new String(message), new String(rs));
            byte[] encrypted2 = instance.encrypt(sm2Engine, this.pubKey, "msg".getBytes());
            rs = instance.decrypt(sm2Engine, this.privKey, encrypted2);
            Assert.assertNotEquals(new String(message), new String(rs));
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail(exceptionHappened);
        } finally {
            if (sm2Engine != null) {
                sm2EnginePool.returnObject(sm2Engine);
            }
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

    @Test
    public void issueCertificate() throws Exception {

        SM2Util sm2Util = new SM2Util();
        // 证书颁发时长
        long certExpire = 20L * 365 * 24 * 60 * 60 * 1000;
        CertSNAllocator snAllocator = new RandomSNAllocator();

        // one 模拟根 CA 自签名生成根证书 rootCACert
        KeyPair rootKeyPair = sm2Util.generatekeyPair();
        X500Name rootX500Name = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, "Root CA").build();
        SM2X509CertFactory rootCertMaker = new SM2X509CertFactory(rootKeyPair, rootX500Name);
        PublicKey rootKeyPairPublic = rootKeyPair.getPublic();
        byte[] rootcsr = SM2Util.generateCSR(rootKeyPair, new X500Principal(String.valueOf(rootX500Name))).getEncoded();
        Date now = new Date();
        X509Certificate rootCACert = rootCertMaker.rootCACert(rootcsr,
                "test@twgc.com",
                snAllocator.nextSerialNumber(),
                now,
                new Date(now.getDate() + certExpire));

        // two 模拟根 CA 生成中间证书
        KeyPair midKeyPair = sm2Util.generatekeyPair();
        PublicKey midKeyPairPublic = midKeyPair.getPublic();
        X500Name midX500Name = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, "Intermediate CA").build();
        byte[] midcsr = SM2Util.generateCSR(midKeyPair, new X500Principal(String.valueOf(midX500Name))).getEncoded();
        X509Certificate midCACert = rootCertMaker.subCACert(midcsr,
                "test1@twgc.com",
                snAllocator.nextSerialNumber(),
                now,
                new Date(now.getDate() + certExpire)
        );

        // three 模拟中间 CA 生成用户证书
        SM2X509CertFactory midCertMaker = new SM2X509CertFactory(midKeyPair, midX500Name);
        KeyPair userKeyPair = sm2Util.generatekeyPair();
        X500Name userX500Name = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, "User CA").build();
        byte[] usercsr = SM2Util.generateCSR(userKeyPair, new X500Principal(String.valueOf(userX500Name))).getEncoded();
        X509Certificate userCACert = midCertMaker.subCACert(usercsr,
                "test2@twgc.com",
                snAllocator.nextSerialNumber(),
                now,
                new Date(now.getDate() + certExpire));

        // 根证书自签名，用自己的公钥验证
        rootCACert.verify(rootKeyPairPublic, BouncyCastleProvider.PROVIDER_NAME);
        // 中间证书可用根证书的公钥验证
        midCACert.verify(rootKeyPairPublic, BouncyCastleProvider.PROVIDER_NAME);
        // 用户证书可用中间证书的公钥验证
        userCACert.verify(midKeyPairPublic, BouncyCastleProvider.PROVIDER_NAME);

    }

    static {
        try {
            Security.addProvider(new BouncyCastleProvider());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}