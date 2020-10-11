import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import javax.security.auth.x500.X500Principal;

import org.junit.Assert;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;


@FixMethodOrder(MethodSorters.JVM)
public class SM2UtilTest {

    static String pubFileName = "pub.pem";
    static String privFileName = "priv.pem";

    @Before
    @Test
    public void generateFile() {
        Throwable t = null;
        try {
            KeyPair keyPair = SM2Util.generatekeyPair();
            SM2Util.saveKeyPairInPem(keyPair, pubFileName, privFileName);
            SM2Util.saveCSRInPem(SM2Util.generatekeyPair(), new X500Principal("C=CN"), "req.pem");
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
        Assert.assertEquals(null, t);
    }
    //encrypt and decrypt
    @Test
    public void encryptAnddecrypt() {
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
        Assert.assertEquals(null, t);
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
            Assert.assertEquals(true, rs);
        } catch (Exception e) {
            t = e;
            e.printStackTrace();
        }
        Assert.assertEquals(null, t);
    }
}