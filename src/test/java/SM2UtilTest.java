import java.security.KeyPair;
import java.security.Signature;

import org.junit.Assert;
import org.junit.Test;

public class SM2UtilTest {

    @Test
    public void generateCsr() {
        Throwable t = null;
        try {
            SM2Util.generateCsr(false);
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
            KeyPair keyPair = SM2Util.generatekeyPair();
            byte[] message = "hello,world!".getBytes();
            byte[] encrypted = SM2Util.encrypt(keyPair.getPublic(), message);
            byte[] rs = SM2Util.decrypt(keyPair.getPrivate(), encrypted);
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
            KeyPair keyPair = SM2Util.generatekeyPair();
            Signature signature = SM2Util.generateSignature();
            byte[] message = "hello,world!".getBytes();
            byte[] signbyte = SM2Util.sign(signature, keyPair.getPrivate(), message);
            boolean rs = SM2Util.verify(signature, keyPair.getPublic(), message, signbyte);
            Assert.assertEquals(true, rs);
        } catch (Exception e) {
            t = e;
            e.printStackTrace();
        }
        Assert.assertEquals(null, t);
    }
}