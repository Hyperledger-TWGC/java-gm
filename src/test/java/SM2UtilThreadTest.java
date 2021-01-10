import java.security.*;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;


/**
 * @author Sam
 * @Description: 国密算法SM2工具类线程安全测试
 * @date 2021/1/10
 */
@FixMethodOrder(MethodSorters.JVM)
public class SM2UtilThreadTest {

    static String exceptionHappened = "Exception happened";
    static int randomData = 128;
    static byte[] message = RandomStringUtils.random(randomData).getBytes();
    PublicKey pubKey;
    PrivateKey privKey;
    KeyPair keyPair;

    @Test
    public void threadSafeEncryptDecrypt() {
        try {
            Queue<byte[]> results = new ConcurrentLinkedQueue<byte[]>();
            Queue<Exception> ex = new ConcurrentLinkedQueue<Exception>();
            SM2Util instance = new SM2Util();
            this.keyPair = instance.generatekeyPair();
            this.pubKey = keyPair.getPublic();
            this.privKey = keyPair.getPrivate();
            byte[] encrypted = instance.encrypt(this.pubKey, message);
            byte[] rs = instance.decrypt(this.privKey, encrypted);
            Assert.assertEquals(new String(message), new String(rs));
            for (int i = 0; i < 300; i++) {
                new Thread(() -> {
                    try {
                        results.add(instance.decrypt(this.privKey, encrypted));
                    } catch (InvalidCipherTextException e) {
                        ex.add(e);
                    }
                }).start();
            }
            Thread.sleep(5000);
            while (!ex.isEmpty()) {
                Exception e =  ex.poll();
                e.printStackTrace();
                Assert.fail(exceptionHappened);
            }
            Assert.assertTrue(results.size() == 300);
            while (!results.isEmpty()) {
                rs = results.poll();
                Assert.assertEquals(new String(message), new String(rs));
            }
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail(exceptionHappened);
        }
    }

    @Test
    public void threadSafeSignVerify() {
        try {
            Queue<Boolean> results = new ConcurrentLinkedQueue<Boolean>();
            SM2Util instance = new SM2Util();
            this.keyPair = instance.generatekeyPair();
            this.pubKey = keyPair.getPublic();
            this.privKey = keyPair.getPrivate();
            byte[] signbyte = instance.sign(this.privKey, message);
            boolean rs = instance.verify(this.pubKey, message, signbyte);
            Assert.assertTrue(rs);
            for (int i = 0; i < 300; i++) {
                new Thread(() -> {
                        try {
                            results.add(instance.verify(this.pubKey, message, signbyte));
                        } catch (InvalidKeyException e) {
                            e.printStackTrace();
                        } catch (SignatureException e) {
                            e.printStackTrace();
                        }
                }).start();
            }
            Thread.sleep(5000);
            Assert.assertTrue(results.size() == 300);
            while (!results.isEmpty()) {
                Assert.assertTrue(results.poll());
            }
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail(exceptionHappened);
        }
    }

}