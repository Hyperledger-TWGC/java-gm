import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.junit.Assert;
import org.junit.Test;
import twgc.gm.pool.SM3DigestPool;
import twgc.gm.sm2.SM2Util;
import twgc.gm.sm2sm3.SM2SM3Util;
import twgc.gm.sm3.SM3Util;

import static org.junit.Assert.*;

public class SM2SM3UtilThreadTest {

    static int randomData = 128;
    static byte[] message = RandomStringUtils.random(randomData).getBytes();

    static SM3DigestPool sm3DigestPool;

    PublicKey pubKey;
    PrivateKey privKey;
    KeyPair keyPair;

    static {
        try {
            sm3DigestPool = new SM3DigestPool();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    static String exceptionHappened = "Exception happened";

    @Test
    public void threadSafe() throws Exception {
        Queue<Boolean> results = new ConcurrentLinkedQueue<>();
        Queue<Exception> ex = new ConcurrentLinkedQueue<>();
        SM3Digest sm3Digest = null;

        SM2Util sm2instance = new SM2Util();
        this.keyPair = sm2instance.generatekeyPair();
        this.pubKey = keyPair.getPublic();
        this.privKey = keyPair.getPrivate();

        SM2SM3Util instance = new SM2SM3Util();
        byte[] signresult = null;
        try {
            sm3Digest = sm3DigestPool.borrowObject();
            signresult = instance.digestAndSign(sm3Digest, this.privKey, message);
            Assert.assertTrue(instance.verifySignatureAndDigest(sm3Digest, this.pubKey, message, signresult));
        } finally {
            if (sm3Digest != null) {
                sm3DigestPool.returnObject(sm3Digest);
            }
        }

        for (int i = 0; i < 300; i++) {
            new Thread(() -> {
                SM3Digest sm3DigestInThead = null;
                try {
                    sm3DigestInThead = sm3DigestPool.borrowObject();
                    byte[] result = instance.digestAndSign(sm3DigestInThead, this.privKey, message);
                    results.add(instance.verifySignatureAndDigest(sm3DigestInThead, this.pubKey, message, result));
                } catch (Exception e) {
                    ex.add(e);
                } finally {
                    if (sm3DigestInThead != null) {
                        sm3DigestPool.returnObject(sm3DigestInThead);
                    }
                }
            }).start();
        }
        while (!ex.isEmpty()) {
            Exception e = ex.poll();
            e.printStackTrace();
            Assert.fail(exceptionHappened);
        }
        Thread.sleep(5000);
        Assert.assertEquals(300, results.size());
        while (!results.isEmpty()) {
            Assert.assertTrue(results.poll());
        }
    }
}