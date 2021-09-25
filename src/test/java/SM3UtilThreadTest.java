import java.io.IOException;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.junit.Assert;
import org.junit.Test;
import twgc.gm.pool.SM3DigestPool;
import twgc.gm.sm3.SM3Util;


/**
 * @author Sam
 * @Description: 国密算法SM3工具类线程安全测试
 * @date 2021/1/10
 */
public class SM3UtilThreadTest {

    static int randomData = 128;
    static byte[] message = RandomStringUtils.random(randomData).getBytes();

    static SM3DigestPool sm3DigestPool;

    static {
        try {
            sm3DigestPool = new SM3DigestPool();
            System.out.println("maxTotal=" + sm3DigestPool.getMaxTotal() + ", maxIdle=" + sm3DigestPool.getMaxIdle() + ", minIdle=" + sm3DigestPool.getMinIdle());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    static String exceptionHappened = "Exception happened";

    @Test
    public void hashAndVerify() throws Exception {
        Queue<Boolean> results = new ConcurrentLinkedQueue<>();
        Queue<Exception> ex = new ConcurrentLinkedQueue<>();
        SM3Digest sm3Digest = null;
        try {
            sm3Digest = sm3DigestPool.borrowObject();
            byte[] hashVal = SM3Util.hash(sm3Digest, message);
            Assert.assertTrue(SM3Util.verify(sm3Digest, message, hashVal));
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
                    byte[] hashValInThread = SM3Util.hash(sm3DigestInThead, message);
                    results.add(SM3Util.verify(sm3DigestInThead, message, hashValInThread));
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
            Exception e =  ex.poll();
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