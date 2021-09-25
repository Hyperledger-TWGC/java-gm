import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;

import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import twgc.gm.pool.SM2EnginePool;
import twgc.gm.sm2.SM2Util;


/**
 * @author Sam
 * @description 国密算法SM2工具类线程安全测试
 * @date 2021/1/10
 */
@FixMethodOrder(MethodSorters.JVM)
public class SM2UtilThreadTest {

    static String exceptionHappened = "Exception happened";
    static int randomData = 128;
    static byte[] message = RandomStringUtils.random(randomData).getBytes();
    static SM2EnginePool sm2EnginePool;

    static {
        try {
            sm2EnginePool = new SM2EnginePool(SM2Engine.Mode.C1C3C2);
            System.out.println("maxTotal=" + sm2EnginePool.getMaxTotal() + ", maxIdle=" + sm2EnginePool.getMaxIdle() + ", minIdle=" + sm2EnginePool.getMinIdle());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    PublicKey pubKey;
    PrivateKey privKey;
    KeyPair keyPair;

    @Test
    public void threadSafeEncryptDecrypt() {
        try {
            Queue<byte[]> results = new ConcurrentLinkedQueue<>();
            Queue<Exception> ex = new ConcurrentLinkedQueue<>();
            SM2Util instance = new SM2Util();
            this.keyPair = instance.generatekeyPair();
            this.pubKey = keyPair.getPublic();
            this.privKey = keyPair.getPrivate();

            SM2Engine sm2Engine = sm2EnginePool.borrowObject();
            byte[] encrypted = instance.encrypt(sm2Engine, this.pubKey, message);
            byte[] rs = instance.decrypt(sm2Engine, this.privKey, encrypted);
            Assert.assertEquals(new String(message), new String(rs));
            sm2EnginePool.returnObject(sm2Engine);

            int threadNum = 300;
            final CountDownLatch startGate = new CountDownLatch(1);
            final CountDownLatch endGate  = new CountDownLatch(threadNum);
            for (int i = 0; i < threadNum; i++) {
                new Thread(() -> {
                    try {
                        startGate.await();
                        SM2Engine sm2Engine1 = null;
                        try {
                            sm2Engine1 = sm2EnginePool.borrowObject();
                            results.add(instance.decrypt(sm2Engine1, this.privKey, encrypted));
                        } catch (Exception e) {
                            ex.add(e);
                        } finally {
                            if (sm2Engine1 != null) {
                                sm2EnginePool.returnObject(sm2Engine1);
                            }
                            endGate.countDown();
                        }
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }).start();
            }

            long start =  System.currentTimeMillis();
            startGate.countDown();
            try {
                endGate.await();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            long end = System.currentTimeMillis();
            System.out.println("cost times :" + (end - start));

            while (!ex.isEmpty()) {
                Exception e =  ex.poll();
                e.printStackTrace();
                Assert.fail(exceptionHappened);
            }
            Assert.assertEquals(threadNum, results.size());
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
            Queue<Boolean> results = new ConcurrentLinkedQueue<>();
            Queue<Exception> ex = new ConcurrentLinkedQueue<>();
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
                        } catch (Exception e) {
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
            Assert.assertEquals(300, results.size());
            while (!results.isEmpty()) {
                Assert.assertTrue(results.poll());
            }
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail(exceptionHappened);
        }
    }

    @Test
    public void testKeyGen() {
        try {
            SM2Util instance = new SM2Util();
            Instant start = Instant.now();
            for (int i = 0; i < 1000; i++) {
                instance.generatekeyPair();
            }
            System.out.println("cost ms: " + Duration.between(start, Instant.now()).toMillis());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}