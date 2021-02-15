import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.Assert;
import org.junit.Test;
import twgc.gm.sm3.SM3Util;


/**
 * @author Sam
 * @Description: 国密算法SM3工具类线程安全测试
 * @date 2021/1/10
 */
public class SM3UtilThreadTest {

    static int randomData = 128;
    static byte[] message = RandomStringUtils.random(randomData).getBytes();

    @Test
    public void hashAndVerify() throws InterruptedException {
        Queue<Boolean> results = new ConcurrentLinkedQueue<Boolean>();
        byte[] hashVal = SM3Util.hash(message);
        Assert.assertTrue(SM3Util.verify(message, hashVal));
        for (int i = 0; i < 300; i++) {
            new Thread(() -> {
                    results.add(SM3Util.verify(message, hashVal));
            }).start();
        }
        Thread.sleep(5000);
        Assert.assertTrue(results.size() == 300);
        while (!results.isEmpty()) {
            Assert.assertTrue(results.poll());
        }
    }
}