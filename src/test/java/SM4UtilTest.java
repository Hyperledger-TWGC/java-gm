import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import twgc.gm.consts.SM4ModeAndPaddingEnum;
import twgc.gm.pool.SM4CipherPool;
import twgc.gm.sm4.SM4Cipher;
import twgc.gm.sm4.SM4Util;

/**
 * @author Sean
 * @Description: 国密算法SM4工具类测试
 * @date 2020/9/18
 */

@RunWith(Parameterized.class)
public class SM4UtilTest {
    private static byte[] content = null;
    private static final byte[] content16 = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};
    private static byte[] iv = null;
    private static SM4ModeAndPaddingEnum type;
    static int randomData = 128;
    static String message = RandomStringUtils.random(randomData);
    static String exceptionHappened = "Exception happened";
    SM4CipherPool sm4CipherPool;
    {
        try {
            sm4CipherPool = new SM4CipherPool();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @SuppressWarnings("rawtypes")
    @Parameters(name = "{index}: sm4({1})")
    public static Collection prepareData() {
        Object[][] object = {
                {content16, SM4ModeAndPaddingEnum.SM4_ECB_NoPadding, false},
                {message.getBytes(StandardCharsets.UTF_8), SM4ModeAndPaddingEnum.SM4_ECB_PKCS5Padding, false},
                {message.getBytes(StandardCharsets.UTF_8), SM4ModeAndPaddingEnum.SM4_ECB_PKCS7Padding, false},
                {content16, SM4ModeAndPaddingEnum.SM4_CBC_NoPadding, true},
                {message.getBytes(StandardCharsets.UTF_8), SM4ModeAndPaddingEnum.SM4_CBC_PKCS5Padding, true},
                {message.getBytes(StandardCharsets.UTF_8), SM4ModeAndPaddingEnum.SM4_CBC_PKCS7Padding, true},
                {message.getBytes(StandardCharsets.UTF_8), SM4ModeAndPaddingEnum.SM4_CFB_NoPadding, true},
                {message.getBytes(StandardCharsets.UTF_8), SM4ModeAndPaddingEnum.SM4_OFB_NoPadding, true},
                {message.getBytes(StandardCharsets.UTF_8), SM4ModeAndPaddingEnum.SM4_CTR_NoPadding, true}
        };
        return Arrays.asList(object);
    }

    public SM4UtilTest(byte[] content, SM4ModeAndPaddingEnum type, boolean flag) throws NoSuchProviderException, NoSuchAlgorithmException {
        SM4UtilTest.content = content;
        SM4UtilTest.type = type;
        if (flag) {
            SM4Util instance = new SM4Util();
            iv = instance.generateKey();
        }
    }

    @Test
    public void testingSM4() throws Exception {
        SM4Cipher sm4Cipher = null;
        try {
            sm4Cipher = sm4CipherPool.borrowObject();
            Cipher cipher = sm4Cipher.getCipher(type);
            SM4Util instance = new SM4Util();
            byte[] key = instance.generateKey();
            SecretKeySpec sm4Key = new SecretKeySpec(key, type.getName());
            System.out.println("===== " + type + " =====");
            // 加密
            byte[] v = instance.encrypt(cipher, content, sm4Key, iv);
            // 解密
            byte[] c = instance.decrypt(cipher, v, sm4Key, iv);

            System.out.println("解密内容：" + new String(c));
            Assert.assertArrayEquals(c, content);
        } finally {
            if (sm4Cipher != null) {
                sm4CipherPool.returnObject(sm4Cipher);
            }
        }
    }

    @Test
    public void threadsafe() throws Exception {
        SM4Cipher sm4Cipher;
        sm4Cipher = sm4CipherPool.borrowObject();
        Queue<byte[]> results = new ConcurrentLinkedQueue<>();
        Queue<Exception> ex = new ConcurrentLinkedQueue<>();
        SM4Util instance = new SM4Util();
        byte[] key = instance.generateKey();
        SecretKeySpec sm4Key = new SecretKeySpec(key, type.getName());
        byte[] v;
        try {
            Cipher cipher = sm4Cipher.getCipher(type);
            System.out.println("===== " + type + " =====");
            // 加密
            v = instance.encrypt(cipher, content, sm4Key, iv);
            // 解密
            byte[] c = instance.decrypt(cipher, v, sm4Key, iv);

            System.out.println("解密内容：" + new String(c));
            Assert.assertArrayEquals(c, content);
        } finally {
            if (sm4Cipher != null) {
                sm4CipherPool.returnObject(sm4Cipher);
            }
        }
        for (int i = 0; i < 300; i++) {
            new Thread(() -> {
                SM4Cipher sm4Ciphertest = null;
                try {
                    sm4Ciphertest = sm4CipherPool.borrowObject();
                    Cipher ciphertest = sm4Ciphertest.getCipher(type);
                    results.add(instance.decrypt(ciphertest, v, sm4Key, iv));
                } catch (Exception e) {
                    ex.add(e);
                } finally {
                    if (sm4Ciphertest != null) {
                        sm4CipherPool.returnObject(sm4Ciphertest);
                    }
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
            Assert.assertArrayEquals(results.poll(), content);
        }
    }
}
