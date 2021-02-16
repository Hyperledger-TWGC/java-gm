import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.junit.Assert;
import org.junit.Test;
import twgc.gm.sm3.SM3Util;
import twgc.gm.sm3.pool.SM3DigestPool;

/**
 * @author Sean
 * @Description: 国密算法SM3工具类测试
 * @date 2020/9/18
 */
public class SM3UtilTest {

    static int randomData = 128;
    static byte[] message = RandomStringUtils.random(randomData).getBytes();

    static SM3DigestPool sm3DigestPool = new SM3DigestPool(1);

    @Test
    public void hashAndVerify() throws Exception {
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
    }
}