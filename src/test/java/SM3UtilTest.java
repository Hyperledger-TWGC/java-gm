import org.apache.commons.lang3.RandomStringUtils;
import org.junit.Assert;
import org.junit.Test;

/**
 * @author Sean
 * @Description: 国密算法SM3工具类测试
 * @date 2020/9/18
 */
public class SM3UtilTest {

    static int randomData = 128;
    static byte[] message = RandomStringUtils.random(randomData).getBytes();

    @Test
    public void hashAndVerify() {
        byte[] hashVal = SM3Util.hash(message);
        Assert.assertTrue(SM3Util.verify(message, hashVal));
    }
}