import org.junit.Test;

/**
 * @author Sean
 * @Description: 国密算法SM3工具类测试
 * @date 2020/9/18
 */
public class SM3UtilTest {

    @Test
    public void hashAndVerify() {
        byte[] srcData = "I'm using the SM3.".getBytes();
        byte[] hashVal = SM3Util.hash(srcData);
        System.out.println("Verify result: " + SM3Util.verify(srcData, hashVal));
    }
}