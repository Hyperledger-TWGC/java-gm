import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
/**
 * @author Sean
 * @Description: 国密算法SM4工具类测试
 * @date 2020/9/18
 */
public class SM4UtilTest {

    private static byte[] content;
    private static byte[] content16;
    private static byte[] key;
    private static byte[] iv;

    @BeforeClass
    public static void init() throws Exception {
//        content = "国密算法sm4测试使用中...".getBytes(StandardCharsets.UTF_8);
        content = RandomStringUtils.random(128).getBytes();
        // NoPadding模式只能对16整数倍的内容进行加解密
        content16 = "I get your means".getBytes();
        key = SM4Util.generateKey();
        iv = SM4Util.generateKey();
    }

    @Test
    public void sm4ECBNoPadding() throws Exception {
        System.out.println("===== " + SM4Util.SM4ModeAndPaddingEnum.SM4_ECB_NoPadding + " =====");
        // 加密
        byte[] v = SM4Util.encrypt(content16, key, SM4Util.SM4ModeAndPaddingEnum.SM4_ECB_NoPadding, null);
        // 解密
        byte[] c = SM4Util.decrypt(v, key, SM4Util.SM4ModeAndPaddingEnum.SM4_ECB_NoPadding, null);

        System.out.println("解密内容：" + new String(c));
        Assert.assertArrayEquals(c, content16);
    }

    @Test
    public void sm4ECBPKCS5Padding() throws Exception {
        System.out.println("===== " + SM4Util.SM4ModeAndPaddingEnum.SM4_ECB_PKCS5Padding + " =====");
        // 加密
        byte[] v = SM4Util.encrypt(content, key, SM4Util.SM4ModeAndPaddingEnum.SM4_ECB_PKCS5Padding, null);
        // 解密
        byte[] c = SM4Util.decrypt(v, key, SM4Util.SM4ModeAndPaddingEnum.SM4_ECB_PKCS5Padding, null);

        System.out.println("解密内容：" + new String(c));
        Assert.assertArrayEquals(c, content);
    }

    @Test
    public void sm4ECBPKCS7Padding() throws Exception {
        System.out.println("===== " + SM4Util.SM4ModeAndPaddingEnum.SM4_ECB_PKCS7Padding + " =====");
        // 加密
        byte[] v = SM4Util.encrypt(content, key, SM4Util.SM4ModeAndPaddingEnum.SM4_ECB_PKCS7Padding, null);
        // 解密
        byte[] c = SM4Util.decrypt(v, key, SM4Util.SM4ModeAndPaddingEnum.SM4_ECB_PKCS7Padding, null);

        System.out.println("解密内容：" + new String(c));
        Assert.assertArrayEquals(c, content);
    }

    @Test
    public void sm4CBCNoPadding() throws Exception {
        System.out.println("===== " + SM4Util.SM4ModeAndPaddingEnum.SM4_CBC_NoPadding + " =====");
        // 加密
        byte[] v = SM4Util.encrypt(content16, key, SM4Util.SM4ModeAndPaddingEnum.SM4_CBC_NoPadding, iv);
        // 解密
        byte[] c = SM4Util.decrypt(v, key, SM4Util.SM4ModeAndPaddingEnum.SM4_CBC_NoPadding, iv);

        System.out.println("解密内容：" + new String(c));
        Assert.assertArrayEquals(c, content16);
    }

    @Test
    public void sm4CBCPKCS5Padding() throws Exception {
        System.out.println("===== " + SM4Util.SM4ModeAndPaddingEnum.SM4_CBC_PKCS5Padding + " =====");
        // 加密
        byte[] v = SM4Util.encrypt(content, key, SM4Util.SM4ModeAndPaddingEnum.SM4_CBC_PKCS5Padding, iv);
        // 解密
        byte[] c = SM4Util.decrypt(v, key, SM4Util.SM4ModeAndPaddingEnum.SM4_CBC_PKCS5Padding, iv);

        System.out.println("解密内容：" + new String(c));
        Assert.assertArrayEquals(c, content);
    }

    @Test
    public void sm4CBCPKCS7Padding() throws Exception {
        System.out.println("===== " + SM4Util.SM4ModeAndPaddingEnum.SM4_CBC_PKCS7Padding + " =====");
        // 加密
        byte[] v = SM4Util.encrypt(content, key, SM4Util.SM4ModeAndPaddingEnum.SM4_CBC_PKCS7Padding, iv);
        // 解密
        byte[] c = SM4Util.decrypt(v, key, SM4Util.SM4ModeAndPaddingEnum.SM4_CBC_PKCS7Padding, iv);

        System.out.println("解密内容：" + new String(c));
        Assert.assertArrayEquals(c, content);
    }

    @Test
    public void sm4Interaction() throws Exception {
        byte[] key = "1234567890abcdef".getBytes();
        byte[] iv = "ilovegolangjava.".getBytes();

        //解密校验
        String cryptText = "8781d981f7ffd6c1a780f8b213f596aa535c8bb6389923f8329f79a1707966e2";
        byte[] b = SM4Util.decrypt(ByteUtils.fromHexString(cryptText), key, SM4Util.SM4ModeAndPaddingEnum.SM4_CBC_PKCS7Padding, iv);
        Assert.assertEquals("I am encrypted by golang SM4.", new String(b));

        //加密校验，SM4加密以下明文以供Go SM4进行解密验证
        byte[] msg = "I am encrypted by java SM4.".getBytes();
        byte[] cryptData = SM4Util.encrypt(msg, key, SM4Util.SM4ModeAndPaddingEnum.SM4_CBC_PKCS7Padding, iv);
        String cryptStr = ByteUtils.toHexString(cryptData);
        System.out.println(cryptStr);
    }
}
