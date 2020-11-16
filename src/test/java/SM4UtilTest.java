import java.nio.charset.Charset;

import org.apache.commons.lang3.RandomStringUtils;
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
    static int randomData = 128;
    static String message = RandomStringUtils.random(randomData);

    @BeforeClass
    public static void init() throws Exception {
        content = message.getBytes(Charset.forName("utf8"));
        content16 = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};
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

        System.out.println("解密内容：" + new String(c, Charset.forName("utf8")));
        Assert.assertArrayEquals(c, content16);
    }

    @Test
    public void sm4ECBPKCS5Padding() throws Exception {
        System.out.println("===== " + SM4Util.SM4ModeAndPaddingEnum.SM4_ECB_PKCS5Padding + " =====");
        // 加密
        byte[] v = SM4Util.encrypt(content, key, SM4Util.SM4ModeAndPaddingEnum.SM4_ECB_PKCS5Padding, null);
        // 解密
        byte[] c = SM4Util.decrypt(v, key, SM4Util.SM4ModeAndPaddingEnum.SM4_ECB_PKCS5Padding, null);

        System.out.println("解密内容：" + new String(c, Charset.forName("utf8")));
        Assert.assertArrayEquals(c, content);
    }

    @Test
    public void sm4ECBPKCS7Padding() throws Exception {
        System.out.println("===== " + SM4Util.SM4ModeAndPaddingEnum.SM4_ECB_PKCS7Padding + " =====");
        // 加密
        byte[] v = SM4Util.encrypt(content, key, SM4Util.SM4ModeAndPaddingEnum.SM4_ECB_PKCS7Padding, null);
        // 解密
        byte[] c = SM4Util.decrypt(v, key, SM4Util.SM4ModeAndPaddingEnum.SM4_ECB_PKCS7Padding, null);

        System.out.println("解密内容：" + new String(c, Charset.forName("utf8")));
        Assert.assertArrayEquals(c, content);
    }

    @Test
    public void sm4CBCNoPadding() throws Exception {
        System.out.println("===== " + SM4Util.SM4ModeAndPaddingEnum.SM4_CBC_NoPadding + " =====");
        // 加密
        byte[] v = SM4Util.encrypt(content16, key, SM4Util.SM4ModeAndPaddingEnum.SM4_CBC_NoPadding, iv);
        // 解密
        byte[] c = SM4Util.decrypt(v, key, SM4Util.SM4ModeAndPaddingEnum.SM4_CBC_NoPadding, iv);

        System.out.println("解密内容：" + new String(c, Charset.forName("utf8")));
        Assert.assertArrayEquals(c, content16);
    }

    @Test
    public void sm4CBCPKCS5Padding() throws Exception {
        System.out.println("===== " + SM4Util.SM4ModeAndPaddingEnum.SM4_CBC_PKCS5Padding + " =====");
        // 加密
        byte[] v = SM4Util.encrypt(content, key, SM4Util.SM4ModeAndPaddingEnum.SM4_CBC_PKCS5Padding, iv);
        // 解密
        byte[] c = SM4Util.decrypt(v, key, SM4Util.SM4ModeAndPaddingEnum.SM4_CBC_PKCS5Padding, iv);

        System.out.println("解密内容：" + new String(c, Charset.forName("utf8")));
        Assert.assertArrayEquals(c, content);
    }

    @Test
    public void sm4CBCPKCS7Padding() throws Exception {
        System.out.println("===== " + SM4Util.SM4ModeAndPaddingEnum.SM4_CBC_PKCS7Padding + " =====");
        // 加密
        byte[] v = SM4Util.encrypt(content, key, SM4Util.SM4ModeAndPaddingEnum.SM4_CBC_PKCS7Padding, iv);
        // 解密
        byte[] c = SM4Util.decrypt(v, key, SM4Util.SM4ModeAndPaddingEnum.SM4_CBC_PKCS7Padding, iv);

        System.out.println("解密内容：" + new String(c, Charset.forName("utf8")));
        Assert.assertArrayEquals(c, content);
    }
}
