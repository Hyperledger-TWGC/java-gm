import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.junit.Assert;
import org.junit.Test;

public class SM4Interation {

    @Test
    public void sm4Interaction() throws Exception {
        byte[] key = "1234567890abcdef".getBytes();
        byte[] iv = "ilovegolangjava.".getBytes();
        SM4Util instance = new SM4Util();
        //解密校验
        String cryptText = "8781d981f7ffd6c1a780f8b213f596aa535c8bb6389923f8329f79a1707966e2";
        byte[] b = instance.decrypt(ByteUtils.fromHexString(cryptText), key, SM4Util.SM4ModeAndPaddingEnum.SM4_CBC_PKCS7Padding, iv);
        Assert.assertEquals("I am encrypted by golang SM4.", new String(b));

        //加密校验，SM4加密以下明文以供Go SM4进行解密验证
        byte[] msg = "I am encrypted by java SM4.".getBytes();
        byte[] cryptData = instance.encrypt(msg, key, SM4Util.SM4ModeAndPaddingEnum.SM4_CBC_PKCS7Padding, iv);
        String cryptStr = ByteUtils.toHexString(cryptData);
        System.out.println(cryptStr);
    }
}
