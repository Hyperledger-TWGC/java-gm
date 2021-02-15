import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.junit.Assert;
import org.junit.Test;

import twgc.gm.sm4.SM4ModeAndPaddingEnum;
import twgc.gm.sm4.SM4Util;
import twgc.gm.sm4.pool.SM4Cipher;
import twgc.gm.sm4.pool.SM4CipherPool;


public class SM4InterationTest {

    @Test
    public void sm4Interaction() throws Exception {
        SM4CipherPool sm4CipherPool = new SM4CipherPool(10);
        SM4Cipher sm4Cipher = null;
        try {
                sm4Cipher = sm4CipherPool.borrowObject();
                Cipher cipher = sm4Cipher.getCipher(SM4ModeAndPaddingEnum.SM4_CBC_PKCS7Padding);

                byte[] key = "1234567890abcdef".getBytes();
                SecretKeySpec sm4Key = new SecretKeySpec(key, SM4ModeAndPaddingEnum.SM4_CBC_PKCS7Padding.getName());
                byte[] iv = "ilovegolangjava.".getBytes();
                SM4Util instance = new SM4Util();
                //解密校验
                String cryptText = "8781d981f7ffd6c1a780f8b213f596aa535c8bb6389923f8329f79a1707966e2";
                byte[] b = instance.decrypt(cipher, ByteUtils.fromHexString(cryptText), sm4Key, iv);
                Assert.assertEquals("I am encrypted by golang SM4.", new String(b));

                //加密校验，SM4加密以下明文以供Go SM4进行解密验证
                byte[] msg = "I am encrypted by java SM4.".getBytes();
                byte[] cryptData = instance.encrypt(cipher, msg, sm4Key, iv);
                String cryptStr = ByteUtils.toHexString(cryptData);
                System.out.println(cryptStr);
        } finally {
            if (sm4Cipher != null) {
                sm4CipherPool.returnObject(sm4Cipher);
            }
        }
    }
}
