package twgc.gm.sm3;

import java.util.Arrays;

import org.bouncycastle.crypto.digests.SM3Digest;

/**
 * @author Sean
 * @Description: 国密SM3工具类
 * @date 2020/9/18
 */
public class SM3Util {

    private SM3Util() {

    }

    /**
     * 计算SM3摘要值
     *
     * @param srcData 原文
     * @return 摘要值
     */
    public static byte[] hash(SM3Digest digest, byte[] srcData) {
        digest.update(srcData, 0, srcData.length);
        byte[] hashVal = new byte[digest.getDigestSize()];
        digest.doFinal(hashVal, 0);
        return hashVal;
    }

    /**
     * SM3摘要值验证
     *
     * @param srcData 原文
     * @param sm3HashVal 原文对应的摘要值
     * @return 返回true标识验证成功，false标识验证失败
     */
    public static boolean verify(SM3Digest digest, byte[] srcData, byte[] sm3HashVal) {
        byte[] hashVal = hash(digest, srcData);
        return Arrays.equals(hashVal, sm3HashVal);
    }
}
