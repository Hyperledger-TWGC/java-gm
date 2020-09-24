import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author Sean
 * @Description: 国密SM4工具类
 * @date 2020/9/18
 */
public class SM4Util {

    private static String algorithmName = "SM4";

    private SM4Util() {

    }

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    enum SM4ModeAndPaddingEnum {
        SM4_ECB_NoPadding("SM4/ECB/NoPadding"),
        SM4_ECB_PKCS5Padding("SM4/ECB/PKCS5Padding"),
        SM4_ECB_PKCS7Padding("SM4/ECB/PKCS7Padding"),
        SM4_CBC_NoPadding("SM4/CBC/NoPadding"),
        SM4_CBC_PKCS5Padding("SM4/CBC/PKCS5Padding"),
        SM4_CBC_PKCS7Padding("SM4/CBC/PKCS7Padding");

        private String name;

        SM4ModeAndPaddingEnum(String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }
    }

    /**
     * SM4加密
     *
     * @param input                 明文数据
     * @param key                   密钥，SM4 requires a 128 bit key
     * @param sm4ModeAndPaddingEnum 加密模式和padding模式
     * @param iv                    初始向量(ECB模式下传NULL), IV must be 16 bytes long
     * @return
     * @throws Exception
     */
    public static byte[] encrypt(byte[] input, byte[] key, SM4ModeAndPaddingEnum sm4ModeAndPaddingEnum, byte[] iv) throws Exception {
        return sm4(input, key, sm4ModeAndPaddingEnum, iv, Cipher.ENCRYPT_MODE);
    }

    /**
     * SM4解密
     *
     * @param input                 密文数据
     * @param key                   密钥，SM4 requires a 128 bit key
     * @param sm4ModeAndPaddingEnum 加密模式和padding模式
     * @param iv                    初始向量(ECB模式下传NULL), IV must be 16 bytes long
     * @return
     * @throws Exception
     */
    public static byte[] decrypt(byte[] input, byte[] key, SM4ModeAndPaddingEnum sm4ModeAndPaddingEnum, byte[] iv) throws Exception {
        return sm4(input, key, sm4ModeAndPaddingEnum, iv, Cipher.DECRYPT_MODE);
    }

    /**
     * 执行sm4加解密
     *
     * @param input                 明文或密文，与参数mode有关
     * @param key                   密钥
     * @param sm4ModeAndPaddingEnum 加密模式和padding模式
     * @param iv                    初始向量(ECB模式下传NULL)
     * @param mode                  1-加密；2-解密
     * @return
     * @throws Exception
     */
    private static byte[] sm4(byte[] input, byte[] key, SM4ModeAndPaddingEnum sm4ModeAndPaddingEnum, byte[] iv, int mode) throws Exception {
        IvParameterSpec ivParameterSpec = null;
        if (iv != null) {
            ivParameterSpec = new IvParameterSpec(iv);
        }

        SecretKeySpec sm4Key = new SecretKeySpec(key, algorithmName);
        Cipher cipher = Cipher.getInstance(sm4ModeAndPaddingEnum.getName(), BouncyCastleProvider.PROVIDER_NAME);
        if (ivParameterSpec == null) {
            cipher.init(mode, sm4Key);
        } else {
            cipher.init(mode, sm4Key, ivParameterSpec);
        }

        return cipher.doFinal(input);
    }

    /**
     * SM4算法目前只支持128位（即密钥16字节）
     */
    public static final int DEFAULT_KEY_SIZE = 128;

    public static byte[] generateKey() throws NoSuchAlgorithmException, NoSuchProviderException {
        return generateKey(DEFAULT_KEY_SIZE);
    }

    public static byte[] generateKey(int keySize) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyGenerator kg = KeyGenerator.getInstance(algorithmName, BouncyCastleProvider.PROVIDER_NAME);
        kg.init(keySize, new SecureRandom());
        return kg.generateKey().getEncoded();
    }
}
