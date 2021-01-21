package twgc.gm.sm4;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import twgc.gm.sm4.pool.SM4Cipher;
import twgc.gm.sm4.pool.SM4CipherPool;

/**
 * @author Sean
 * @Description: 国密SM4工具类
 * @date 2020/9/18
 */
public class SM4Util {

    private static final String ALGORITHM_NAME = "SM4";
    private static KeyGenerator kg;
    private static SM4CipherPool sm4CipherPool = new SM4CipherPool(10);

    public SM4Util() throws NoSuchProviderException, NoSuchAlgorithmException, NoSuchPaddingException {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        kg = KeyGenerator.getInstance(ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
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
    public byte[] encrypt(byte[] input, byte[] key, SM4ModeAndPaddingEnum sm4ModeAndPaddingEnum, byte[] iv) throws Exception {
        IvParameterSpec ivParameterSpec = null;
        if (iv != null) {
            ivParameterSpec = new IvParameterSpec(iv);
        }

        SM4Cipher sm4Cipher = null;
        byte[] ret = null;
        try {
            sm4Cipher = sm4CipherPool.borrowObject();
            Cipher cipher = sm4Cipher.getCipher(sm4ModeAndPaddingEnum);

            SecretKeySpec sm4Key = new SecretKeySpec(key, ALGORITHM_NAME);
            ret = sm4(input, sm4Key, cipher, ivParameterSpec, Cipher.ENCRYPT_MODE);
        } finally {
            if (sm4Cipher != null) {
                sm4CipherPool.returnObject(sm4Cipher);
            }
        }

        return ret;
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
    public byte[] decrypt(byte[] input, byte[] key, SM4ModeAndPaddingEnum sm4ModeAndPaddingEnum, byte[] iv) throws Exception {
        IvParameterSpec ivParameterSpec = null;
        if (iv != null) {
            ivParameterSpec = new IvParameterSpec(iv);
        }

        SM4Cipher sm4Cipher = null;
        byte[] ret = null;

        try {
            sm4Cipher = sm4CipherPool.borrowObject();
            Cipher cipher = sm4Cipher.getCipher(sm4ModeAndPaddingEnum);

            SecretKeySpec sm4Key = new SecretKeySpec(key, ALGORITHM_NAME);
            ret = sm4(input, sm4Key, cipher, ivParameterSpec, Cipher.DECRYPT_MODE);
        } finally {
            if (sm4Cipher != null) {
                sm4CipherPool.returnObject(sm4Cipher);
            }
        }

        return ret;
    }

    /**
     * 执行sm4加解密
     *
     * @param input                 明文或密文，与参数mode有关
     * @param sm4Key                   密钥
     * @param cipher                 加密模式和padding模式
     * @param ivParameterSpec       初始向量(ECB模式下传NULL)
     * @param mode                  1-加密；2-解密
     * @return
     * @throws Exception
     */
    private static byte[] sm4(byte[] input, SecretKeySpec sm4Key, Cipher cipher, IvParameterSpec ivParameterSpec, int mode) throws InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
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

    public byte[] generateKey() {
        return generateKey(DEFAULT_KEY_SIZE);
    }

    private byte[] generateKey(int keySize) {
        kg.init(keySize, new SecureRandom());
        return kg.generateKey().getEncoded();
    }
}