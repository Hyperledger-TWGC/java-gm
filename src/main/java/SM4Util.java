import java.security.*;
import java.util.EnumMap;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author Sean
 * @Description: 国密SM4工具类
 * @date 2020/9/18
 */
public class SM4Util {

    private static final String ALGORITHM_NAME = "SM4";
    private static EnumMap<SM4ModeAndPaddingEnum, Cipher> sm4ModeAndPaddingEnumCipherEnumMap = new EnumMap<>(SM4ModeAndPaddingEnum.class);
    private static KeyGenerator kg;


    public SM4Util() throws NoSuchProviderException, NoSuchAlgorithmException, NoSuchPaddingException {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        for (SM4ModeAndPaddingEnum mode:SM4ModeAndPaddingEnum.values()) {
            Cipher cipher = Cipher.getInstance(mode.getName(), BouncyCastleProvider.PROVIDER_NAME);
            sm4ModeAndPaddingEnumCipherEnumMap.put(mode, cipher);
        }
        kg = KeyGenerator.getInstance(ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
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
    public byte[] encrypt(byte[] input, byte[] key, SM4ModeAndPaddingEnum sm4ModeAndPaddingEnum, byte[] iv) throws Exception {
        synchronized (this) {
            IvParameterSpec ivParameterSpec = null;
            if (iv != null) {
                ivParameterSpec = new IvParameterSpec(iv);
            }
            Cipher cipher = sm4ModeAndPaddingEnumCipherEnumMap.get(sm4ModeAndPaddingEnum);
            SecretKeySpec sm4Key = new SecretKeySpec(key, ALGORITHM_NAME);
            return sm4(input, sm4Key, cipher, ivParameterSpec, Cipher.ENCRYPT_MODE);
        }
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
    public byte[] decrypt(byte[] input, byte[] key, SM4ModeAndPaddingEnum sm4ModeAndPaddingEnum, byte[] iv) throws IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        synchronized (this) {
            IvParameterSpec ivParameterSpec = null;
            if (iv != null) {
                ivParameterSpec = new IvParameterSpec(iv);
            }
            Cipher cipher = sm4ModeAndPaddingEnumCipherEnumMap.get(sm4ModeAndPaddingEnum);
            SecretKeySpec sm4Key = new SecretKeySpec(key, ALGORITHM_NAME);
            return sm4(input, sm4Key, cipher, ivParameterSpec, Cipher.DECRYPT_MODE);
        }
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