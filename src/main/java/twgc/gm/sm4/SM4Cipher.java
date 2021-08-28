package twgc.gm.sm4;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.EnumMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import twgc.gm.consts.SM4ModeAndPaddingEnum;


/**
 * @author Sean
 * @Description: SM4Cipher
 * @date 2021/2/12
 */
public class SM4Cipher {

    private final Map<SM4ModeAndPaddingEnum, Cipher> cipherMap = new EnumMap<>(SM4ModeAndPaddingEnum.class);

    public SM4Cipher() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        for (SM4ModeAndPaddingEnum mode : SM4ModeAndPaddingEnum.values()) {
            Cipher cipher = Cipher.getInstance(mode.getName(), BouncyCastleProvider.PROVIDER_NAME);
            cipherMap.put(mode, cipher);
        }
    }

    public Cipher getCipher(SM4ModeAndPaddingEnum sm4ModeAndPaddingEnum) {
        return cipherMap.get(sm4ModeAndPaddingEnum);
    }
}
