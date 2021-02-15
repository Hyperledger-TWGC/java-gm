package twgc.gm.sm4.pool;

import java.security.Security;
import org.apache.commons.pool2.impl.GenericObjectPool;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


/**
 * @author Sean
 * @Description: SM4Cipher对象池
 * @date 2021/1/21
 */
public class SM4CipherPool extends GenericObjectPool<SM4Cipher> {

    private static SM4CipherFactory sm4CipherFactory = new SM4CipherFactory();

    public SM4CipherPool(int max) {
        this(1, max);
    }

    public SM4CipherPool(int init, int max) {
        super(sm4CipherFactory);
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        setMaxTotal(max);
        setMinIdle(init);
    }
}
