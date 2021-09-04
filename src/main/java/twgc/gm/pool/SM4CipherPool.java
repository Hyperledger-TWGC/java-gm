package twgc.gm.pool;

import java.io.IOException;
import java.security.Security;
import org.apache.commons.pool2.impl.GenericObjectPool;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import twgc.gm.consts.Const;
import twgc.gm.sm4.SM4Cipher;


/**
 * @author Sean
 * @Description: SM4Cipher对象池
 * @date 2021/1/21
 */
public class SM4CipherPool extends GenericObjectPool<SM4Cipher> {

    private static final SM4CipherFactory sm4CipherFactory = new SM4CipherFactory();

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

    public SM4CipherPool(SM4PoolConfig config) {
        super(sm4CipherFactory, config);
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public SM4CipherPool() throws IOException {
        super(sm4CipherFactory, new SM4PoolConfig(Const.SM4_POOL_CONFIG));
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
}
