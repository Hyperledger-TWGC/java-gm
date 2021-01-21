package twgc.gm.sm4.pool;

import org.apache.commons.pool2.impl.GenericObjectPool;

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
        setMaxTotal(max);
        setMinIdle(init);
    }
}
