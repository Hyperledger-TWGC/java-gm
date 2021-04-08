package twgc.gm.sm3.pool;

import org.apache.commons.pool2.impl.GenericObjectPool;
import org.bouncycastle.crypto.digests.SM3Digest;

/**
 * @author Sean
 * @Description: SM3Digest对象池
 * @date 2021/1/21
 */
public class SM3DigestPool extends GenericObjectPool<SM3Digest> {

    private static final SM3DigestFactory sm3DigestFactory = new SM3DigestFactory();

    public SM3DigestPool(int max) {
        this(1, max);
    }

    public SM3DigestPool(int init, int max) {
        super(sm3DigestFactory);
        setMaxTotal(max);
        setMinIdle(init);
    }

    @Override
    public void returnObject(SM3Digest obj) {
        if (obj != null) {
           obj.reset();
        }
        super.returnObject(obj);
    }
}
