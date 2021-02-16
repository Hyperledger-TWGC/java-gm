package twgc.gm.sm3.pool;

import org.apache.commons.pool2.BasePooledObjectFactory;
import org.apache.commons.pool2.PooledObject;
import org.apache.commons.pool2.impl.DefaultPooledObject;
import org.bouncycastle.crypto.digests.SM3Digest;

/**
 * @author Sean
 * @Description: SM3Digest工厂
 * @date 2021/1/21
 */
public class SM3DigestFactory extends BasePooledObjectFactory<SM3Digest> {
    @Override
    public SM3Digest create() throws Exception {
        return new SM3Digest();
    }

    @Override
    public PooledObject<SM3Digest> wrap(SM3Digest obj) {
        return new DefaultPooledObject<>(obj);
    }
}
