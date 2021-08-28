package twgc.gm.pool;

import org.apache.commons.pool2.BasePooledObjectFactory;
import org.apache.commons.pool2.PooledObject;
import org.apache.commons.pool2.impl.DefaultPooledObject;
import twgc.gm.sm4.SM4Cipher;

/**
 * @author Sean
 * @Description: SM4Cipher工厂
 * @date 2021/1/21
 */
public class SM4CipherFactory extends BasePooledObjectFactory<SM4Cipher> {
    @Override
    public SM4Cipher create() throws Exception {
        return new SM4Cipher();
    }

    @Override
    public PooledObject<SM4Cipher> wrap(SM4Cipher obj) {
        return new DefaultPooledObject<>(obj);
    }
}
