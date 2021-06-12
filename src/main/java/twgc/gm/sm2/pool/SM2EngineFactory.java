package twgc.gm.sm2.pool;

import org.apache.commons.pool2.BasePooledObjectFactory;
import org.apache.commons.pool2.PooledObject;
import org.apache.commons.pool2.impl.DefaultPooledObject;
import org.bouncycastle.crypto.engines.SM2Engine;

/**
 * @author Sean
 * @Description: SM2Engine工厂
 * @date 2021/6/12
 */
public class SM2EngineFactory extends BasePooledObjectFactory<SM2Engine> {

    @Override
    public SM2Engine create() throws Exception {
        return new SM2Engine(SM2Engine.Mode.C1C3C2);
    }

    @Override
    public PooledObject<SM2Engine> wrap(SM2Engine obj) {
        return new DefaultPooledObject<>(obj);
    }
}
