package twgc.gm.pool;

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

    private SM2Engine.Mode mode;

    public SM2EngineFactory(SM2Engine.Mode mode) {
        this.mode = mode;
    }

    @Override
    public SM2Engine create() {
        return new SM2Engine(mode);
    }

    @Override
    public PooledObject<SM2Engine> wrap(SM2Engine obj) {
        return new DefaultPooledObject<>(obj);
    }
}
