package twgc.gm.sm2.pool;

import org.apache.commons.pool2.impl.GenericObjectPool;
import org.bouncycastle.crypto.engines.SM2Engine;

/**
 * @author Sean
 * @Description: SM2Engine对象池
 * @date 2021/6/12
 */
public class SM2EnginePool extends GenericObjectPool<SM2Engine> {

    private static final SM2EngineFactory sm2EngineFactory = new SM2EngineFactory();

    public SM2EnginePool(int max) {
        this(1, max);
    }

    public SM2EnginePool(int init, int max) {
        super(sm2EngineFactory);
        setMaxTotal(max);
        setMinIdle(init);
    }

}
