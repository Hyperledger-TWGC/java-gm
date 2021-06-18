package twgc.gm.sm2.pool;

import org.apache.commons.pool2.impl.GenericObjectPool;
import org.bouncycastle.crypto.engines.SM2Engine;

/**
 * @author Sean
 * @Description: SM2Engine对象池
 * @date 2021/6/12
 */
public class SM2EnginePool extends GenericObjectPool<SM2Engine> {

    public SM2EnginePool(int max, SM2Engine.Mode mode) {
        this(1, max, mode);
    }

    public SM2EnginePool(int init, int max, SM2Engine.Mode mode) {
        super(new SM2EngineFactory(mode));
        setMaxTotal(max);
        setMinIdle(init);
    }

}
