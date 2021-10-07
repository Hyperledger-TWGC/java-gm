package twgc.gm.pool;

import java.io.IOException;
import java.util.Map;

import org.apache.commons.pool2.impl.GenericObjectPoolConfig;
import twgc.gm.consts.Const;
import twgc.gm.utils.ConfigLoader;

public class SM4PoolConfig extends GenericObjectPoolConfig {

    public SM4PoolConfig() {
    }

    public SM4PoolConfig(String file) throws IOException {
        this.setProperties(ConfigLoader.loadConfig(this.getClass().getResourceAsStream(file), Const.SM4));
    }

    private void setProperties(Map<String, Object> map) {
        this.setMaxTotal(Integer.valueOf(map.get("maxTotal").toString()));
        this.setMaxIdle(Integer.valueOf(map.get("maxIdle").toString()));
        this.setMinIdle(Integer.valueOf(map.get("minIdle").toString()));
        this.setMaxWaitMillis(Integer.valueOf(map.get("maxWaitMillis").toString()));
    }
}