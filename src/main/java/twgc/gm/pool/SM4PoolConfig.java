package twgc.gm.pool;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import org.apache.commons.pool2.impl.GenericObjectPoolConfig;
import twgc.gm.consts.Const;

public class SM4PoolConfig extends GenericObjectPoolConfig {

    public SM4PoolConfig() {
    }

    public SM4PoolConfig(String file) throws IOException {
        new SM4PoolConfig(Const.loadConfig(this.getClass().getResourceAsStream(file)));
    }

    public SM4PoolConfig(Properties properties) {
        this.setMaxTotal(Integer.valueOf(properties.getProperty("maxTotal")).intValue());
        this.setMaxIdle(Integer.valueOf(properties.getProperty("maxIdle")).intValue());
        this.setMinIdle(Integer.valueOf(properties.getProperty("minIdle")).intValue());
        this.setMaxWaitMillis(Integer.valueOf(properties.getProperty("maxWaitMillis")).intValue());
    }
}