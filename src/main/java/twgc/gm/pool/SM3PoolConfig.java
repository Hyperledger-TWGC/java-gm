package twgc.gm.pool;

import java.io.IOException;
import java.util.Properties;

import org.apache.commons.pool2.impl.GenericObjectPoolConfig;
import twgc.gm.consts.Const;

public class SM3PoolConfig extends GenericObjectPoolConfig {

    public SM3PoolConfig() {
    }

    public SM3PoolConfig(String file) throws IOException {
        this.setProperties(Const.loadConfig(this.getClass().getResourceAsStream(file)));
    }

    private void setProperties(Properties properties) {
        this.setMaxTotal(Integer.valueOf(properties.getProperty("maxTotal")).intValue());
        this.setMaxIdle(Integer.valueOf(properties.getProperty("maxIdle")).intValue());
        this.setMinIdle(Integer.valueOf(properties.getProperty("minIdle")).intValue());
        this.setMaxWaitMillis(Integer.valueOf(properties.getProperty("maxWaitMillis")).intValue());
    }
}