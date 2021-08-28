package twgc.gm.pool;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import org.apache.commons.pool2.impl.GenericObjectPoolConfig;

public class SM4PoolConfig extends GenericObjectPoolConfig {

    public SM4PoolConfig() {
    }

    public SM4PoolConfig(String file) {
        loadConfig(file);
    }

    public void loadConfig(String file) {
        try {
            InputStream in = this.getClass().getResourceAsStream(file);
            Properties properties = new Properties();
            properties.load(in);
            this.setMaxTotal(Integer.valueOf(properties.getProperty("maxTotal")).intValue());
            this.setMaxIdle(Integer.valueOf(properties.getProperty("maxIdle")).intValue());
            this.setMinIdle(Integer.valueOf(properties.getProperty("minIdle")).intValue());
            this.setMaxWaitMillis(Integer.valueOf(properties.getProperty("maxWaitMillis")).intValue());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}