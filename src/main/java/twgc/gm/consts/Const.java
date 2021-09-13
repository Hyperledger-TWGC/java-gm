package twgc.gm.consts;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class Const {
    private Const() {

    }

    public static final String EC_VALUE = "EC";
    public static final String SM3SM2_VALUE = "SM3WITHSM2";
    public static final String CURVE_NAME = "sm2p256v1";
    public static final String SM2_POOL_CONFIG = "/SM2Pool.properties";
    public static final String SM3_POOL_CONFIG = "/SM3Pool.properties";
    public static final String SM4_POOL_CONFIG = "/SM4Pool.properties";

    public static Properties loadConfig(InputStream in) throws IOException {
        Properties properties = new Properties();
        properties.load(in);
        in.close();
        return properties;
    }
}