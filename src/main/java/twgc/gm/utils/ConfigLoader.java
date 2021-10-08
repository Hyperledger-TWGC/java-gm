package twgc.gm.utils;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

import org.yaml.snakeyaml.Yaml;
/**
 * @author Sean
 * @Description: 配置文件加载工具类
 * @date 2021/9/25
 */
public class ConfigLoader {

    private ConfigLoader() {

    }

    private static final Yaml yaml = new Yaml();

    public static Map<String, Map<String, Object>> loadConfig(InputStream in) throws IOException {
        Map<String, Map<String, Object>> ret =  yaml.load(in);
        in.close();
        return ret;
    }

    public static Map<String, Object> loadConfig(InputStream in, String algorithm) throws IOException {
        return loadConfig(in).get(algorithm);
    }
}
