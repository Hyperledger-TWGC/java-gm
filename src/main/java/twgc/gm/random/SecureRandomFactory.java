package twgc.gm.random;

import java.security.SecureRandom;

/**
 * @author Sean
 * @Description: SecureRandomHolder
 * @date 2021/6/13
 */
public class SecureRandomFactory {

    private SecureRandomFactory() { }

    public static SecureRandom getSecureRandom() {
        return SecureRandomFactory.CachedSecureRandomHolder.instance;
    }

    private static class CachedSecureRandomHolder {
        public static SecureRandom instance = new SecureRandom();

        private CachedSecureRandomHolder() {
        }
    }
}
