package cert;

import java.math.BigInteger;

/**
 * @author liqs
 * @version 1.0
 * @date 2021/1/19 14:27
 * 参考：https://github.com/ZZMarquis/gmhelper
 */
public interface CertSNAllocator {
    BigInteger nextSerialNumber() throws Exception;
}
