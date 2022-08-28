package twgc.gm.sm2sm3;

import java.security.*;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import twgc.gm.random.SecureRandomFactory;
import twgc.gm.sm3.SM3Util;
import twgc.gm.utils.Const;

public class SM2SM3Util {
    private Signature signature;

    public SM2SM3Util() throws NoSuchProviderException, NoSuchAlgorithmException {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        signature = Signature.getInstance(Const.SM3SM2_VALUE, BouncyCastleProvider.PROVIDER_NAME);
    }
    // Digest and Sign
    public byte[] digestAndSign(SM3Digest sm3Digest, PrivateKey privateKey, byte[] message) throws SignatureException, InvalidKeyException {
        byte[] hashVal = SM3Util.hash(sm3Digest, message);
        synchronized (this) {
            signature.initSign(privateKey, SecureRandomFactory.getSecureRandom());
            signature.update(hashVal);
            return signature.sign();
        }
    }
    // Verify Signature and Digest
    public boolean verifySignatureAndDigest(SM3Digest sm3Digest, PublicKey publicKey, byte[] message, byte[] sigBytes) throws InvalidKeyException, SignatureException {
        byte[] hashVal = SM3Util.hash(sm3Digest, message);
        synchronized (this) {
            signature.initVerify(publicKey);
            signature.update(hashVal);
            return signature.verify(sigBytes);
        }
    }
}
