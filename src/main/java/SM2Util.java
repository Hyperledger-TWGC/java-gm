import java.io.IOException;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 * @author SamYuan
 * @co-author 吴仙杰
 * @Description: 国密SM2工具类
 * @date 2020/10
 * ref:
 * https://tools.ietf.org/html/draft-shen-sm2-ecdsa-02
 * http://gmssl.org/docs/oid.html
 * http://www.jonllen.com/jonllen/work/164.aspx
 * https://blog.csdn.net/Vincent2014Linux/article/details/108668186
 * https://www.pixelstech.net/article/1464167276-Generating-CSR-using-Java
 * http://senthadev.com/generating-csr-using-java-and-bouncycastle-api.html
 * https://github.com/Trisia/alg-sm2-demo
*/
public class SM2Util {

    private SM2Util() {

    }
    /**
     * 算法提供者 Bouncy Castle
     */

    private static final String BC_VALUE = "BC";
    private static final String EC_VALUE = "EC";
    private static final String SM3SM2_VALUE = "SM3withSM2";
    private static X9ECParameters x9ECParameters = GMNamedCurves.getByName("sm2p256v1");

    private static ECDomainParameters ecDomainParameters = new ECDomainParameters(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN());

    static {
        if (Security.getProvider(BC_VALUE) == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }
    /**
     * 生成 PKCS#10 证书请求
     *
     * @return RSA P10 证书请求 Base64 字符串
     * @throws NoSuchAlgorithmException  当指定的密钥对算法不支持时
     * @throws InvalidAlgorithmParameterException 当采用的 ECC 算法不适用于该密钥对生成器时
     * */
    public static KeyPair generatekeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(EC_VALUE, BC_VALUE);
        generator.initialize(new ECGenParameterSpec("sm2p256v1"));
        KeyPair keyPair = generator.generateKeyPair();
        return keyPair;
    }

    public static Signature generateSignature() throws NoSuchAlgorithmException, NoSuchProviderException {
        Signature signature = Signature.getInstance(SM3SM2_VALUE, BC_VALUE);
        return signature;
    }

    public static byte[] encrypt(PublicKey publicKey, byte[] message) throws InvalidCipherTextException {
        BCECPublicKey localECPublicKey = (BCECPublicKey) publicKey;
        ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(localECPublicKey.getQ(), ecDomainParameters);
        SM2Engine sm2Engine = new SM2Engine();
        sm2Engine.init(true, new ParametersWithRandom(ecPublicKeyParameters, new SecureRandom()));
        return sm2Engine.processBlock(message, 0, message.length);
    }

    public static byte[] decrypt(PrivateKey privateKey, byte[] message) throws InvalidCipherTextException {
        BCECPrivateKey localECPrivateKey = (BCECPrivateKey) privateKey;
        ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(localECPrivateKey.getD(), ecDomainParameters);
        SM2Engine sm2Engine = new SM2Engine();
        sm2Engine.init(false, ecPrivateKeyParameters);
        return sm2Engine.processBlock(message, 0, message.length);
    }

    public static byte[] sign(Signature signature, PrivateKey privateKey, byte[] message) throws SignatureException, InvalidKeyException {
        signature.initSign(privateKey,
                new SecureRandom());
        signature.update(message);
        byte[] sigBytes = signature.sign();
        return sigBytes;
    }

    public static boolean verify(Signature signature, PublicKey publicKey, byte[] message, byte[] sigBytes) throws InvalidKeyException, SignatureException {
        signature.initVerify(publicKey);
        signature.update(message);
        return signature.verify(sigBytes);
    }

    /**
     * @throws OperatorCreationException 当创建签名者对象失败时
     * @throws IOException               当打印 OpenSSL PEM 格式文件字符串失败时
     */
    public static String generateCsr(boolean isRsaNotEcc) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, OperatorCreationException, IOException, NoSuchProviderException {
        KeyPair keyPair = generatekeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // 打印私钥，注意：请务必保存您的私钥
        printOpensslPemFormatKeyFileContent(privateKey, isRsaNotEcc);

        // 按需添加证书主题项，
        // 有些 CSR 不需要我们在主题项中添加各字段,
        // 如 `C=CN, CN=吴仙杰, E=wuxianjiezh@gmail.com, OU=3303..., L=杭州, S=浙江`，
        // 而是通过额外参数提交，故这里我只简单地指定了国家码
        X500Principal subject = new X500Principal("C=CN");

        // 使用私钥和 SHA256WithRSA/SM3withSM2 算法创建签名者对象
        ContentSigner signer = new JcaContentSignerBuilder(isRsaNotEcc ? "SHA256WithRSA" : "SM3withSM2")
                .build(privateKey);

        // 创建 CSR
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, publicKey);
        PKCS10CertificationRequest csr = builder.build(signer);

        // 打印 OpenSSL PEM 格式文件字符串
        printOpensslPemFormatCsrFileContent(csr);

        // 以 Base64 字符串形式返回 CSR
        return Base64.getEncoder().encodeToString(csr.getEncoded());
    }

    /**
     * 打印 OpenSSL PEM 格式文件字符串的 SSL证书密钥 KEY 文件内容
     *
     * @param privateKey 私钥
     * @param isRsaNotEcc {@code true}：使用 RSA 加密算法；{@code false}：使用 ECC（SM2）加密算法
     */
    private static void printOpensslPemFormatKeyFileContent(PrivateKey privateKey, boolean isRsaNotEcc) throws IOException {
        PemObject pem = new PemObject(isRsaNotEcc ? "PRIVATE KEY" : "EC PRIVATE KEY", privateKey.getEncoded());
        StringWriter str = new StringWriter();
        PemWriter pemWriter = new PemWriter(str);
        pemWriter.writeObject(pem);
        pemWriter.close();
        str.close();

        System.out.println(str.toString());
        Files.write(Paths.get("./priv.pem"), str.toString().getBytes());

        //str.toString() => file
    }

    /**
     * 打印 OpenSSL PEM 格式文件字符串的 SSL 证书请求 CSR 文件内容
     *
     * @param csr 证书请求对象
     */
    private static void printOpensslPemFormatCsrFileContent(PKCS10CertificationRequest csr) throws IOException {
        PemObject pem = new PemObject("CERTIFICATE REQUEST", csr.getEncoded());
        StringWriter str = new StringWriter();
        PemWriter pemWriter = new PemWriter(str);
        pemWriter.writeObject(pem);
        pemWriter.close();
        str.close();

        System.out.println(str.toString());
        Files.write(Paths.get("./pub.pem"), str.toString().getBytes());
        //str.toString() => file
    }
}
