package twgc.gm.sm2;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.*;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import twgc.gm.random.SecureRandomFactory;
import twgc.gm.utils.Const;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.function.Supplier;

/**
 * @author SamYuan; 吴仙杰
 * @Description 国密SM2工具类, 算法提供者 Bouncy Castle
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

    public SM2Util() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        signature = Signature.getInstance(Const.SM3SM2_VALUE, BouncyCastleProvider.PROVIDER_NAME);
        generator = KeyPairGenerator.getInstance(Const.EC_VALUE, BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(new ECGenParameterSpec(Const.CURVE_NAME));
    }

    public Signature getSignature() {
        return signature;
    }

    public void setSignature(Signature signature) {
        this.signature = signature;
    }

    private Signature signature;
    private static final X9ECParameters X_9_EC_PARAMETERS = GMNamedCurves.getByName(Const.CURVE_NAME);
    private static final ECDomainParameters EC_DOMAIN_PARAMETERS = new ECDomainParameters(X_9_EC_PARAMETERS.getCurve(), X_9_EC_PARAMETERS.getG(), X_9_EC_PARAMETERS.getN());
    private static final ECParameterSpec PARAMETER_SPEC = new ECParameterSpec(X_9_EC_PARAMETERS.getCurve(), X_9_EC_PARAMETERS.getG(), X_9_EC_PARAMETERS.getN());
    private static KeyPairGenerator generator;
    private static final JcaPEMKeyConverter CONVERTER = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);


    /**
     * 生成 PKCS#10 证书请求
     *
     * @return RSA P10 证书请求 Base64 字符串
     */
    public KeyPair generatekeyPair() {
        return generator.generateKeyPair();
    }

    public byte[] encrypt(SM2Engine sm2Engine, PublicKey publicKey, byte[] message) throws InvalidCipherTextException {
        BCECPublicKey localECPublicKey = (BCECPublicKey) publicKey;
        ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(localECPublicKey.getQ(), EC_DOMAIN_PARAMETERS);
        sm2Engine.init(true, new ParametersWithRandom(ecPublicKeyParameters, SecureRandomFactory.getSecureRandom()));
        return sm2Engine.processBlock(message, 0, message.length);
    }

    public byte[] decrypt(SM2Engine sm2Engine, PrivateKey privateKey, byte[] message) throws InvalidCipherTextException {
        BCECPrivateKey localECPrivateKey = (BCECPrivateKey) privateKey;
        ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(localECPrivateKey.getD(), EC_DOMAIN_PARAMETERS);
        sm2Engine.init(false, ecPrivateKeyParameters);
        return sm2Engine.processBlock(message, 0, message.length);
    }

    public byte[] sign(PrivateKey privateKey, byte[] message) throws SignatureException, InvalidKeyException {
        synchronized (this) {
            signature.initSign(privateKey, SecureRandomFactory.getSecureRandom());
            signature.update(message);
            return signature.sign();
        }
    }

    public boolean verify(PublicKey publicKey, byte[] message, byte[] sigBytes) throws InvalidKeyException, SignatureException {
        synchronized (this) {
            signature.initVerify(publicKey);
            signature.update(message);
            return signature.verify(sigBytes);
        }
    }

    public static PKCS10CertificationRequest generateCSR(KeyPair keyPair, X500Principal subject) throws OperatorCreationException {
        ContentSigner signer = new JcaContentSignerBuilder("SM3withSM2").build(keyPair.getPrivate());
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());
        return builder.build(signer);
    }

    public static String pemFrom(PrivateKey privateKey, String password) throws OperatorCreationException, IOException {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
            OutputEncryptor encryptor = null;
            if (password != null && password.length() > 0) {
                encryptor = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.AES_256_CBC)
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .setRandom(SecureRandomFactory.getSecureRandom())
                        .setPasssword(password.toCharArray())
                        .build();
            }
            PKCS8Generator generator = new JcaPKCS8Generator(privateKey, encryptor);
            pemWriter.writeObject(generator);
        }
        return sw.toString();
    }

    public static String pemFrom(PublicKey publicKey) throws IOException {
        StringWriter sw = new StringWriter();
        try (PemWriter pemWriter = new PemWriter(sw)) {
            PemObject pem = new PemObject("PUBLIC KEY", publicKey.getEncoded());
            pemWriter.writeObject(pem);
        }
        return sw.toString();
    }

    /**
     * 打印 OpenSSL PEM 格式文件字符串的 SSL 证书请求 CSR 文件内容
     *
     * @param csr 证书请求对象
     */
    public static String pemFrom(PKCS10CertificationRequest csr) throws IOException {
        StringWriter sw = new StringWriter();
        try (PemWriter pemWriter = new PemWriter(sw)) {
            PemObject pem = new PemObject("CERTIFICATE REQUEST", csr.getEncoded());
            pemWriter.writeObject(pem);
        }
        return sw.toString();
    }

    public static String pemFrom(X509Certificate x509Certificate) throws IOException, CertificateEncodingException {
        StringWriter sw = new StringWriter();
        try (PemWriter pemWriter = new PemWriter(sw)) {
            PemObject pem = new PemObject("CERTIFICATE", x509Certificate.getEncoded());
            pemWriter.writeObject(pem);
        }
        return sw.toString();
    }

    public static PrivateKey loadPrivFromFile(String filename, String password) throws IOException, OperatorCreationException, PKCSException {
        PrivateKey priv = null;
        try (PEMParser pemParser = new PEMParser(new FileReader(filename))) {
            Object obj = pemParser.readObject();
            if (password != null && password.length() > 0) {
                if (obj instanceof PKCS8EncryptedPrivateKeyInfo) {
                    PKCS8EncryptedPrivateKeyInfo epkInfo = (PKCS8EncryptedPrivateKeyInfo) obj;
                    InputDecryptorProvider decryptor = new JceOpenSSLPKCS8DecryptorProviderBuilder()
                            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                            .build(password.toCharArray());
                    PrivateKeyInfo pkInfo = epkInfo.decryptPrivateKeyInfo(decryptor);
                    priv = CONVERTER.getPrivateKey(pkInfo);
                }
            } else {
                priv = CONVERTER.getPrivateKey((PrivateKeyInfo) obj);
            }
        }
        return priv;
    }

    public static PublicKey loadPublicFromFile(String filename) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        try (PemReader pemReader = new PemReader(new FileReader(filename))) {
            PemObject spki = pemReader.readPemObject();
            Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
            return KeyFactory.getInstance(Const.EC_VALUE, BouncyCastleProvider.PROVIDER_NAME).generatePublic(new X509EncodedKeySpec(spki.getContent()));
        }
    }

    public static X509Certificate loadX509CertificateFromFile(String filename) throws IOException, CertificateException,
            NoSuchProviderException {
        try (FileInputStream in = new FileInputStream(filename)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
            return (X509Certificate) cf.generateCertificate(in);
        }
    }

    /**
     * 从字符串加载私钥
     *
     * @param privateKey 字符串字私钥
     * @param password   密码
     * @return {@link PrivateKey} 私钥对象
     * @throws IOException
     * @throws OperatorCreationException
     * @throws PKCSException
     */
    public static PrivateKey loadPrivFromString(String privateKey, String password) throws IOException, OperatorCreationException, PKCSException {
        return loadPriv(password, () -> new StringReader(privateKey));
    }

    /**
     * 从字符串加载公钥
     *
     * @param publicKey 字符串公钥
     * @return {@link PublicKey} 公钥对象
     * @throws IOException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PublicKey loadPublicFromString(String publicKey) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        return loadPublic(() -> new StringReader(publicKey));
    }

    /**
     * 从字符串加载证书
     *
     * @param cert 字符串证书
     * @return {@link X509Certificate} 证书对象
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchProviderException
     */
    public static X509Certificate loadX509CertificateFromString(String cert) throws IOException, CertificateException, NoSuchProviderException {
        try (InputStream in = new ByteArrayInputStream(cert.getBytes())) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
            return (X509Certificate) cf.generateCertificate(in);
        }
    }

    public static PublicKey derivePublicFromPrivate(PrivateKey privateKey) {
        BCECPrivateKey localECPrivateKey = (BCECPrivateKey) privateKey;
        BigInteger d = localECPrivateKey.getD();
        ECPoint ecpoint = new FixedPointCombMultiplier().multiply(GMNamedCurves.getByName(Const.CURVE_NAME).getG(), d);
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(ecpoint, PARAMETER_SPEC);
        return new BCECPublicKey(privateKey.getAlgorithm(), pubKeySpec,
                BouncyCastleProvider.CONFIGURATION);
    }

    public static PrivateKey loadPriv(String password, Supplier<Reader> fx) throws IOException, OperatorCreationException, PKCSException {
        PrivateKey priv = null;
        try (PEMParser pemParser = new PEMParser(fx.get())) {
            Object obj = pemParser.readObject();
            if (password != null && password.length() > 0) {
                if (obj instanceof PKCS8EncryptedPrivateKeyInfo) {
                    PKCS8EncryptedPrivateKeyInfo epkInfo = (PKCS8EncryptedPrivateKeyInfo) obj;
                    InputDecryptorProvider decryptor = new JceOpenSSLPKCS8DecryptorProviderBuilder()
                            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                            .build(password.toCharArray());
                    PrivateKeyInfo pkInfo = epkInfo.decryptPrivateKeyInfo(decryptor);
                    priv = CONVERTER.getPrivateKey(pkInfo);
                }
            } else {
                priv = CONVERTER.getPrivateKey((PrivateKeyInfo) obj);
            }
        }
        return priv;
    }

    public static PublicKey loadPublic(Supplier<Reader> fx) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        try (PemReader pemReader = new PemReader(fx.get())) {
            PemObject spki = pemReader.readPemObject();
            Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
            return KeyFactory.getInstance(Const.EC_VALUE, BouncyCastleProvider.PROVIDER_NAME).generatePublic(new X509EncodedKeySpec(spki.getContent()));
        }
    }
}