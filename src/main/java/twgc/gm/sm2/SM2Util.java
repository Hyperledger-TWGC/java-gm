package twgc.gm.sm2;

import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import javax.security.auth.x500.X500Principal;

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
import twgc.gm.consts.Const;
import twgc.gm.random.SecureRandomFactory;

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
     * @throws InvalidAlgorithmParameterException 当采用的 ECC 算法不适用于该密钥对生成器时
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
        OutputEncryptor encryptor = null;
        if (password != null && password.length() > 0) {
            encryptor = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.AES_256_CBC)
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .setRandom(SecureRandomFactory.getSecureRandom())
                    .setPasssword(password.toCharArray())
                    .build();
        }
        PKCS8Generator generator = new JcaPKCS8Generator(privateKey, encryptor);
        StringWriter stringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);
        pemWriter.writeObject(generator);
        pemWriter.close();
        stringWriter.close();
        return stringWriter.toString();
    }


    public static String pemFrom(PublicKey publicKey) throws IOException {
        PemObject pem = new PemObject("PUBLIC KEY", publicKey.getEncoded());
        StringWriter str = new StringWriter();
        PemWriter pemWriter = new PemWriter(str);
        pemWriter.writeObject(pem);
        pemWriter.close();
        str.close();
        return str.toString();
    }

    /**
     * 打印 OpenSSL PEM 格式文件字符串的 SSL 证书请求 CSR 文件内容
     *
     * @param csr 证书请求对象
     */
    public static String pemFrom(PKCS10CertificationRequest csr) throws IOException {
        PemObject pem = new PemObject("CERTIFICATE REQUEST", csr.getEncoded());
        StringWriter str = new StringWriter();
        PemWriter pemWriter = new PemWriter(str);
        pemWriter.writeObject(pem);
        pemWriter.close();
        str.close();
        return str.toString();
    }

    public static String pemFrom(X509Certificate x509Certificate) throws IOException, CertificateEncodingException {
        PemObject pem = new PemObject("CERTIFICATE", x509Certificate.getEncoded());
        StringWriter str = new StringWriter();
        PemWriter pemWriter = new PemWriter(str);
        pemWriter.writeObject(pem);
        pemWriter.close();
        str.close();
        return str.toString();
    }

    public static PrivateKey loadPrivFromFile(String filename, String password) throws IOException, OperatorCreationException, PKCSException {
        FileReader fr = new FileReader(filename);
        PEMParser pemReader = new PEMParser(fr);
        Object obj = pemReader.readObject();
        PrivateKey priv = null;
        fr.close();
        pemReader.close();
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
        return priv;
    }


    public static PublicKey loadPublicFromFile(String filename) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        FileReader fr = new FileReader(filename);
        PemObject spki = new PemReader(fr).readPemObject();
        fr.close();
        Provider p = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        return KeyFactory.getInstance(Const.EC_VALUE, BouncyCastleProvider.PROVIDER_NAME).generatePublic(new X509EncodedKeySpec(spki.getContent()));
    }

    public static X509Certificate loadX509CertificateFromFile(String filename) throws IOException, CertificateException,
            NoSuchProviderException {
            FileInputStream in = null;
            in = new FileInputStream(filename);
            CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
            return (X509Certificate) cf.generateCertificate(in);
    }

    public static PublicKey derivePublicFromPrivate(PrivateKey privateKey) {
        BCECPrivateKey localECPrivateKey = (BCECPrivateKey) privateKey;
        BigInteger d = localECPrivateKey.getD();
        ECPoint ecpoint = new FixedPointCombMultiplier().multiply(GMNamedCurves.getByName(Const.CURVE_NAME).getG(), d);
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(ecpoint, PARAMETER_SPEC);
        return new BCECPublicKey(privateKey.getAlgorithm(), pubKeySpec,
                BouncyCastleProvider.CONFIGURATION);
    }
}