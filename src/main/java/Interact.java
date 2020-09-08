import java.io.IOException;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 * CSR 生成工具类
 *
 * @author 吴仙杰
 * @see <a href="https://www.pixelstech.net/article/1464167276-Generating-CSR-using-Java">Generating CSR using Java</a>
 * @see <a href="http://senthadev.com/generating-csr-using-java-and-bouncycastle-api.html">
 * Generating CSR using Java and BouncyCastle API</a>
 * @see <a href="https://github.com/Trisia/alg-sm2-demo">Trisia/alg-sm2-demo</a>
 */
public class Interact {

    private Interact() {

    }
    /**
     * 算法提供者 Bouncy Castle
     */
    private static final Provider BC = new BouncyCastleProvider();

    /**
     * 生成 PKCS#10 证书请求
     *
     * @param isRsaNotEcc {@code true}：使用 RSA 加密算法；{@code false}：使用 ECC（SM2）加密算法
     * @return RSA P10 证书请求 Base64 字符串
     * @throws NoSuchAlgorithmException  当指定的密钥对算法不支持时
     * @throws InvalidAlgorithmParameterException 当采用的 ECC 算法不适用于该密钥对生成器时
     * @throws OperatorCreationException 当创建签名者对象失败时
     * @throws IOException               当打印 OpenSSL PEM 格式文件字符串失败时
     */
    public static String generateCsr(boolean isRsaNotEcc) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, OperatorCreationException, IOException {
        // 使用 RSA/ECC 算法，生成密钥对（公钥、私钥）
        KeyPairGenerator generator = KeyPairGenerator.getInstance(isRsaNotEcc ? "RSA" : "EC", BC);
        if (isRsaNotEcc) {
            // RSA
            generator.initialize(2048);
        } else {
            // ECC
            generator.initialize(new ECGenParameterSpec("sm2p256v1"));
        }
        KeyPair keyPair = generator.generateKeyPair();
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
                .setProvider(BC)
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
