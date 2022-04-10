package twgc.gm.sm2;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import twgc.gm.consts.Const;

/**
 * @author liqs
 * @version 1.0
 * @date 2021/1/19 14:26
 * ref：https://github.com/ZZMarquis/gmhelper
 */
public class SM2X509CertFactory {

    private enum CertLevel {
        RootCA,
        SubCA
        //EndEntity
    } // class CertLevel

    private X500Name issuerDN;
    private KeyPair issuerKeyPair;
    private String commonName;
    private List<GeneralName> subjectAltNames = new LinkedList<>();
    private boolean selfSignedEECert;
    private JcaX509ExtensionUtils extUtils;
    /**
     * @param issuerKeyPair 证书颁发者的密钥对。
     * @param issuer        证书颁发者信息
     */
    public SM2X509CertFactory(KeyPair issuerKeyPair, X500Name issuer) throws NoSuchAlgorithmException {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        this.issuerKeyPair = issuerKeyPair;
        this.issuerDN = issuer;
        this.extUtils = new JcaX509ExtensionUtils();
    }

    /**
     * 生成RootCA证书
     * @param csr
     * @param mail
     * @throws Exception
     */
    public X509Certificate rootCACert(byte[] csr, String mail,
                                      BigInteger serial,
                                      Date notBefore,
                                      Date notAfter) throws OperatorCreationException, InvalidKeyException, NoSuchAlgorithmException, IOException, SignatureException, NoSuchProviderException, CertificateException {
        KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        PKCS10CertificationRequest request = new PKCS10CertificationRequest(csr);
        X500Name subject = request.getSubject();
        if (!issuerDN.equals(subject)) {
            throw new IllegalArgumentException("subject != issuer for certLevel " + CertLevel.RootCA);
        }
        X509v3CertificateBuilder v3CertGen = genX509v3CertificateBuilder(CertLevel.RootCA, request, mail, serial, notBefore, notAfter);
        if (!selfSignedEECert) {
            v3CertGen.addExtension(Extension.authorityKeyIdentifier, false,
                    extUtils.createAuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(issuerKeyPair.getPublic().getEncoded())));
        }
        BasicConstraints basicConstraints = new BasicConstraints(true);
        return certificate(CertLevel.RootCA, usage, basicConstraints, request, v3CertGen);
    }

    /**
     * 生成SubCA证书
     *
     * @param csr CSR
     * @param mail
     * @throws Exception 如果错误发生
     */
    public X509Certificate subCACert(byte[] csr, String mail,
                                     BigInteger serial,
                                     Date notBefore,
                                     Date notAfter) throws OperatorCreationException, InvalidKeyException, NoSuchAlgorithmException, IOException, SignatureException, NoSuchProviderException, CertificateException {
        KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        BasicConstraints basicConstraints = new BasicConstraints(0);
        PKCS10CertificationRequest request = new PKCS10CertificationRequest(csr);
        X500Name subject = request.getSubject();
        if (issuerDN.equals(subject)) {
            throw new IllegalArgumentException(
                    "subject MUST not equals issuer for certLevel " + CertLevel.SubCA);
        }
        X509v3CertificateBuilder v3CertGen = genX509v3CertificateBuilder(CertLevel.SubCA, request, mail, serial, notBefore, notAfter);
        return certificate(CertLevel.SubCA, usage, basicConstraints, request, v3CertGen);
    }

    private X509Certificate certificate(CertLevel certLevel,
                                        KeyUsage keyUsage, //KeyPurposeId[] extendedKeyUsages
                                        BasicConstraints basicConstraints,
                                        PKCS10CertificationRequest request,
                                        X509v3CertificateBuilder v3CertGen) throws IOException, OperatorCreationException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        /*if (certLevel == CertLevel.EndEntity) {
            if (keyUsage.hasUsages(KeyUsage.keyCertSign)) {
                throw new IllegalArgumentException("key usage keyCertSign is not allowed in EndEntity Certificate");
            }
        }*/
        X509Certificate cert = null;
        SubjectPublicKeyInfo subPub = request.getSubjectPublicKeyInfo();
        v3CertGen.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(subPub));
        v3CertGen.addExtension(Extension.basicConstraints, true, basicConstraints);
        v3CertGen.addExtension(Extension.keyUsage, true, keyUsage);

       /*
       comments so far as no invoked and used code branch
       if (extendedKeyUsages != null) {
            ExtendedKeyUsage xku = new ExtendedKeyUsage(extendedKeyUsages);
            v3CertGen.addExtension(Extension.extendedKeyUsage, false, xku);
            boolean forSSLServer = false;
            for (KeyPurposeId purposeId : extendedKeyUsages) {
                if (KeyPurposeId.id_kp_serverAuth.equals(purposeId)) {
                    forSSLServer = true;
                    break;
                }
            }
            if (forSSLServer) {
                if (commonName == null) {
                    throw new IllegalArgumentException("commonName must not be null");
                }
                GeneralName name = new GeneralName(GeneralName.dNSName, new DERIA5String(commonName, true));
                subjectAltNames.add(name);
            }
        } */

        if (!subjectAltNames.isEmpty()) {
            v3CertGen.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(subjectAltNames.toArray(new GeneralName[0])));
        }

        JcaContentSignerBuilder contentSignerBuilder = makeContentSignerBuilder(issuerKeyPair.getPublic());
        if (contentSignerBuilder != null) {
            cert = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(v3CertGen.build(contentSignerBuilder.build(issuerKeyPair.getPrivate())));
            cert.verify(issuerKeyPair.getPublic());
        }
        return cert;
    }

    private JcaContentSignerBuilder makeContentSignerBuilder(PublicKey issPub) {
        JcaContentSignerBuilder contentSignerBuilder = null;
        if (issPub.getAlgorithm().equals(Const.EC_VALUE)) {
            contentSignerBuilder = new JcaContentSignerBuilder(Const.SM3SM2_VALUE);
            contentSignerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        }
        return contentSignerBuilder;
    }

    private X509v3CertificateBuilder genX509v3CertificateBuilder(CertLevel certLevel,
                                                                 PKCS10CertificationRequest request,
                                                                 String email,
                                                                 BigInteger serial,
                                                                 Date notBefore,
                                                                 Date notAfter) {

        SubjectPublicKeyInfo subPub = request.getSubjectPublicKeyInfo();
        X500Name subject = request.getSubject();
        /*
         * RFC 5280 §4.2.1.6 Subject
         *  Conforming implementations generating new certificates with
         *  electronic mail addresses MUST use the rfc822Name in the subject
         *  alternative name extension (Section 4.2.1.6) to describe such
         *  identities.  Simultaneous inclusion of the emailAddress attribute in
         *  the subject distinguished name to support legacy implementations is
         *  deprecated but permitted.
         */
        RDN[] rdns = subject.getRDNs();
        List<RDN> newRdns = new ArrayList<>(rdns.length);
        for (int i = 0; i < rdns.length; i++) {
            RDN rdn = rdns[i];

            AttributeTypeAndValue atv = rdn.getFirst();
            ASN1ObjectIdentifier type = atv.getType();
            if (BCStyle.EmailAddress.equals(type)) {
                email = IETFUtils.valueToString(atv.getValue());
            } else {
                if (BCStyle.CN.equals(type)) {
                    commonName = IETFUtils.valueToString(atv.getValue());
                }
                newRdns.add(rdn);
            }
        }

        if (email != null) {
            subject = new X500Name(newRdns.toArray(new RDN[0]));
            subjectAltNames.add(
                    new GeneralName(GeneralName.rfc822Name,
                            new DERIA5String(email, true)));
        }

        if (issuerDN.equals(subject)) {
            selfSignedEECert = true;
        }
        return new X509v3CertificateBuilder(
                issuerDN, serial,
                notBefore, notAfter,
                subject, subPub);
    }

}
