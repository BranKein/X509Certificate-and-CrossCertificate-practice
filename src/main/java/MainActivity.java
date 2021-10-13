import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

public class MainActivity {
    Date startDate;
    Date endDate;

    public X500Name rootCA_A_SubjectName;
    public KeyPair rootCA_A_KeyPair;
    public X509Certificate rootCA_A_Cert;

    public X500Name subCA1_A_SubjectName;
    public KeyPair subCA1_A_KeyPair;
    public X509Certificate subCA1_A_Cert;

    public X500Name subCA2_A_SubjectName;
    public KeyPair subCA2_A_KeyPair;
    public X509Certificate subCA2_A_Cert;

    public X500Name leaf_A_SubjectName;
    public KeyPair leaf_A_KeyPair;
    public X509Certificate leaf_A_Cert;

    public X500Name rootCA_B_SubjectName;
    public KeyPair rootCA_B_KeyPair;
    public X509Certificate rootCA_B_Cert;

    public X500Name subCA1_B_SubjectName;
    public KeyPair subCA1_B_KeyPair;
    public X509Certificate subCA1_B_Cert;

    public X500Name subCA2_B_SubjectName;
    public KeyPair subCA2_B_KeyPair;
    public X509Certificate subCA2_B_Cert;

    public X500Name leaf_B_SubjectName;
    public KeyPair leaf_B_KeyPair;
    public X509Certificate leaf_B_Cert;

    public X500Name cross_SubjectName;
    // public KeyPair cross_KeyPair;
    public X509Certificate cross_Cert;

    public static void main(String[] args) {
        new MainActivity().start();
    }

    public void start() {
        try {
            init();
            makeRootCA_A();
            makeCertChain_A();
            makeRootCA_B();
            makeCertChain_B();
            crossCert();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void crossCert() throws Exception {
        BigInteger cross_Serial = new BigInteger(Long.toString(Math.abs(new SecureRandom().nextLong())));

        X500Name cross_Issuer = rootCA_A_SubjectName;
        cross_SubjectName = new X500Name("CN=cross_cert");

        PKCS10CertificationRequestBuilder cross_p10Builder = new JcaPKCS10CertificationRequestBuilder(cross_SubjectName, subCA1_B_KeyPair.getPublic());
        JcaContentSignerBuilder cross_csrBuilder = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC");

        ContentSigner cross_csrContentSigner = cross_csrBuilder.build(rootCA_A_KeyPair.getPrivate());
        PKCS10CertificationRequest cross_csr = cross_p10Builder.build(cross_csrContentSigner);

        X509v3CertificateBuilder cross_Builder = new X509v3CertificateBuilder(
                cross_Issuer, cross_Serial, startDate, endDate, cross_csr.getSubject(), cross_csr.getSubjectPublicKeyInfo());
        X509CertificateHolder cross_CertHolder = cross_Builder.build(cross_csrContentSigner);
        cross_Cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(cross_CertHolder);

        // print Certificate
        printCertificate("cross Cert", cross_Cert);

        // chain validation
        List<Certificate> certChain = new ArrayList<Certificate>();
        certChain.add(leaf_B_Cert);
        certChain.add(subCA2_B_Cert);
        certChain.add(cross_Cert);
        certChain.add(rootCA_A_Cert);
        if (verifyChain(certChain)) {
            System.out.println("A Chain Verified!");
            System.out.println();
        } else {
            System.out.println("A Chain Not Verified...");
            System.out.println();
            throw new Exception();
        }
    }

    public void init() {
        Security.addProvider(new BouncyCastleProvider());

        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.YEAR, -1);
        startDate = calendar.getTime();
        calendar.add(Calendar.YEAR, 20);
        endDate = calendar.getTime();
    }

    public void makeRootCA_A() throws Exception {
        rootCA_A_KeyPair = generateKeyPairWithRSA();

        BigInteger rootSerialNum = new BigInteger(Long.toString(Math.abs(new SecureRandom().nextLong())));

        rootCA_A_SubjectName = new X500Name("CN=RootCA_A");
        ContentSigner rootCertContentSigner = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(rootCA_A_KeyPair.getPrivate());
        X509v3CertificateBuilder rootCertBuilder = new JcaX509v3CertificateBuilder(rootCA_A_SubjectName, rootSerialNum, startDate, endDate, rootCA_A_SubjectName, rootCA_A_KeyPair.getPublic());

        X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootCertContentSigner);
        rootCA_A_Cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(rootCertHolder);

        printCertificate("RootCA_A", rootCA_A_Cert);

    }

    public void makeRootCA_B() throws Exception {
        rootCA_B_KeyPair = generateKeyPairWithRSA();

        BigInteger rootSerialNum = new BigInteger(Long.toString(Math.abs(new SecureRandom().nextLong())));

        rootCA_B_SubjectName = new X500Name("CN=RootCA_B");
        ContentSigner rootCertContentSigner = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(rootCA_B_KeyPair.getPrivate());
        X509v3CertificateBuilder rootCertBuilder = new JcaX509v3CertificateBuilder(rootCA_B_SubjectName, rootSerialNum, startDate, endDate, rootCA_B_SubjectName, rootCA_B_KeyPair.getPublic());

        X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootCertContentSigner);
        rootCA_B_Cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(rootCertHolder);

        printCertificate("RootCA_B", rootCA_B_Cert);

    }

    public void makeCertChain_A() throws Exception {
        // Sub CA1 A
        subCA1_A_KeyPair = generateKeyPairWithRSA();
        BigInteger subCA1_A_Serial = new BigInteger(Long.toString(Math.abs(new SecureRandom().nextLong())));

        X500Name subCA1_A_Issuer = rootCA_A_SubjectName;
        subCA1_A_SubjectName = new X500Name("CN=SubCA1_A");

        PKCS10CertificationRequestBuilder subCA1_A_p10Builder = new JcaPKCS10CertificationRequestBuilder(subCA1_A_SubjectName, subCA1_A_KeyPair.getPublic());
        JcaContentSignerBuilder subCA1_A_csrBuilder = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC");

        ContentSigner subCA1_A_csrContentSigner = subCA1_A_csrBuilder.build(rootCA_A_KeyPair.getPrivate());
        PKCS10CertificationRequest subCA1_A_csr = subCA1_A_p10Builder.build(subCA1_A_csrContentSigner);

        X509v3CertificateBuilder subCA1_A_Builder = new X509v3CertificateBuilder(
                subCA1_A_Issuer, subCA1_A_Serial, startDate, endDate, subCA1_A_csr.getSubject(), subCA1_A_csr.getSubjectPublicKeyInfo());
        X509CertificateHolder subCA1_A_CertHolder = subCA1_A_Builder.build(subCA1_A_csrContentSigner);
        subCA1_A_Cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(subCA1_A_CertHolder);

        /*
        ###############################################################################################################################################################
         */

        // Sub CA2 A
        subCA2_A_KeyPair = generateKeyPairWithRSA();
        BigInteger subCA2_A_Serial = new BigInteger(Long.toString(Math.abs(new SecureRandom().nextLong())));

        X500Name subCA2_A_Issuer = subCA1_A_SubjectName;
        subCA2_A_SubjectName = new X500Name("CN=SubCA2_A");

        PKCS10CertificationRequestBuilder subCA2_A_p10Builder = new JcaPKCS10CertificationRequestBuilder(subCA2_A_SubjectName, subCA2_A_KeyPair.getPublic());
        JcaContentSignerBuilder subCA2_A_csrBuilder = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC");

        ContentSigner subCA2_A_csrContentSigner = subCA2_A_csrBuilder.build(subCA1_A_KeyPair.getPrivate());
        PKCS10CertificationRequest subCA2_A_csr = subCA2_A_p10Builder.build(subCA2_A_csrContentSigner);

        X509v3CertificateBuilder subCA2_A_Builder = new X509v3CertificateBuilder(
                subCA2_A_Issuer, subCA2_A_Serial, startDate, endDate, subCA2_A_csr.getSubject(), subCA2_A_csr.getSubjectPublicKeyInfo());
        X509CertificateHolder subCA2_A_CertHolder = subCA2_A_Builder.build(subCA2_A_csrContentSigner);
        subCA2_A_Cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(subCA2_A_CertHolder);

        /*
        ###############################################################################################################################################################
         */

        // Leaf A
        leaf_A_KeyPair = generateKeyPairWithRSA();
        BigInteger leaf_A_Serial = new BigInteger(Long.toString(Math.abs(new SecureRandom().nextLong())));

        X500Name leaf_A_Issuer = subCA2_A_SubjectName;
        leaf_A_SubjectName = new X500Name("CN=Leaf_A");

        PKCS10CertificationRequestBuilder leaf_A_p10Builder = new JcaPKCS10CertificationRequestBuilder(leaf_A_SubjectName, subCA2_A_KeyPair.getPublic());
        JcaContentSignerBuilder leaf_A_csrBuilder = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC");

        ContentSigner leaf_A_csrContentSigner = leaf_A_csrBuilder.build(subCA2_A_KeyPair.getPrivate());
        PKCS10CertificationRequest leaf_A_csr = leaf_A_p10Builder.build(leaf_A_csrContentSigner);

        X509v3CertificateBuilder leaf_A_Builder = new X509v3CertificateBuilder(
                leaf_A_Issuer, leaf_A_Serial, startDate, endDate, leaf_A_csr.getSubject(), leaf_A_csr.getSubjectPublicKeyInfo());
        X509CertificateHolder leaf_A_CertHolder = leaf_A_Builder.build(leaf_A_csrContentSigner);
        leaf_A_Cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(leaf_A_CertHolder);

        /*
        ###############################################################################################################################################################
         */

        // print certificate
        System.out.println("########################################################################################################");
        System.out.println("########################################################################################################");
        printCertificate("SubCA1_A", subCA1_A_Cert);
        printCertificate("SubCA2_A", subCA2_A_Cert);
        printCertificate("Leaf_A", leaf_A_Cert);
        System.out.println("########################################################################################################");
        System.out.println("########################################################################################################");

        /*
        ###############################################################################################################################################################
         */

        // chain validation
        List<Certificate> certChain = new ArrayList<Certificate>();
        certChain.add(leaf_A_Cert);
        certChain.add(subCA2_A_Cert);
        certChain.add(subCA1_A_Cert);
        certChain.add(rootCA_A_Cert);
        if (verifyChain(certChain)) {
            System.out.println("A Chain Verified!");
            System.out.println();
        } else {
            System.out.println("A Chain Not Verified...");
            System.out.println();
            throw new Exception();
        }
    }

    public void makeCertChain_B() throws Exception {
        // Sub CA1 B
        subCA1_B_KeyPair = generateKeyPairWithRSA();
        BigInteger subCA1_B_Serial = new BigInteger(Long.toString(Math.abs(new SecureRandom().nextLong())));

        X500Name subCA1_B_Issuer = rootCA_A_SubjectName;
        subCA1_B_SubjectName = new X500Name("CN=SubCA1_B");

        PKCS10CertificationRequestBuilder subCA1_B_p10Builder = new JcaPKCS10CertificationRequestBuilder(subCA1_B_SubjectName, subCA1_B_KeyPair.getPublic());
        JcaContentSignerBuilder subCA1_B_csrBuilder = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC");

        ContentSigner subCA1_B_csrContentSigner = subCA1_B_csrBuilder.build(rootCA_B_KeyPair.getPrivate());
        PKCS10CertificationRequest subCA1_B_csr = subCA1_B_p10Builder.build(subCA1_B_csrContentSigner);

        X509v3CertificateBuilder subCA1_B_Builder = new X509v3CertificateBuilder(
                subCA1_B_Issuer, subCA1_B_Serial, startDate, endDate, subCA1_B_csr.getSubject(), subCA1_B_csr.getSubjectPublicKeyInfo());
        X509CertificateHolder subCA1_B_CertHolder = subCA1_B_Builder.build(subCA1_B_csrContentSigner);
        subCA1_B_Cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(subCA1_B_CertHolder);

        /*
        ###############################################################################################################################################################
         */

        // Sub CA2 B
        subCA2_B_KeyPair = generateKeyPairWithRSA();
        BigInteger subCA2_B_Serial = new BigInteger(Long.toString(Math.abs(new SecureRandom().nextLong())));

        X500Name subCA2_B_Issuer = subCA1_B_SubjectName;
        subCA2_B_SubjectName = new X500Name("CN=SubCA2_B");

        PKCS10CertificationRequestBuilder subCA2_B_p10Builder = new JcaPKCS10CertificationRequestBuilder(subCA2_B_SubjectName, subCA2_B_KeyPair.getPublic());
        JcaContentSignerBuilder subCA2_B_csrBuilder = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC");

        ContentSigner subCA2_B_csrContentSigner = subCA2_B_csrBuilder.build(subCA1_B_KeyPair.getPrivate());
        PKCS10CertificationRequest subCA2_B_csr = subCA2_B_p10Builder.build(subCA2_B_csrContentSigner);

        X509v3CertificateBuilder subCA2_B_Builder = new X509v3CertificateBuilder(
                subCA2_B_Issuer, subCA2_B_Serial, startDate, endDate, subCA2_B_csr.getSubject(), subCA2_B_csr.getSubjectPublicKeyInfo());
        X509CertificateHolder subCA2_B_CertHolder = subCA2_B_Builder.build(subCA2_B_csrContentSigner);
        subCA2_B_Cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(subCA2_B_CertHolder);

        /*
        ###############################################################################################################################################################
         */

        // Leaf A
        leaf_B_KeyPair = generateKeyPairWithRSA();
        BigInteger leaf_B_Serial = new BigInteger(Long.toString(Math.abs(new SecureRandom().nextLong())));

        X500Name leaf_B_Issuer = subCA2_B_SubjectName;
        leaf_B_SubjectName = new X500Name("CN=Leaf_B");

        PKCS10CertificationRequestBuilder leaf_B_p10Builder = new JcaPKCS10CertificationRequestBuilder(leaf_B_SubjectName, subCA2_B_KeyPair.getPublic());
        JcaContentSignerBuilder leaf_B_csrBuilder = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC");

        ContentSigner leaf_B_csrContentSigner = leaf_B_csrBuilder.build(subCA2_B_KeyPair.getPrivate());
        PKCS10CertificationRequest leaf_B_csr = leaf_B_p10Builder.build(leaf_B_csrContentSigner);

        X509v3CertificateBuilder leaf_B_Builder = new X509v3CertificateBuilder(
                leaf_B_Issuer, leaf_B_Serial, startDate, endDate, leaf_B_csr.getSubject(), leaf_B_csr.getSubjectPublicKeyInfo());
        X509CertificateHolder leaf_B_CertHolder = leaf_B_Builder.build(leaf_B_csrContentSigner);
        leaf_B_Cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(leaf_B_CertHolder);

        /*
        ###############################################################################################################################################################
         */

        // print certificate
        System.out.println("########################################################################################################");
        System.out.println("########################################################################################################");
        printCertificate("SubCA1_B", subCA1_B_Cert);
        printCertificate("SubCA2_B", subCA2_B_Cert);
        printCertificate("Leaf_B", leaf_B_Cert);
        System.out.println("########################################################################################################");
        System.out.println("########################################################################################################");

        /*
        ###############################################################################################################################################################
         */

        // chain validation
        List<Certificate> certChain = new ArrayList<Certificate>();
        certChain.add(leaf_B_Cert);
        certChain.add(subCA2_B_Cert);
        certChain.add(subCA1_B_Cert);
        certChain.add(rootCA_B_Cert);
        if (verifyChain(certChain)) {
            System.out.println("B Chain Verified!");
            System.out.println();
        } else {
            System.out.println("B Chain Not Verified...");
            System.out.println();
            throw new Exception();
        }
    }

    public KeyPair generateKeyPairWithRSA() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    public KeyPair generateKeyPairWithSecp256r1() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("ECDSA", "BC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        generator.initialize(ecSpec, new SecureRandom());
        return generator.generateKeyPair();
    }

    public boolean verifyChain(List<Certificate> certChain) {
        try {
            for (int i = 0; i < certChain.size(); i++) {
                Certificate targetCert = certChain.get(i);
                X509Certificate x509TargetCert = (X509Certificate) targetCert;
                if (i == certChain.size() - 1) {
                    // RootCA
                    System.out.print("Certificating " + x509TargetCert.getSubjectDN().getName() + "...");
                    targetCert.verify(targetCert.getPublicKey(), "BC");
                } else {
                    // SubCA, Leaf
                    Certificate issuerCert = certChain.get(i + 1);
                    X509Certificate x509IssuerCert = (X509Certificate) issuerCert;
                    System.out.print("Certificating " + x509TargetCert.getSubjectDN().getName() + " with " + x509IssuerCert.getSubjectDN().getName() + "...");
                    targetCert.verify(issuerCert.getPublicKey(), "BC");
                }
                System.out.println("  Done!");
            }
        } catch (CertificateException | NoSuchAlgorithmException |
                InvalidKeyException | SignatureException | NoSuchProviderException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    public void printCertificate(String name, Certificate certificate) throws Exception {
        String cert = new String(Base64.encode(certificate.getEncoded()));
        char[] certArr = cert.toCharArray();

        System.out.println(name + " Certificate Made!");
        System.out.println("-----BEGIN CERTIFICATE-----");
        System.out.println(cert);
//        for(int i = 0; i < certArr.length; i++) {
//            System.out.print(certArr[i]);
//            if ((i + 1) % 65 == 0) {
//                System.out.println();
//            }
//        }
        System.out.println("------END CERTIFICATE------");
        System.out.println();
    }
}
