import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;

public class MainActivity {

    public static void main(String[] args) {
        new MainActivity().start();
    }

    public void start() {
        Security.addProvider(new BouncyCastleProvider());

        try {
            makeNewRootCertificate();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void makeNewRootCertificate() throws Exception {
        KeyPair keyPair = generateKeyPairWithRSA();

        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.YEAR, -1);
        Date startDate = calendar.getTime();
        calendar.add(Calendar.YEAR, 20);
        Date endDate = calendar.getTime();

        BigInteger rootSerialNum = new BigInteger(Long.toString(Math.abs(new SecureRandom().nextLong())));

        X500Name rootCertIssuer = new X500Name("CN=TestRootCert");
        X500Name rootCertSubject = rootCertIssuer;
        ContentSigner rootCertContentSigner = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(keyPair.getPrivate());
        X509v3CertificateBuilder rootCertBuilder = new JcaX509v3CertificateBuilder(rootCertIssuer, rootSerialNum, startDate, endDate, rootCertSubject, keyPair.getPublic());

        X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootCertContentSigner);
        X509Certificate rootCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(rootCertHolder);

        printCertificate("TestRootCert", rootCert);

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

    public void printCertificate(String name, Certificate certificate) throws Exception {
        String cert = new String(Base64.encode(certificate.getEncoded()));
        char[] certArr = cert.toCharArray();

        System.out.println("#################################");
        System.out.println(name + " Certificate Made!");
        System.out.println("-----BEGIN CERTIFICATE-----");
        for(int i = 0; i < certArr.length; i++) {
            System.out.print(certArr[i]);
            if ((i + 1) % 65 == 0) {
                System.out.println();
            }
        }
        System.out.println();
        System.out.println("------END CERTIFICATE------");
        System.out.println("#################################");
    }
}
