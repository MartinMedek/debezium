/*
 * Copyright Debezium Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */
package io.debezium.testing.system.tools.databases.mongodb.sharded.certutil;

import io.fabric8.openshift.client.OpenShiftClient;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

public class CertificateGenerator {

    private static final Logger LOGGER = LoggerFactory.getLogger(CertificateGenerator.class);
    public static final String KEYSTORE_PASSWORD = "password";
    private static final String SIGNATURE_ALGORITHM = "SHA384WITHRSA";
    private final X500Name caSubject = new X500Name("c=IN, o=CertificateAuthority, ou=Root_CertificateAuthority, cn=RootCA");
//    private final String targetDirectory = getClass().getResource("/").getPath();

    private final List<LeafCertSpec> leafSpec;
    private final boolean exportPems;
    private final boolean exportKeyStores;
    private final OpenShiftClient ocp;

    private CertificateWrapper ca;

    public CertificateGenerator(List<LeafCertSpec> leafSpec, boolean exportPems, boolean exportKeyStores, OpenShiftClient ocp) {
        this.leafSpec = leafSpec;
        this.exportPems = exportPems;
        this.exportKeyStores = exportKeyStores;
        this.ocp = ocp;
    }

    public void generate() throws Exception {
        // generate keys and certificates
        ca = generateCa();
        if (exportPems) {
            writeCertToFile(convertToBase64PEMString(ca.getHolder()), "ca-cert.pem");
        }

        leafSpec.forEach(l -> {
            try {
                var cert = genLeafCert(ca, l.getSubject(), l.getExtensions());
                l.setCert(cert);

//                if (exportPems) {
//                    writeCertToFile(exportToPem(cert, ca), targetDirectory + l.getName() + ".pem");
//                }
                if (exportKeyStores) {
                    KeyStore ks = createKeyStore(l.getName(), cert.getKeyPair().getPrivate(), new X509Certificate[]{ convertHolderToCert(cert.getHolder()), convertHolderToCert(ca.getHolder()) });
                    ks.setCertificateEntry("ca", convertHolderToCert(ca.getHolder()));
//                    keyStoreToFile(ks, targetDirectory + l.getName() + ".jks");
                    l.setKeyStore(ks);
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    public CertificateWrapper generateCa() throws NoSuchAlgorithmException, IOException, CertificateException {
        Security.addProvider(new BouncyCastleProvider());
        KeyPair keyPair = generateKeyPair();

        long notBefore = System.currentTimeMillis();
        long notAfter = notBefore + (1000L * 3600L * 24 * 365); // one year from now
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                caSubject,
                BigInteger.ONE,
                new Date(notBefore),
                new Date(notAfter),
                caSubject,
                keyPair.getPublic());
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        var subjectKeyIdentifier = extUtils.createSubjectKeyIdentifier(keyPair.getPublic());
        var authorityKeyIdentifier = extUtils.createAuthorityKeyIdentifier(keyPair.getPublic());

        X509CertificateHolder certHolder;
        List<CertificateExtensionWrapper> extensions = List.of(
                new CertificateExtensionWrapper(Extension.basicConstraints, true, new BasicConstraints(true)),
                new CertificateExtensionWrapper(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign)),
                new CertificateExtensionWrapper(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier),
                new CertificateExtensionWrapper(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier)
        );
        try {
            extensions.forEach(e -> {
                try {
                    certBuilder.addExtension(e.getIdentifier(), e.isCritical(), e.getValue());
                } catch (CertIOException ex) {
                    throw new RuntimeException(ex);
                }
            });

            final ContentSigner signer = new JcaContentSignerBuilder((SIGNATURE_ALGORITHM)).build(keyPair.getPrivate());
            certHolder = certBuilder.build(signer);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        writeCertToFile(convertToBase64PEMString(certHolder), "ca-cert.pem");

        return CertificateWrapper.builder()
                .withKeyPair(keyPair)
                .withExtensions(extensions)
                .withSubject(new String(caSubject.getEncoded()))
                .withHolder(certHolder)
                .build();
    }

    public CertificateWrapper genLeafCert(CertificateWrapper ca, String subject, List<CertificateExtensionWrapper> extensions) throws OperatorCreationException, NoSuchAlgorithmException, CertIOException {
        KeyPair keyPair = generateKeyPair();

        long notBefore = System.currentTimeMillis();
        long notAfter = notBefore + (1000L * 3600L * 24 * 365);

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(caSubject,
                new BigInteger(String.valueOf(System.currentTimeMillis())), new Date(notBefore), new Date(notAfter), new X500Name(subject), keyPair.getPublic());

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        var newExtensions = new LinkedList<>(extensions);
        newExtensions.add(new CertificateExtensionWrapper(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(keyPair.getPublic())));
        newExtensions.add(new CertificateExtensionWrapper(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(ca.getKeyPair().getPublic())));
        newExtensions.forEach(e -> {
            try {
                certBuilder.addExtension(e.getIdentifier(), e.isCritical(), e.getValue());
            } catch (CertIOException ex) {
                throw new RuntimeException(ex);
            }
        });

        ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(ca.getKeyPair().getPrivate());
        var holder = certBuilder.build(signer);

        return CertificateWrapper.builder()
                .withSubject(subject)
                .withKeyPair(keyPair)
                .withExtensions(newExtensions)
                .withHolder(holder)
                .build();
    }

    public List<LeafCertSpec> getLeafSpec() {
        return leafSpec;
    }

    public LeafCertSpec getLeafSpec(String name) {
        var spec = leafSpec.stream().filter(l -> l.getName().equals(name)).findFirst();
        if (spec.isEmpty()) {
            throw new IllegalStateException("Certificate not found in generated certs list");
        }
        return spec.get();
    }

    private void writeCertToFile(String data, String path) throws IOException {
        File file = new File(path);
        file.createNewFile();

        try {
            Files.write(file.toPath(), data.getBytes());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public String exportToPem(CertificateWrapper cert, CertificateWrapper ca) throws IOException, CertificateException {
        return convertToBase64PEMString(cert.getKeyPair().getPrivate()) +
                convertToBase64PEMString(cert.getHolder()) +
                convertToBase64PEMString(ca.getHolder());
    }

    public String convertToBase64PEMString(X509CertificateHolder holder) throws CertificateException, IOException {
        return convertToBase64PEMString(convertHolderToCert(holder));
    }

    private X509Certificate convertHolderToCert(X509CertificateHolder holder) throws CertificateException {
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        converter.setProvider(new BouncyCastleProvider());
        return converter.getCertificate(holder);
    }

    public String convertToBase64PEMString(X509Certificate x509Cert) throws IOException {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            pw.writeObject(x509Cert);
        }
        return sw.toString();
    }

    public static String decodeBase64(String string) throws UnsupportedEncodingException {
            byte[] dst = new byte[]{};
            Base64.getDecoder().decode(string.getBytes("UTF-8"), dst);
            return new String(dst);
    }

    public String convertToBase64PEMString(PrivateKey privateKey) throws IOException {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            pw.writeObject(privateKey);
        }
        return sw.toString();
    }

    private KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(3072, new SecureRandom());
            return keyPairGenerator.generateKeyPair();
        } catch (GeneralSecurityException var2) {
            throw new AssertionError(var2);
        }
    }

    public static KeyStore createKeyStore(String alias, PrivateKey privateKey, Certificate[] certificates)
            throws Exception {
        final KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(null);
        // Import private key
        keystore.setKeyEntry(alias, privateKey, KEYSTORE_PASSWORD.toCharArray(), certificates);
        return keystore;
    }

    public static void keyStoreToFile(KeyStore keyStore, String filePath) throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException {
        char[] pwdArray = KEYSTORE_PASSWORD.toCharArray();
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            keyStore.store(fos, pwdArray);
        }
    }



    public static CertificateGeneratorBuilder builder() {
        return new CertificateGeneratorBuilder();
    }

    public CertificateWrapper getCa() {
        return ca;
    }

    public static final class CertificateGeneratorBuilder {
        private List<LeafCertSpec> leafSpec;
        private boolean exportPems;
        private boolean exportKeyStores;
        private OpenShiftClient ocp;

        private CertificateGeneratorBuilder() {
        }

        public CertificateGeneratorBuilder withLeafSpec(List<LeafCertSpec> leafSpec) {
            this.leafSpec = leafSpec;
            return this;
        }

        public CertificateGeneratorBuilder withExportPems(boolean exportPems) {
            this.exportPems = exportPems;
            return this;
        }

        public CertificateGeneratorBuilder withExportKeyStores(boolean exportKeyStores) {
            this.exportKeyStores = exportKeyStores;
            return this;
        }

        public CertificateGeneratorBuilder withOcp(OpenShiftClient ocp) {
            this.ocp = ocp;
            return this;
        }

        public CertificateGenerator build() {
            return new CertificateGenerator(leafSpec, exportPems, exportKeyStores, ocp);
        }
    }
}
