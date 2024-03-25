/*
 * Copyright Debezium Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */
package io.debezium.testing.system.tools.databases.mongodb.sharded.certutil;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

public class CertificateGenerator {

    public static final String KEYSTORE_PASSWORD = "password";
    private static final String SIGNATURE_ALGORITHM = "SHA384WITHRSA";
    private final X500Name caSubject = new X500Name("c=IN, o=CertificateAuthority, ou=Root_CertificateAuthority, cn=RootCA");
    private final List<LeafCertSpec> leafSpec;
    private CertificateWrapper ca;

    public CertificateGenerator(List<LeafCertSpec> leafSpec) {
        this.leafSpec = leafSpec;
    }

    public void generate() throws Exception {
        // generate keys and certificates
        ca = generateCa();

        leafSpec.forEach(l -> {
            try {
                var cert = genLeafCert(ca, l.getSubject(), l.getExtensions());
                l.setCert(cert);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    public CertificateWrapper generateCa() throws IOException {
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

        X509CertificateHolder certHolder;
        List<CertificateExtensionWrapper> extensions = List.of(
                new CertificateExtensionWrapper(Extension.basicConstraints, true, new BasicConstraints(true)),
                new CertificateExtensionWrapper(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign))//,
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

        return CertificateWrapper.builder()
                .withKeyPair(keyPair)
                .withExtensions(extensions)
                .withSubject(new String(caSubject.getEncoded()))
                .withHolder(certHolder)
                .build();
    }

    public CertificateWrapper genLeafCert(CertificateWrapper ca, String subject, List<CertificateExtensionWrapper> extensions) throws OperatorCreationException {
        KeyPair keyPair = generateKeyPair();

        long notBefore = System.currentTimeMillis();
        long notAfter = notBefore + (1000L * 3600L * 24 * 365);

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(caSubject,
                new BigInteger(String.valueOf(System.currentTimeMillis())), new Date(notBefore), new Date(notAfter), new X500Name(subject), keyPair.getPublic());

        extensions.forEach(e -> {
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
                .withExtensions(extensions)
                .withHolder(holder)
                .build();
    }

    public KeyStore generateKeyStore(String leafName) throws Exception {
        var leaf = getLeafSpec(leafName);
        return createKeyStore(leaf.getName(), leaf.getCert().getKeyPair().getPrivate(), new X509Certificate[]{ convertHolderToCert(leaf.getCert().getHolder()), convertHolderToCert(ca.getHolder()) });
    }

    public List<LeafCertSpec> getLeafSpec() {
        return leafSpec;
    }

    public CertificateWrapper getCa() {
        return ca;
    }

    public LeafCertSpec getLeafSpec(String name) {
        var spec = leafSpec.stream().filter(l -> l.getName().equals(name)).findFirst();
        if (spec.isEmpty()) {
            throw new IllegalStateException("Certificate not found in generated certs list");
        }
        return spec.get();
    }

    private X509Certificate convertHolderToCert(X509CertificateHolder holder) throws CertificateException {
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        converter.setProvider(new BouncyCastleProvider());
        return converter.getCertificate(holder);
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

    private static KeyStore createKeyStore(String alias, PrivateKey privateKey, Certificate[] certificates)
            throws Exception {
        final KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(null);
        // Import private key
        keystore.setKeyEntry(alias, privateKey, KEYSTORE_PASSWORD.toCharArray(), certificates);
        return keystore;
    }

}
