/*
 * Copyright Debezium Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */
package io.debezium.testing.system.tools.databases.mongodb.sharded.certutil;

import io.debezium.testing.system.tools.ConfigProperties;
import io.fabric8.kubernetes.api.model.ConfigMapBuilder;
import io.fabric8.kubernetes.api.model.ObjectMetaBuilder;
import io.fabric8.openshift.client.OpenShiftClient;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Map;

public class OcpMongoCertGenerator {
    private static final Logger LOGGER = LoggerFactory.getLogger(OcpMongoCertGenerator.class);

    public static final String KEYSTORE_CONFIGMAP = "keystore";
    public static final String KEYSTORE_SUBPATH = "keystore.jks";
    public static final String TRUSTSTORE_CONFIGMAP = "truststore";
    public static final String TRUSTSTORE_SUBPATH = "truststore.jks";
    public static final String CLIENT_SUBJECT = "CN=client";
    public static final String KEYSTORE_PASSWORD = "password";

    public static final String CLIENT_CERT_CONFIGMAP = "client-cert";
    public static final String CLIENT_CERT_SUBPATH = "client-combined.pem";
    public static final String SERVER_CERT_CONFIGMAP = "server-cert";
    public static final String SERVER_CERT_SUBPATH = "server-combined.pem";
    public static final String CA_CERT_CONFIGMAP = "ca-cert";
    public static final String CA_CERT_SUBPATH = "ca-cert.pem";


    private static final String SERVER_SUBJECT = "O=Debezium, CN=mongo-server";
    private static final String CLIENT_CERT_NAME = "client";
    private static final String SERVER_CERT_NAME = "server";

    public static void generateMongoTestCerts(OpenShiftClient ocp) throws Exception {
        List<LeafCertSpec> specs = getLeafCertSpecs();
        var certificateCreator = new CertificateGenerator(specs);
        certificateCreator.generate();

        LOGGER.info("Creating truststore/keystore configmaps for mongo connector");
        keystoreToConfigMap(ConfigProperties.OCP_PROJECT_DBZ, certificateCreator.generateKeyStore(CLIENT_CERT_NAME), KEYSTORE_CONFIGMAP, KEYSTORE_SUBPATH, ocp);
        keystoreToConfigMap(ConfigProperties.OCP_PROJECT_DBZ, certificateCreator.generateKeyStore(SERVER_CERT_NAME), TRUSTSTORE_CONFIGMAP, TRUSTSTORE_SUBPATH, ocp);

        LOGGER.info("Creating certificate configmaps for mongo database");
        pemToConfigMap(ConfigProperties.OCP_PROJECT_MONGO, exportToPem(certificateCreator.getLeafSpec(CLIENT_CERT_NAME).getCert(), certificateCreator.getCa()), CLIENT_CERT_CONFIGMAP, CLIENT_CERT_SUBPATH, ocp);
        pemToConfigMap(ConfigProperties.OCP_PROJECT_MONGO, exportToPem(certificateCreator.getLeafSpec(SERVER_CERT_NAME).getCert(), certificateCreator.getCa()), SERVER_CERT_CONFIGMAP, SERVER_CERT_SUBPATH, ocp);
        pemToConfigMap(ConfigProperties.OCP_PROJECT_MONGO, convertToBase64PEMString(certificateCreator.getCa().getHolder()), CA_CERT_CONFIGMAP, CA_CERT_SUBPATH, ocp);
    }

    private static List<LeafCertSpec> getLeafCertSpecs() {
        ASN1Encodable[] subjectAltNames = new ASN1Encodable[]{
                new GeneralName(GeneralName.dNSName, "*." + ConfigProperties.OCP_PROJECT_MONGO + ".svc.cluster.local"),
                new GeneralName(GeneralName.dNSName, "localhost"),
                new GeneralName(GeneralName.iPAddress, "127.0.0.1")
        };
        return List.of(
                new LeafCertSpec(CLIENT_CERT_NAME, CLIENT_SUBJECT, List.of(
                        new CertificateExtensionWrapper(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature)),
                        new CertificateExtensionWrapper(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_clientAuth})),
                        new CertificateExtensionWrapper(Extension.subjectAlternativeName, true, new DERSequence(subjectAltNames)))),
                new LeafCertSpec(SERVER_CERT_NAME, SERVER_SUBJECT, List.of(
                        new CertificateExtensionWrapper(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature)),
                        new CertificateExtensionWrapper(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth})),
                        new CertificateExtensionWrapper(Extension.subjectAlternativeName, true, new DERSequence(subjectAltNames))))
        );
    }

    private static void pemToConfigMap(String project, String data, String configMapName, String fileNameInConfigMap, OpenShiftClient ocp) {
        var configMap = new ConfigMapBuilder()
                .withMetadata(new ObjectMetaBuilder()
                        .withName(configMapName)
                        .build())
                .withData(Map.of(fileNameInConfigMap, data))
                .build();
        ocp.configMaps().inNamespace(project).createOrReplace(configMap);
    }


    private static void keystoreToConfigMap(String project, KeyStore keyStore, String configMapName, String fileNameInConfigMap, OpenShiftClient ocp) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        char[] pwdArray = KEYSTORE_PASSWORD.toCharArray();
        try (ByteArrayOutputStream fos = new ByteArrayOutputStream()) {
            keyStore.store(fos, pwdArray);
            var configMap = new ConfigMapBuilder()
                    .withMetadata(new ObjectMetaBuilder()
                            .withName(configMapName)
                            .build())
                    .withBinaryData(Map.of(fileNameInConfigMap, Base64.getEncoder().encodeToString(fos.toByteArray())))
                    .build();
            ocp.configMaps().inNamespace(project).createOrReplace(configMap);

        }
    }

    private static String exportToPem(CertificateWrapper cert, CertificateWrapper ca) throws IOException, CertificateException {
        return convertToBase64PEMString(cert.getKeyPair().getPrivate()) +
                convertToBase64PEMString(cert.getHolder()) +
                convertToBase64PEMString(ca.getHolder());
    }

    private static String convertToBase64PEMString(PrivateKey privateKey) throws IOException {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            pw.writeObject(privateKey);
        }
        return sw.toString();
    }

    private static String convertToBase64PEMString(X509CertificateHolder holder) throws CertificateException, IOException {
        return convertToBase64PEMString(convertHolderToCert(holder));
    }

    private static X509Certificate convertHolderToCert(X509CertificateHolder holder) throws CertificateException {
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        converter.setProvider(new BouncyCastleProvider());
        return converter.getCertificate(holder);
    }

    private static String convertToBase64PEMString(X509Certificate x509Cert) throws IOException {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            pw.writeObject(x509Cert);
        }
        return sw.toString();
    }
}
