/*
 * Copyright Debezium Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */
package io.debezium.testing.system.tools.databases.mongodb.sharded.certutil;

import io.debezium.testing.system.tools.ConfigProperties;
import io.fabric8.kubernetes.api.model.ConfigMapBuilder;
import io.fabric8.kubernetes.api.model.ObjectMetaBuilder;
import io.fabric8.kubernetes.api.model.SecretBuilder;
import io.fabric8.kubernetes.client.utils.KubernetesResourceUtil;
import io.fabric8.openshift.client.OpenShiftClient;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.AbstractMap;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static io.debezium.testing.system.tools.databases.mongodb.sharded.certutil.CertificateGenerator.KEYSTORE_PASSWORD;

public class OcpMongoCertGenerator {
    private static final Logger LOGGER = LoggerFactory.getLogger(OcpMongoCertGenerator.class);

    private static final String SERVER_SUBJECT = "O=Debezium, CN=mongo-mongos." + ConfigProperties.OCP_PROJECT_MONGO + ".svc.cluster.local";
    public static final String CLIENT_SUBJECT = "CN=client";

    public static void generateMongoTestCerts(OpenShiftClient ocp) throws Exception {
        List<LeafCertSpec> specs = getLeafCertSpecs();
        var certificateCreator = CertificateGenerator.builder()
                .withExportKeyStores(true)
                .withExportPems(false)
                .withLeafSpec(specs)
                .withOcp(ocp)
                .build();
        certificateCreator.generate();

//        keyStoreToFile(certificateCreator.getLeafSpec("client").getKeyStore(), "/tmp/keystore.jks");
//        keyStoreToFile(certificateCreator.getLeafSpec("server").getKeyStore(), "/tmp/truststore.jks");
//        keystoreToConfigMap(ConfigProperties.OCP_PROJECT_MONGO, Path.of("/tmp/keystore.jks"), "keystore", "keystore.jks", ocp);
//        keystoreToConfigMap(ConfigProperties.OCP_PROJECT_MONGO, Path.of("/tmp/truststore.jks"), "truststore", "truststore.jks", ocp);

        LOGGER.info("Creating truststore/keystore configmaps for connector");
        keystoreToConfigMap(ConfigProperties.OCP_PROJECT_DBZ, certificateCreator.getLeafSpec("client").getKeyStore(), "keystore", "client.jks", ocp);
        keystoreToConfigMap(ConfigProperties.OCP_PROJECT_DBZ, certificateCreator.getLeafSpec("server").getKeyStore(), "truststore", "server.jks", ocp);

        LOGGER.info("Creating certificate configmaps for mongo database");
        pemToConfigMap(ConfigProperties.OCP_PROJECT_MONGO, certificateCreator.exportToPem(certificateCreator.getLeafSpec("client").getCert(), certificateCreator.getCa()), "client-cert", "client-combined.pem", ocp);
        pemToConfigMap(ConfigProperties.OCP_PROJECT_MONGO, certificateCreator.exportToPem(certificateCreator.getLeafSpec("server").getCert(), certificateCreator.getCa()), "server-cert", "server-combined.pem", ocp);
        pemToConfigMap(ConfigProperties.OCP_PROJECT_MONGO, certificateCreator.convertToBase64PEMString(certificateCreator.getCa().getHolder()), "ca-cert", "ca-cert.pem", ocp);
    }

    private static List<LeafCertSpec> getLeafCertSpecs() {
        ASN1Encodable[] subjectAltNames = new ASN1Encodable[]{
                new GeneralName(GeneralName.dNSName, "*.debezium-mmedek-mongo.svc.cluster.local"),
                new GeneralName(GeneralName.iPAddress, "127.0.0.1")
        };
        return List.of(
                new LeafCertSpec("client", CLIENT_SUBJECT, List.of(
                        new CertificateExtensionWrapper(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature)),
                        new CertificateExtensionWrapper(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_clientAuth})),
                        new CertificateExtensionWrapper(Extension.subjectAlternativeName, true, new DERSequence(subjectAltNames)))),
                new LeafCertSpec("server", SERVER_SUBJECT, List.of(
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


    /*
    ============================================== KEYSTORE UTILS ======================================================
     */


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
            LOGGER.info("creating configmap " + configMapName + " in namespace " + project);
            ocp.configMaps().inNamespace(project).createOrReplace(configMap);

        }
    }

    private static String keyStoreToString(KeyStore keyStore) throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException {
        char[] pwdArray = KEYSTORE_PASSWORD.toCharArray();
        String result;
        try (ByteArrayOutputStream fos = new ByteArrayOutputStream()) {
            keyStore.store(fos, pwdArray);
            return fos.toString(StandardCharsets.US_ASCII);
        }
    }

    public static void keyStoreToFile(KeyStore keyStore, String filePath) throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException {
        char[] pwdArray = "password".toCharArray();
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            keyStore.store(fos, pwdArray);
        }
    }

    private static void keystoreToConfigMap(String project, Path file, String configMapName, String fileNameInConfigMap, OpenShiftClient ocp) throws IOException {
        var configMapBuilder = new ConfigMapBuilder()
                .withMetadata(new ObjectMetaBuilder()
                        .withName(configMapName)
                        .build());
        addEntryFromFileToConfigMap(configMapBuilder, fileNameInConfigMap, file);
        ocp.configMaps().inNamespace(project).createOrReplace(configMapBuilder.build());
    }

    private static void addEntryFromFileToConfigMap(ConfigMapBuilder configMapBuilder, final String key,
                                                    final Path file) throws IOException {
        String entryKey = Optional.ofNullable(key).orElse(file.toFile().getName());
        Map.Entry<String, String> configMapEntry = createConfigMapEntry(entryKey, file);
        addEntryToConfigMap(configMapBuilder, configMapEntry, file);
    }

    private static void addEntryToConfigMap(ConfigMapBuilder configMapBuilder, Map.Entry<String, String> entry,
                                            final Path file)
            throws IOException {
        if (isFileWithBinaryContent(file)) {
            configMapBuilder.addToBinaryData(entry.getKey(), entry.getValue());
        } else {
            configMapBuilder.addToData(entry.getKey(), entry.getValue());
        }
    }

    private static Map.Entry<String, String> createConfigMapEntry(final String key, final Path file) throws IOException {
        final byte[] bytes = Files.readAllBytes(file);
        if (isFileWithBinaryContent(file)) {
            final String value = Base64.getEncoder().encodeToString(bytes);
            return new AbstractMap.SimpleEntry<>(key, value);
        } else {
            return new AbstractMap.SimpleEntry<>(key, new String(bytes));
        }
    }

    private static boolean isFileWithBinaryContent(Path file) {
        return false;
    }


}
