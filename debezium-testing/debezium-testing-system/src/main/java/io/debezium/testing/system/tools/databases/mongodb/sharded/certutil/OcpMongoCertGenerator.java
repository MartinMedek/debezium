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

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Map;

import static io.debezium.testing.system.tools.databases.mongodb.sharded.certutil.CertificateGenerator.KEYSTORE_PASSWORD;

public class OcpMongoCertGenerator {
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

        keystoreToConfigMap(ConfigProperties.OCP_PROJECT_DBZ, keyStoreToString(certificateCreator.getLeafSpec("client").getKeyStore()), "keystore", "client.jks", ocp);
        keystoreToConfigMap(ConfigProperties.OCP_PROJECT_DBZ, keyStoreToString(certificateCreator.getLeafSpec("server").getKeyStore()), "truststore", "server.jks", ocp);

//        keyStoreToFile(certificateCreator.getLeafSpec("client").getKeyStore(), "/tmp/client.jks");
//        var configMap = new ConfigMapBuilder()
//                .withMetadata(new ObjectMetaBuilder()
//                        .withName("keystore")
//                        .build())
//                .withData(Map.of("client.jks", data))
//                .build();
//        ocp.configMaps().inNamespace(project).createOrReplace(configMap);

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

    private static void keystoreToConfigMap(String project, String data, String configMapName, String fileNameInConfigMap, OpenShiftClient ocp) {
        var configMap = new ConfigMapBuilder()
                .withMetadata(new ObjectMetaBuilder()
                        .withName(configMapName)
                        .build())
                .withData(Map.of(fileNameInConfigMap, data))
                .build();
        ocp.configMaps().inNamespace(project).createOrReplace(configMap);
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

    private static void pemToSecret(String project, String data, String secretName, String secretSubPath, OpenShiftClient ocp) {
        var secret = new SecretBuilder()
                .withMetadata(new ObjectMetaBuilder()
                        .withName(secretName)
                        .build())
                .withData(Map.of(secretSubPath, data))
                .build();
        ocp.secrets().inNamespace(project).createOrReplace(secret);
    }

    private static void keyStoreToSecret(String project, String data, String secretName, String secretSubPath, OpenShiftClient ocp) {
        var secret = new SecretBuilder()
                .withMetadata(new ObjectMetaBuilder()
                        .withName(secretName)
                        .build())
                .withData(Map.of(secretSubPath, data))
                .build();
        ocp.secrets().inNamespace(project).createOrReplace(secret);
    }

    private static String keyStoreToString(KeyStore keyStore) throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException {
        char[] pwdArray = KEYSTORE_PASSWORD.toCharArray();
        String result;
        try (ByteArrayOutputStream fos = new ByteArrayOutputStream()) {
            keyStore.store(fos, pwdArray);
            result = fos.toString();
        }
        return StringUtils.substring(result, 0, result.length() - 1);
    }

    public static void keyStoreToFile(KeyStore keyStore, String filePath) throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException {
        char[] pwdArray = "password".toCharArray();
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            keyStore.store(fos, pwdArray);
        }
    }


}
