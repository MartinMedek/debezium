/*
 * Copyright Debezium Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */
package io.debezium.testing.system.tools.databases.mongodb.sharded.certutil;

import java.security.KeyStore;
import java.util.List;

public class LeafCertSpec {
    private final String name;
    private final String subject;
    private final List<CertificateExtensionWrapper> extensions;
    private CertificateWrapper cert;
    private KeyStore keyStore;

    public LeafCertSpec(String name, String subject, List<CertificateExtensionWrapper> extensions) {
        this.name = name;
        this.subject = subject;
        this.extensions = extensions;
    }

    public String getName() {
        return name;
    }

    public String getSubject() {
        return subject;
    }

    public List<CertificateExtensionWrapper> getExtensions() {
        return extensions;
    }

    public CertificateWrapper getCert() {
        return cert;
    }

    public void setCert(CertificateWrapper cert) {
        this.cert = cert;
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }

    public void setKeyStore(KeyStore keyStore) {
        this.keyStore = keyStore;
    }
}
