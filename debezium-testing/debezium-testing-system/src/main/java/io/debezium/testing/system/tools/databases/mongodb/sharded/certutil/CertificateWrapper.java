/*
 * Copyright Debezium Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */
package io.debezium.testing.system.tools.databases.mongodb.sharded.certutil;

import java.security.KeyPair;
import java.util.List;

import org.bouncycastle.cert.X509CertificateHolder;

public class CertificateWrapper {
    private final KeyPair keyPair;
    private final String subject;
    private final List<CertificateExtensionWrapper> extensions;
    private final X509CertificateHolder holder;

    public static X509CertificateWrapperBuilder builder() {
        return new X509CertificateWrapperBuilder();
    }

    public CertificateWrapper(KeyPair keyPair, String subject, List<CertificateExtensionWrapper> extensions, X509CertificateHolder holder) {
        this.keyPair = keyPair;
        this.subject = subject;
        this.extensions = extensions;
        this.holder = holder;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public String getSubject() {
        return subject;
    }

    public List<CertificateExtensionWrapper> getExtensions() {
        return extensions;
    }

    public X509CertificateHolder getHolder() {
        return holder;
    }

    public static final class X509CertificateWrapperBuilder {
        private KeyPair keyPair;
        private String subject;
        private List<CertificateExtensionWrapper> extensions;
        private X509CertificateHolder holder;

        private X509CertificateWrapperBuilder() {
        }

        public static X509CertificateWrapperBuilder aCertThing() {
            return new X509CertificateWrapperBuilder();
        }

        public X509CertificateWrapperBuilder withKeyPair(KeyPair keyPair) {
            this.keyPair = keyPair;
            return this;
        }

        public X509CertificateWrapperBuilder withSubject(String subject) {
            this.subject = subject;
            return this;
        }

        public X509CertificateWrapperBuilder withExtensions(List<CertificateExtensionWrapper> extensions) {
            this.extensions = extensions;
            return this;
        }

        public X509CertificateWrapperBuilder withHolder(X509CertificateHolder holder) {
            this.holder = holder;
            return this;
        }

        public CertificateWrapper build() {
            return new CertificateWrapper(keyPair, subject, extensions, holder);
        }
    }
}
