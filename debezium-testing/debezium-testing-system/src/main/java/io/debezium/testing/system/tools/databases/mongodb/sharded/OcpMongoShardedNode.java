/*
 * Copyright Debezium Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */
package io.debezium.testing.system.tools.databases.mongodb.sharded;

import org.testcontainers.lifecycle.Startable;

import io.debezium.testing.system.tools.OpenShiftUtils;
import io.fabric8.kubernetes.api.model.Service;
import io.fabric8.kubernetes.api.model.apps.Deployment;
import io.fabric8.openshift.client.OpenShiftClient;

import lombok.Getter;

@Getter
public class OcpMongoShardedNode implements Startable {
    private Deployment deployment;
    private Service service;
    private final String serviceUrl;
    private final OpenShiftClient ocp;
    private final OpenShiftUtils ocpUtils;
    private final String project;

    public OcpMongoShardedNode(Deployment deployment, Service service, String serviceUrl, OpenShiftClient ocp, String project) {
        this.deployment = deployment;
        this.service = service;
        this.serviceUrl = serviceUrl;
        this.ocp = ocp;
        this.ocpUtils = new OpenShiftUtils(ocp);
        this.project = project;
    }

    @Override
    public void start() {
        deployment = ocp.apps().deployments().inNamespace(project).createOrReplace(deployment);
        service = ocp.services().inNamespace(project).createOrReplace(service);
    }

    @Override
    public void stop() {
        ocpUtils.scaleDeploymentToZero(deployment);
        // ocp.apps().deployments().inNamespace(project).delete(deployment);
        // ocp.services().inNamespace(project).delete(service);
    }

    public void waitForStopped() {
        ocpUtils.waitForDeploymentToScaleDown(deployment);
    }

    public String getHostname() {
        return service.getMetadata().getName() + "." + project + ".svc.cluster.local";
    }
}
