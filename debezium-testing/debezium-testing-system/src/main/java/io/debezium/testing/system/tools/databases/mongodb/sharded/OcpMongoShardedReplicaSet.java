/*
 * Copyright Debezium Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */
package io.debezium.testing.system.tools.databases.mongodb.sharded;

import static io.debezium.testing.system.tools.databases.mongodb.sharded.MongoShardedUtil.createRootUserCommand;
import static io.debezium.testing.system.tools.databases.mongodb.sharded.MongoShardedUtil.executeMongoShOnPod;
import static io.debezium.testing.system.tools.databases.mongodb.sharded.MongoShardedUtil.getFreemarkerConfiguration;
import static io.debezium.testing.system.tools.databases.mongodb.sharded.MongoShardedUtil.intRange;

import java.io.IOException;
import java.io.StringWriter;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.lifecycle.Startable;

import io.debezium.testing.system.tools.ConfigProperties;
import io.debezium.testing.system.tools.OpenShiftUtils;
import io.debezium.testing.system.tools.databases.mongodb.sharded.componentfactories.OcpConfigServerModelFactory;
import io.debezium.testing.system.tools.databases.mongodb.sharded.componentfactories.OcpShardModelFactory;
import io.debezium.testing.system.tools.databases.mongodb.sharded.freemarkermodels.InitReplicaSetModel;
import io.fabric8.openshift.client.OpenShiftClient;

import freemarker.template.Template;
import freemarker.template.TemplateException;
import lombok.Builder;
import lombok.Getter;

public class OcpMongoShardedReplicaSet implements Startable {
    private static final Logger LOGGER = LoggerFactory.getLogger(OcpMongoShardedReplicaSet.class);

    @Getter
    private String name;
    private final boolean configServer;
    private final int memberCount;
    private boolean authRequired = false;
    private final String rootUserName;
    private final String rootPassword;
    private boolean started = false;
    private final OpenShiftClient ocp;
    private final OpenShiftUtils ocpUtil;
    private final String project;
    private final boolean useInternalAuth;
    @Getter
    private int shardNum;
    private final List<OcpShardedMongoReplica> members;

    @Builder(setterPrefix = "with")
    public OcpMongoShardedReplicaSet(String name, boolean configServer, int memberCount, String rootUserName, String rootPassword, OpenShiftClient ocp, String project,
                                     boolean useInternalAuth, int shardNum) {
        this.name = name;
        this.configServer = configServer;
        this.memberCount = memberCount;
        this.authRequired = false;
        this.rootUserName = rootUserName;
        this.rootPassword = rootPassword;
        this.ocp = ocp;
        this.project = project;
        this.useInternalAuth = useInternalAuth;
        this.shardNum = shardNum;
        this.ocpUtil = new OpenShiftUtils(ocp);

        this.members = intRange(memberCount)
                .stream()
                .map(i -> configServer
                        ? new OcpShardedMongoReplica(OcpConfigServerModelFactory.configServerDeployment(i), OcpConfigServerModelFactory.configServerService(i),
                                getConfigServerServiceName(i), ocp, project, i)
                        : new OcpShardedMongoReplica(OcpShardModelFactory.shardDeployment(shardNum, i), OcpShardModelFactory.shardService(shardNum, i),
                                getShardReplicaServiceName(i), ocp, project, i))
                .collect(Collectors.toList());
    }

    public String getReplicaSetFullName() {
        return name + "/" + members
                .stream()
                .map(OcpShardedMongoReplica::getServiceUrl)
                .collect(Collectors.joining(","));
    }

    private String getLocalhostConnectionString() {
        var builder = new StringBuilder("mongodb://");

        if (authRequired) {
            builder
                    .append(URLEncoder.encode(rootUserName, StandardCharsets.UTF_8))
                    .append(":")
                    .append(URLEncoder.encode(rootPassword, StandardCharsets.UTF_8))
                    .append("@");
        }

        var host = "localhost:" + getPort();

        builder.append(host)
                .append("/?");

        if (authRequired) {
            builder.append("&").append("authSource=admin");
        }
        return builder.toString();
    }

    @Override
    public void start() {
        if (started) {
            return;
        }
        // Add keyfile to deployment
        if (useInternalAuth) {
            members.forEach(m -> MongoShardedUtil.addKeyFileToDeployment(m.getDeployment()));
        }

        // Deploy all members in parallel
        LOGGER.info("[{}] Starting {} node replica set...", name, memberCount);
        members.parallelStream().forEach(m -> {
            m.start();
            ocpUtil.waitForPods(project, m.getDeployment().getMetadata().getLabels());
        });

        // Initialize the configured replica set to contain all the cluster's members
        LOGGER.info("[{}] Initializing replica set...", name);
        try {
            var output = executeMongosh(getInitRsCommand(), false);
            if (!output.getStdOut().contains("is primary result:  true")) {
                throw new IllegalStateException("Replicaset initialization failed" + output);
            }
            if (StringUtils.isNotEmpty(rootUserName) && StringUtils.isNotEmpty(rootPassword)) {
                executeMongosh(createRootUserCommand(rootUserName, rootPassword), false);
                authRequired = true;
            }
            // set small cleanup delay so mongo doesn't wait 15 minutes for shard removal
            if (!configServer) {
                executeMongosh("db.adminCommand({ setParameter: 1, orphanCleanupDelaySecs: 60 });", false);
            }
        }
        catch (TemplateException | IOException e) {
            throw new RuntimeException(e);
        }

        started = true;
    }

    @Override
    public void stop() {
        members.parallelStream().forEach(OcpMongoShardedNode::stop);
    }

    public void waitForStopped() {
        members.parallelStream().forEach(OcpMongoShardedNode::waitForStopped);
    }

    private int getPort() {
        return configServer ? OcpMongoShardedConstants.MONGO_CONFIG_PORT : OcpMongoShardedConstants.MONGO_SHARD_PORT;
    }

    public OpenShiftUtils.CommandOutputs executeMongosh(String command, boolean debugLogs) {
        return executeMongoShOnPod(ocpUtil, project, members.get(0).getDeployment(), getLocalhostConnectionString(), command, debugLogs);
    }

    private String getInitRsCommand() throws IOException, TemplateException {
        var writer = new StringWriter();
        Template template = getFreemarkerConfiguration().getTemplate(OcpMongoShardedConstants.INIT_RS_TEMPLATE);
        template.process(new InitReplicaSetModel(members, name, configServer), writer);
        return writer.toString();
    }

    private String getShardReplicaServiceName(int replicaNum) {
        return String.format("%s%dr%d.%s.svc.cluster.local:%d", OcpMongoShardedConstants.MONGO_SHARD_DEPLOYMENT_PREFIX, shardNum, replicaNum,
                ConfigProperties.OCP_PROJECT_MONGO, OcpMongoShardedConstants.MONGO_SHARD_PORT);
    }

    private String getConfigServerServiceName(int replicaNum) {
        return String.format("%s.%s.svc.cluster.local:%d", OcpConfigServerModelFactory.getConfigServerName(replicaNum), ConfigProperties.OCP_PROJECT_MONGO,
                OcpMongoShardedConstants.MONGO_CONFIG_PORT);
    }

}
