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

import java.io.File;
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

import freemarker.template.Configuration;
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
    private boolean authEnabled = false;
    private final String rootUserName;
    private final String rootPassword;
    private boolean started = false;
    private final OpenShiftClient ocp;
    private final OpenShiftUtils ocpUtil;
    private final String project;
    private final String keyFile;
    @Getter
    private int shardNum;
    private final List<OcpShardedMongoReplica> members;
    private final Configuration configuration;

    @Builder(setterPrefix = "with")
    public OcpMongoShardedReplicaSet(String name, boolean configServer, int memberCount, String rootUserName, String rootPassword, OpenShiftClient ocp, String project,
                                     String keyFile, int shardNum) {
        this.name = name;
        this.configServer = configServer;
        this.memberCount = memberCount;
        this.authEnabled = false;
        this.rootUserName = rootUserName;
        this.rootPassword = rootPassword;
        this.ocp = ocp;
        this.project = project;
        this.keyFile = keyFile;
        this.shardNum = shardNum;
        this.ocpUtil = new OpenShiftUtils(ocp);

        this.configuration = new Configuration(Configuration.VERSION_2_3_32);
        try {
            this.configuration.setDirectoryForTemplateLoading(new File("src/test/resources/database-resources/mongodb/sharded/command-templates"));
        }
        catch (IOException e) {
            throw new RuntimeException(e);
        }

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

        if (authEnabled) {
            builder
                    .append(URLEncoder.encode(rootUserName, StandardCharsets.UTF_8))
                    .append(":")
                    .append(URLEncoder.encode(rootPassword, StandardCharsets.UTF_8))
                    .append("@");
        }

        var host = "localhost:" + getPort();

        builder.append(host)
                .append("/?");

        if (authEnabled) {
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
        if (StringUtils.isNotEmpty(keyFile)) {
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
                authEnabled = true;
            }
            // set small cleanup delay so tests don't wait 15 minutes for shard removal
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
