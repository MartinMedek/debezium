/*
 * Copyright Debezium Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */
package io.debezium.testing.system.tools.databases.mongodb.sharded;

import static io.debezium.testing.system.tools.ConfigProperties.DATABASE_MONGO_DBZ_DBNAME;
import static io.debezium.testing.system.tools.WaitConditions.scaled;
import static io.debezium.testing.system.tools.databases.mongodb.sharded.MongoShardedUtil.executeMongoShOnPod;
import static org.awaitility.Awaitility.await;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.lifecycle.Startable;

import io.debezium.testing.system.tools.OpenShiftUtils;
import io.debezium.testing.system.tools.databases.mongodb.OcpMongoShardedConstants;
import io.debezium.testing.system.tools.databases.mongodb.componentfactories.OcpMongosModelFactory;
import io.debezium.testing.system.tools.databases.mongodb.componentfactories.OcpShardModelFactory;
import io.fabric8.kubernetes.api.model.ConfigMap;
import io.fabric8.kubernetes.api.model.ConfigMapBuilder;
import io.fabric8.kubernetes.api.model.ObjectMetaBuilder;
import io.fabric8.openshift.client.OpenShiftClient;

import freemarker.template.TemplateException;
import lombok.Builder;
import lombok.Getter;

public class OcpMongoShardedCluster implements Startable {
    private static final Logger LOGGER = LoggerFactory.getLogger(OcpMongoShardedCluster.class);
    private final int replicaCount;
    private final int configServerCount;
    private final String rootUserName;
    private final String rootPassword;
    private final String internalKey;
    private final OpenShiftClient ocp;
    private final OpenShiftUtils ocpUtils;
    private final int initialShardCount;
    private final String project;
    @Getter
    private final List<MongoShardKey> shardKeys;
    @Getter
    private final List<OcpMongoShardedReplicaSet> shardReplicaSets = Collections.synchronizedList(new LinkedList<>());
    @Getter
    private OcpMongoShardedReplicaSet configServerReplicaSet;
    private OcpMongoShardedNode mongosRouter;
    private boolean isRunning = false;
    private boolean ssl = true;

    @Override
    public void start() {
        if (isRunning) {
            LOGGER.info("Sharded mongo cluster already running, skipping initialization");
            return;
        }
        String pemContent;
        try {
            var path = Paths.get(getClass().getResource("/database-resources/mongodb/sharded/mongodb.pem").toURI());
            pemContent = new String(Files.readAllBytes(path));
        } catch (URISyntaxException | IOException | NullPointerException e) {
            throw new RuntimeException(e);
        }

        // deploy configMap containing keyFile, cert
        ConfigMap configMap = new ConfigMapBuilder()
                .withKind("ConfigMap")
                .withMetadata(new ObjectMetaBuilder()
                        .withName(OcpMongoShardedConstants.CONFIGMAP_NAME)
                        .withLabels(Map.of("asd", "asd"))
                        .build())
                .withData(new TreeMap<>())
                .build();
        if (ssl) {
            configMap.getData().put("pem", pemContent);
        }
        if (StringUtils.isNotEmpty(internalKey)) {
            configMap.getData().put(OcpMongoShardedConstants.KEYFILE_PATH_IN_CONFIGMAP, internalKey);
        }
        ocp.configMaps().inNamespace(project).createOrReplace(configMap);

        // deploy mongo components
        deployConfigServers();
        deployShards();
        deployMongos();
        ocpUtils.waitForPods(project, mongosRouter.getDeployment().getMetadata().getLabels());

        // initialize sharding
        try {
            initMongos();
        }
        catch (IOException | TemplateException | InterruptedException e) {
            throw new RuntimeException(e);
        }
        isRunning = true;
    }

    @Override
    public void stop() {
        shardReplicaSets.parallelStream().forEach(OcpMongoShardedReplicaSet::stop);
        configServerReplicaSet.stop();
        mongosRouter.stop();
        isRunning = false;
    }

    public void waitForStopped() {
        shardReplicaSets.parallelStream().forEach(OcpMongoShardedReplicaSet::waitForStopped);
        configServerReplicaSet.waitForStopped();
        mongosRouter.waitForStopped();
    }

    /**
     * delete last added shard
     */
    public void removeShard() {
        var rs = shardReplicaSets.get(shardReplicaSets.size() - 1);

        shardKeys.forEach(k -> {
            var zones = k.getZones().stream().filter(r -> r.getZoneName().equals(rs.getName())).collect(Collectors.toList());
            zones.forEach(z -> executeMongoSh(
                    String.format("sh.removeRangeFromZone(\"%s\", {%s : %s}, {%s : %s})\n", k.getCollection(), k.getKey(), z.getStart(), k.getKey(), z.getEnd())));
        });

        executeMongoSh(String.format("sh.removeShardFromZone(\"%s\",\"%s\");", rs.getName(), rs.getName()));
        // call mongos removeShard command and wait until chunk cleanup is done and shard can be safely deleted
        await()
                .atMost(scaled(20), TimeUnit.MINUTES)
                .pollInterval(20, TimeUnit.SECONDS)
                .until(() -> {
                    var outputs = executeMongoSh(String.format("db.adminCommand( { removeShard: \"%s\" } )", rs.getName()));
                    return outputs.getStdOut().contains("state: 'completed'");
                });
        rs.stop();
        shardReplicaSets.remove(rs);
    }

    /**
     * deploy new shard and initialize it. Requires running initialized sharded mongo cluster
     */
    public void addShard(@Nullable Map<MongoShardKey, ZoneKeyRange> rangeMap) {
        int shardNum = shardReplicaSets.size() + 1;
        var rs = deployNewShard(shardNum);
        registerShardInMongos(rangeMap, rs);
    }

    public String getConnectionString() {
        StringBuilder builder = new StringBuilder("mongodb://");
        if (StringUtils.isNotEmpty(rootUserName) && StringUtils.isNotEmpty(rootPassword)) {
            builder.append(rootUserName)
                    .append(":")
                    .append(rootPassword)
                    .append("@");
        }
        builder.append(mongosRouter.getHostname() + ":" + OcpMongoShardedConstants.MONGO_MONGOS_PORT);
        return builder.toString();
    }

    public MongoShardKey getShardKey(String collection) {
        return shardKeys.stream().filter(s -> s.getCollection().equals(collection)).findFirst().get();
    }

    public OpenShiftUtils.CommandOutputs executeMongoSh(String command) {
        return executeMongoShOnPod(ocpUtils, project, mongosRouter.getDeployment(), getConnectionString(), command, true);
    }

    private void deployShards() {
        MongoShardedUtil.intRange(initialShardCount).parallelStream().forEach(this::deployNewShard);
    }

    /**
     * deploy new shard, initialize replica set and set authentication if specified
     */
    private OcpMongoShardedReplicaSet deployNewShard(int shardNum) {
        LOGGER.info("Deploying shard number " + shardNum);
        OcpMongoShardedReplicaSet replicaSet = OcpMongoShardedReplicaSet.builder()
                .withShardNum(shardNum)
                .withName(OcpShardModelFactory.getShardReplicaSetName(shardNum))
                .withConfigServer(false)
                .withRootUserName(rootUserName)
                .withRootPassword(rootPassword)
                .withMemberCount(replicaCount)
                .withKeyFile(internalKey)
                .withSsl(ssl)
                .withOcp(ocp)
                .withProject(project)
                .build();
        replicaSet.start();
        synchronized (shardReplicaSets) {
            shardReplicaSets.add(replicaSet);
        }
        return replicaSet;
    }

    private void registerShardInMongos(@Nullable Map<MongoShardKey, ZoneKeyRange> rangeMap, OcpMongoShardedReplicaSet rs) {
        StringBuilder command = new StringBuilder();
        command.append(addShardAndZoneInMongosCommand(rs));

        if (rangeMap != null) {
            rangeMap.forEach((k, z) -> command.append(addShardKeyRangeCommand(k, z)));
        }
        executeMongoSh(command.toString());
    }

    private void deployConfigServers() {
        OcpMongoShardedReplicaSet replicaSet = OcpMongoShardedReplicaSet.builder()
                .withName(OcpMongoShardedConstants.MONGO_CONFIG_REPLICASET_NAME)
                .withConfigServer(true)
                .withRootUserName(rootUserName)
                .withRootPassword(rootPassword)
                .withMemberCount(configServerCount)
                .withKeyFile(internalKey)
                .withSsl(ssl)
                .withOcp(ocp)
                .withProject(project)
                .build();
        replicaSet.start();
        configServerReplicaSet = replicaSet;
    }

    private void deployMongos() {
        mongosRouter = new OcpMongoShardedNode(OcpMongosModelFactory.mongosDeployment(configServerReplicaSet.getReplicaSetFullName()),
                OcpMongosModelFactory.mongosService(), null, ocp, project);
        if(StringUtils.isNotEmpty(internalKey)) {
            MongoShardedUtil.addKeyFileToDeployment(mongosRouter.getDeployment());
        }

        if(ssl) {
            MongoShardedUtil.addSslCertToDeployment(mongosRouter.getDeployment());
        }

        LOGGER.info("Deploying mongos");
        mongosRouter.start();
    }

    private void initMongos() throws IOException, TemplateException, InterruptedException {
        LOGGER.info("Initializing mongos...");
        Thread.sleep(5000);
        StringBuilder command = new StringBuilder();
        // create shards
        shardReplicaSets.forEach(zone -> command.append(addShardAndZoneInMongosCommand(zone)));

        // setup sharding keys and zones
        command.append("sh.enableSharding(\"" + DATABASE_MONGO_DBZ_DBNAME + "\");\n");
        shardKeys.forEach(collection -> command.append(this.shardCollectionCommand(collection)));
        shardKeys.forEach(k -> {
            k.getZones().forEach(z -> command.append(createZoneRangeCommand(z, k)));
        });

        executeMongoSh(command.toString());
    }

    private String addShardKeyRangeCommand(MongoShardKey key, ZoneKeyRange zone) {
        var keyMatch = this.shardKeys.stream().filter(k -> k.equals(key)).findFirst();
        if (keyMatch.isEmpty()) {
            throw new IllegalArgumentException("Illegal shard key");
        }
        keyMatch.get().getZones().add(zone);
        return createZoneRangeCommand(zone, key);
    }

    private String addShardAndZoneInMongosCommand(OcpMongoShardedReplicaSet shardRs) {
        return "sh.addShard(\"" + shardRs.getReplicaSetFullName() + "\");\n " +
                "sh.addShardToZone(\"" + shardRs.getName() + "\", \"" + shardRs.getName() + "\");\n";
    }

    private String shardCollectionCommand(MongoShardKey key) {
        return String.format("sh.shardCollection(\"%s\", { _id: %s } );\n", key.getCollection(), key.getShardingType().getValue());
    }

    private String createZoneRangeCommand(ZoneKeyRange range, MongoShardKey key) {
        return String.format("sh.updateZoneKeyRange(\"%s\",{ %s : %s },{ %s : %s },\"%s\");\n", key.getCollection(), key.getKey(), range.getStart(), key.getKey(),
                range.getEnd(), range.getZoneName());
    }

    @Builder(setterPrefix = "with")
    public OcpMongoShardedCluster(int initialShardCount, int replicaCount, int configServerCount, @Nullable String rootUserName, @Nullable String rootPassword,
                                  @Nullable String internalKey, OpenShiftClient ocp, String project, List<MongoShardKey> shardKeys) {
        this.initialShardCount = initialShardCount;
        this.replicaCount = replicaCount;
        this.configServerCount = configServerCount;
        this.rootUserName = rootUserName;
        this.rootPassword = rootPassword;
        this.internalKey = internalKey;
        this.ocp = ocp;
        this.project = project;
        this.ocpUtils = new OpenShiftUtils(ocp);
        this.shardKeys = shardKeys;
    }

    public static class OcpMongoShardedClusterBuilder {
        public OcpMongoShardedClusterBuilder withRootUser(String rootUserName, String rootPassword) {
            this.rootUserName = rootUserName;
            this.rootPassword = rootPassword;
            return this;
        }
    }
}
