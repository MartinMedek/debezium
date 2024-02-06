/*
 * Copyright Debezium Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */
package io.debezium.testing.system.tools.databases.mongodb.sharded.freemarkermodels;

import java.util.List;
import java.util.stream.Collectors;

import io.debezium.testing.system.tools.databases.mongodb.sharded.OcpShardedMongoReplica;

import lombok.Getter;

public class InitReplicaSetModel {
    private final List<OcpShardedMongoReplica> members;
    @Getter
    private final String rsId;
    @Getter
    private final boolean configServer;

    public String getMembers() {
        return members.stream().map(en -> "{ _id: " + en.getReplicaNum() + ", host: \"" + en.getServiceUrl() + "\" }").collect(Collectors.joining(","));
    }

    public InitReplicaSetModel(List<OcpShardedMongoReplica> members, String rsId, boolean configServer) {
        this.members = members;
        this.rsId = rsId;
        this.configServer = configServer;
    }
}
