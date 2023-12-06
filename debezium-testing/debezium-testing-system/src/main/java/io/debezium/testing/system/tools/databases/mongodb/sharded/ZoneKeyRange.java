/*
 * Copyright Debezium Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */
package io.debezium.testing.system.tools.databases.mongodb.sharded;

import lombok.Getter;

@Getter
public class ZoneKeyRange {
    private final String zoneName;
    private final String start;
    private final String end;

    public ZoneKeyRange(String zoneName, String start, String end) {
        this.zoneName = zoneName;
        this.start = start;
        this.end = end;
    }
}
