package io.bullseye.uog.tcc;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.Set;

final class TccSnapshotV1 {
    private static final Set<String> RESOURCES = Set.of("HOST_CPU", "HOST_MEMORY", "DISK_IO");
    private static final Set<String> SEVERITIES = Set.of("NORMAL", "ELEVATED", "HIGH", "CRITICAL");
    private static final Set<String> STATES =
            Set.of("NORMAL", "PRESSURE", "SATURATION_RISK", "SATURATED", "UNAVAILABLE");
    private static final Set<String> OBSERVATION_STATUSES = Set.of("INITIALIZING", "FRESH", "STALE");
    private static final Set<String> WORKLOAD_TYPES = Set.of(
            "SYSTEMD_SERVICE", "DOCKER_CONTAINER", "KUBERNETES_POD", "GENERIC_CGROUP", "UNKNOWN");
    private static final Set<String> CONFIDENCES = Set.of("UNRESOLVED", "LOW", "MEDIUM", "HIGH");
    private static final Set<String> ATTRIBUTION_STATUSES = Set.of(
            "NOT_ATTEMPTED", "IDENTIFIED", "CGROUP_V2_NOT_AVAILABLE", "ACCESS_DENIED",
            "NO_CANDIDATE", "INSUFFICIENT_DATA");

    private TccSnapshotV1() {}

    static boolean versionOne(JsonNode field) {
        return integralLong(field) && field.longValue() == 1;
    }

    static long sequence(JsonNode telemetry) {
        JsonNode sequence = telemetry.path("sequence");
        return integralLong(sequence) ? Math.max(0, sequence.longValue()) : 0;
    }

    static boolean valid(JsonNode telemetry, String nodeId, String runId) {
        if (!versionOne(telemetry.path("schemaVersion"))
                || !nonblank(telemetry.path("nodeId"))
                || !nodeId.equals(telemetry.path("nodeId").textValue())
                || !runId.equals(telemetry.path("runId").textValue())) {
            return false;
        }

        JsonNode snapshot = telemetry.path("snapshot");
        JsonNode evaluatedAt = snapshot.path("evaluatedAt");
        String resource = snapshot.path("resource").textValue();
        if (!snapshot.isObject()
                || !nonblank(snapshot.path("host"))
                || !nonblank(snapshot.path("application"))
                || resource == null
                || !(RESOURCES.contains(resource) || "UNKNOWN".equals(resource))
                || !nonnegativeLong(evaluatedAt)
                || !integralLong(snapshot.path("wallClockAt"))
                || !nonnegativeLong(snapshot.path("version"))
                || !oneOf(snapshot.path("observationStatus"), OBSERVATION_STATUSES)) {
            return false;
        }
        long evaluation = evaluatedAt.longValue();
        return diagnosis(snapshot, evaluation)
                && observations(snapshot.path("observations"), evaluation)
                && resources(snapshot.path("resources"), evaluation);
    }

    static boolean consistentObservations(JsonNode snapshot) {
        JsonNode observations = snapshot.path("observations");
        JsonNode diagnoses = snapshot.path("resources");
        if (observations.size() != diagnoses.size()) {
            return false;
        }

        boolean allFresh = !observations.isEmpty();
        boolean anyStale = false;
        for (var entry : observations.properties()) {
            JsonNode observation = entry.getValue();
            String status = observation.path("status").textValue();
            boolean fresh = "FRESH".equals(status);
            if (!diagnoses.has(entry.getKey()) || (fresh && !observation.hasNonNull("lastSampleAt"))) {
                return false;
            }
            allFresh &= fresh;
            anyStale |= "STALE".equals(status);
        }

        String expected = allFresh ? "FRESH" : "INITIALIZING";
        if (anyStale) {
            expected = "STALE";
        }
        return expected.equals(snapshot.path("observationStatus").textValue());
    }

    private static boolean diagnosis(JsonNode node, long evaluatedAt) {
        return node.isObject()
                && oneOf(node.path("severity"), SEVERITIES)
                && oneOf(node.path("state"), STATES)
                && timestamp(node.path("since"), evaluatedAt)
                && evidence(node.path("evidence"))
                && attribution(node, evaluatedAt);
    }

    private static boolean observations(JsonNode observations, long evaluatedAt) {
        if (!observations.isObject()) {
            return false;
        }
        for (var entry : observations.properties()) {
            JsonNode observation = entry.getValue();
            if (!RESOURCES.contains(entry.getKey())
                    || !observation.isObject()
                    || !oneOf(observation.path("status"), OBSERVATION_STATUSES)
                    || !nullableTimestamp(observation.path("lastSampleAt"), evaluatedAt)
                    || !evidence(observation.path("metrics"))) {
                return false;
            }
        }
        return true;
    }

    private static boolean resources(JsonNode resources, long evaluatedAt) {
        if (!resources.isObject()) {
            return false;
        }
        for (var entry : resources.properties()) {
            JsonNode diagnosis = entry.getValue();
            if (!RESOURCES.contains(entry.getKey())
                    || !nonblank(diagnosis.path("reason"))
                    || !diagnosis(diagnosis, evaluatedAt)) {
                return false;
            }
        }
        return true;
    }

    private static boolean attribution(JsonNode node, long evaluatedAt) {
        JsonNode type = node.path("workloadType");
        JsonNode confidence = node.path("attributionConfidence");
        JsonNode status = node.path("attributionStatus");
        JsonNode score = node.path("attributionScore");
        JsonNode attributionEvidence = node.path("attributionEvidence");
        if (!nonblank(node.path("primaryWorkload"))
                || !oneOf(type, WORKLOAD_TYPES)
                || !nonblank(node.path("cgroupPath"))
                || !oneOf(confidence, CONFIDENCES)
                || !oneOf(status, ATTRIBUTION_STATUSES)
                || !finiteNumber(score)
                || score.doubleValue() < 0
                || !nullableTimestamp(node.path("attributionCollectedAt"), evaluatedAt)
                || !coverage(node.path("attributionCoverage"))
                || !evidence(attributionEvidence)) {
            return false;
        }
        boolean unknownWorkload = "UNKNOWN".equals(type.textValue());
        boolean unresolvedConfidence = "UNRESOLVED".equals(confidence.textValue());
        if ("IDENTIFIED".equals(status.textValue())) {
            return !unknownWorkload && !unresolvedConfidence;
        }
        return unknownWorkload && unresolvedConfidence
                && score.doubleValue() == 0 && attributionEvidence.isEmpty();
    }

    private static boolean coverage(JsonNode node) {
        if (node.isNull()) {
            return true;
        }
        JsonNode complete = node.path("complete");
        JsonNode collected = node.path("collectedGroups");
        JsonNode failed = node.path("failedGroups");
        JsonNode discoveryFailed = node.path("discoveryFailed");
        JsonNode discoveryLimited = node.path("discoveryLimited");
        return node.isObject()
                && complete.isBoolean()
                && nonnegativeLong(collected) && collected.canConvertToInt()
                && nonnegativeLong(failed) && failed.canConvertToInt()
                && discoveryFailed.isBoolean()
                && discoveryLimited.isBoolean()
                && complete.booleanValue() == (failed.intValue() == 0
                        && !discoveryFailed.booleanValue() && !discoveryLimited.booleanValue());
    }

    private static boolean evidence(JsonNode list) {
        if (!list.isArray()) {
            return false;
        }
        for (JsonNode entry : list) {
            if (!entry.isObject()
                    || !nonblank(entry.path("metric"))
                    || !finiteNumber(entry.path("value"))
                    || !entry.path("unit").isTextual()) {
                return false;
            }
        }
        return true;
    }

    private static boolean integralLong(JsonNode field) {
        return field.isIntegralNumber() && field.canConvertToLong();
    }

    private static boolean nonnegativeLong(JsonNode field) {
        return integralLong(field) && field.longValue() >= 0;
    }

    private static boolean timestamp(JsonNode field, long evaluatedAt) {
        return nonnegativeLong(field) && field.longValue() <= evaluatedAt;
    }

    private static boolean nullableTimestamp(JsonNode field, long evaluatedAt) {
        return field.isNull() || timestamp(field, evaluatedAt);
    }

    private static boolean finiteNumber(JsonNode field) {
        return field.isNumber() && Double.isFinite(field.doubleValue());
    }

    private static boolean nonblank(JsonNode field) {
        return field.isTextual() && !field.textValue().isBlank();
    }

    private static boolean oneOf(JsonNode field, Set<String> values) {
        return field.isTextual() && values.contains(field.textValue());
    }
}
