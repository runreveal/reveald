# Backend Plan: First-Class reveald Source Types

## Context

reveald now sends a new wire format with collector metadata and per-event sourceTypes:

```json
{
  "collector": {
    "agent": {"kind": "reveald", "version": "1.2.3", "id": "persistent-uuid", "runID": "per-run-ksuid"},
    "host": {"name": "prod-web-14", "os": "linux", "arch": "amd64"}
  },
  "events": [
    {"sourceType": "journald", "eventTime": "...", "rawLog": "..."},
    {"sourceType": "syslog", "eventTime": "...", "rawLog": "..."}
  ]
}
```

Previously the format was a bare `[]json.RawMessage` array. The backend needs to:
1. Accept the new envelope format (with backwards compatibility for old agents)
2. Use the claimed `sourceType` from each event instead of hardcoding `SourceTypeReveald`
3. Validate claimed sourceTypes against an allowlist
4. Store collector provenance metadata
5. Remove the hardcoded switch statement for journald/syslog/nginx-json

## Design Decisions (already made)

- **Flat sourceType** — `journald`, `syslog`, not `reveald/journald`. Detection rules stay simple.
- **`ingestType: "reveald"` IS the provenance** — no new `collector` column in ClickHouse. The existing ingestType field on SourceConfig already identifies this as reveald-collected data.
- **Platform-enforced trust** — the backend validates claimed sourceTypes against an allowlist. A reveald agent can't claim `cloudtrail`.
- **Collector metadata stored per-source, not per-event** — `collectorHost`, `collectorVersion`, `agentID`, `runID` are source-level metadata, not denormalized onto every event row.

## Steps

### 1. Parse the new wire format

**File**: `internal/sources/webhook/reveald/source.go`

The `ParseEvents` and `ParseFile` methods currently expect `[]revealdMsg`. Update to accept the new envelope format:

```go
type batchPayload struct {
    Collector CollectorMeta     `json:"collector"`
    Events    []json.RawMessage `json:"events"`
}

type CollectorMeta struct {
    Agent AgentInfo `json:"agent"`
    Host  HostInfo  `json:"host"`
}

type AgentInfo struct {
    Kind    string `json:"kind"`
    Version string `json:"version"`
    ID      string `json:"id"`
    RunID   string `json:"runID"`
}

type HostInfo struct {
    Name string `json:"name"`
    OS   string `json:"os"`
    Arch string `json:"arch"`
}
```

**Backwards compatibility**: Try to unmarshal as `batchPayload` first. If that fails (no `collector` field), fall back to the old `[]revealdMsg` format. This handles old agents gracefully.

### 2. Use claimed sourceType from events

**File**: `internal/sources/webhook/reveald/source.go`

In `createEventsFromRevealdMessages`, change:

```go
// Before:
meta.SourceType = types.SourceTypeReveald

// After:
claimed := kmsg.SourceType
if isAllowedSourceType(claimed) {
    meta.SourceType = types.SourceType(claimed)
} else {
    meta.SourceType = types.SourceTypeReveald  // fallback
    // preserve the original claim in tags for debugging
    tags["reveald.claimed_source_type"] = claimed
}
```

### 3. Define the sourceType allowlist

**File**: `internal/sources/webhook/reveald/source.go` (or a shared config)

```go
var allowedSourceTypes = map[string]types.SourceType{
    "journald":     types.SourceType("journald"),
    "syslog":       types.SourceType("syslog"),
    "nginx-syslog": types.SourceType("nginx-syslog"),
    "file":         types.SourceType("file"),
    "cri":          types.SourceType("cri"),
    "command":      types.SourceType("command"),
    "eventlog":     types.SourceType("eventlog"),
    "mqtt":         types.SourceType("mqtt"),
    "scanner":      types.SourceType("scanner"),
}
```

These sourceTypes need to be registered in the source registry. Two options:

**Option A**: Register each as a new sourceType in `types/sources.go` (manual constants). This is the minimal change — just add `SourceTypeJournald = "journald"` etc. No new source.yaml files, no new webhook handlers.

**Option B**: Add them to `SourceType.Valid()` via a dynamic allowlist or prefix check. This avoids needing to register each one but is less explicit.

Recommend **Option A** — explicit constants are cheap and make the type system work for you.

### 4. Register new SourceType constants

**File**: `types/sources.go`

```go
// Agent-collected source types (via reveald or similar collectors)
const (
    SourceTypeJournald    SourceType = "journald"
    SourceTypeSyslog      SourceType = "syslog"
    SourceTypeNginxSyslog SourceType = "nginx-syslog"
    SourceTypeFile        SourceType = "file"
    SourceTypeCRI         SourceType = "cri"
    SourceTypeCommand     SourceType = "command"
    SourceTypeEventlog    SourceType = "eventlog"
    SourceTypeMQTTAgent   SourceType = "mqtt"
    SourceTypeScanner     SourceType = "scanner"
)
```

Update `SourceType.Valid()` to accept these.

### 5. Remove the hardcoded switch statement

**File**: `internal/sources/webhook/reveald/source.go`

The current code has:
```go
switch kmsg.SourceType {
case "journald":
    // extract SYSLOG_IDENTIFIER
case "syslog":
    switch rrtype {
    case "nginx-json":
        // parse nginx access log
    }
}
```

Replace with per-sourceType normalizer functions:

```go
var normalizers = map[string]func(*types.Event, revealdMsg){
    "journald":     normalizeJournald,
    "syslog":       normalizeSyslog,
    "nginx-syslog": normalizeNginxSyslog,
}

// In createEventsFromRevealdMessages:
if fn, ok := normalizers[kmsg.SourceType]; ok {
    fn(&meta, kmsg)
}
```

This is cleaner, extensible, and each normalizer is independently testable.

### 6. Store collector metadata

The collector metadata (hostname, version, agentID, runID) is per-batch, not per-event. Options:

**Option A (simple)**: Store in tags on each event:
```go
tags["collector.host"] = payload.Collector.Host.Name
tags["collector.version"] = payload.Collector.Agent.Version
tags["collector.runID"] = payload.Collector.Agent.RunID
```

**Option B (richer)**: Add columns to ClickHouse for `collectorHost` and `collectorVersion`:
```sql
ALTER TABLE logs ADD COLUMN collectorHost String DEFAULT '';
ALTER TABLE logs ADD COLUMN collectorVersion String DEFAULT '';
```

**Option C (future)**: Store collector metadata on the source config record and update it when the agent checks in. Don't denormalize onto events.

Recommend starting with **Option A** (tags) — it's zero-migration and immediately queryable. Upgrade to Option B or C later if query patterns demand it.

### 7. Source inventory tracking (future)

When a new sourceType is first seen from a reveald source config:
- Record it in a `source_types_seen` table or a JSON field on the source config
- Surface in the UI under the source's detail page
- Enable per-sourceType enable/disable toggles (server-side filtering)

This is a follow-up, not part of the initial PR.

## Migration / Backwards Compatibility

- Old reveald agents send `[]revealdMsg` → still works (fallback parsing)
- Old reveald agents don't send collector metadata → events still process, just no provenance tags
- New reveald agents send `batchPayload{Collector, Events}` → new path with sourceType mapping and provenance
- Existing events with `sourceType = "reveald"` are unaffected — they stay as-is in ClickHouse
- New events from updated agents get proper sourceTypes — no backfill needed

## Testing

1. Unit test: parse old format `[]revealdMsg` still works
2. Unit test: parse new format `batchPayload` extracts collector metadata
3. Unit test: allowed sourceTypes map correctly
4. Unit test: disallowed sourceTypes fall back to "reveald" with tag
5. Unit test: each normalizer (journald, syslog, nginx) extracts expected fields
6. Integration: deploy to staging, verify events appear with correct sourceTypes in ClickHouse
7. Verify: existing detection rules for `sourceType = 'reveald'` still work (old events unaffected)

## Files to Modify

| File | Change |
|------|--------|
| `internal/sources/webhook/reveald/source.go` | New envelope parsing, sourceType mapping, normalizer dispatch |
| `types/sources.go` | New SourceType constants for agent-collected types |
| `internal/sources/webhook/reveald/source_test.go` | Tests for new format, allowlist, normalizers |

## Non-Goals (for this PR)

- ClickHouse schema changes (use tags for now)
- UI changes (source inventory view)
- Per-sourceType enable/disable
- Agent heartbeat / health monitoring
- Per-sourceType retention policies
