# Troubleshooting Notes

## Lab 11 — C2 Beaconing Threat Hunt

This document records the KQL and synthetic-data issues encountered while building the telemetry for the C2 beaconing hunt.

The troubleshooting process was kept separate from the investigation logic so that parser and query-construction problems could be resolved without changing the underlying investigation hypothesis.

## Issue 1 — `datatable()` Schema Parser Error

### Error

The initial multi-column `datatable()` structure produced a parser error similar to:

```text
A syntax error has been identified in the query.
Query could not be parsed at ',' on line [1,34]
Token: ,
```

### Initial Approach

The original dataset attempted to define multiple columns directly inside `datatable()`:

```text
datatable(
    TimeGenerated:datetime,
    SourceHost:string,
    SourceIP:string,
    ...
)
```

### Problem

The Sentinel Logs environment rejected the multi-column declaration at the schema-definition stage.

The error occurred before the actual investigation logic could be executed.

### Resolution

The synthetic dataset was simplified to a single raw string column:

```text
datatable(Raw:string)
[
    "event1\nevent2\nevent3"
]
```

The individual fields were extracted after the raw data had been expanded.

### Result

The synthetic data could be processed without relying on the problematic multi-column declaration.

## Issue 2 — `union` Parser Error

### Error

An earlier approach that used `union` was rejected by the query environment.

The parser reported an error around the `union` portion of the query.

### Cause

The original construction attempted to combine multiple tabular expressions while building the synthetic dataset.

This introduced additional query complexity without providing a necessary benefit for the lab.

### Resolution

The multiple expressions were replaced with a single `datatable()` source.

The synthetic records were stored in one raw string and processed through a continuous pipeline.

### Result

The query became simpler and easier to isolate during testing.

The final implementation no longer depended on `union`.

## Issue 3 — `print` Parser Error

### Error

A simplified test using `print()` was also rejected by the query environment.

### Cause

`print()` was being used as a convenient way to test or generate small pieces of synthetic data.

It was not required for the actual investigation.

### Resolution

The `print()` approach was removed.

The dataset was generated directly through `datatable()`.

### Result

The final query no longer depended on `print()`.

## Issue 4 — Unexpected Timestamp Parsing

### Symptom

The synthetic records were not initially being interpreted as individual events.

Timestamp values such as:

```text
2026-09-19T09:01:00
```

were not being separated correctly from the surrounding event data.

### Cause

The raw data had been represented using multiline quoted content.

The embedded line breaks were not being handled consistently by the query parser.

This caused subsequent event records to be interpreted incorrectly.

### Resolution

The raw data was represented using escaped newline characters:

```text
event1\nevent2\nevent3
```

The records were then reconstructed with:

```text
| extend Rows = split(Raw, "\n")
| mv-expand Rows
```

Each row was subsequently split into individual fields.

### Result

Each synthetic event became an individual record and the timestamp could be converted using:

```text
todatetime(...)
```

## Issue 5 — `No tabular expression statement found`

### Error

A version of the query using `let` produced:

```text
No tabular expression statement found
```

### Cause

A `let` statement was used to define a temporary expression without correctly providing a final tabular expression that consumed it.

The effective structure was similar to:

```text
let NetworkEvents = ...
```

without a valid final query expression.

### Resolution

The temporary `let` structure was simplified.

The final query was designed as one continuous tabular pipeline from synthetic data generation through parsing and analysis.

### Result

The query no longer depended on an incomplete `let` structure.

## Issue 6 — `NetworkEvents` Could Not Be Resolved

### Error

Another version produced an error similar to:

```text
'order' operator:
Failed to resolve table or column expression named 'NetworkEvents'
```

### Cause

The query attempted to reference `NetworkEvents` after defining it as a temporary expression.

The expression was not resolving as expected in the working query structure.

### Resolution

The temporary variable was removed.

The synthetic data source was connected directly to the parsing and analysis operators.

### Result

The final query no longer depended on the unresolved `NetworkEvents` expression.

## Final Working Data Structure

The stabilized approach used a single raw string column:

```text
datatable(Raw:string)
[
    "event1\nevent2\nevent3"
]
| extend Rows = split(Raw, "\n")
| mv-expand Rows
| extend Fields = split(tostring(Rows), "|")
| extend TimeGenerated = todatetime(tostring(Fields[0]))
| extend SourceHost = tostring(Fields[1])
| extend SourceIP = tostring(Fields[2])
| extend DestinationIP = tostring(Fields[3])
```

The remaining fields were extracted from the `Fields` array and converted to the required data types.

The overall workflow became:

```text
datatable()
    ↓
split()
    ↓
mv-expand
    ↓
split fields
    ↓
type conversion
    ↓
investigation
```

## Why the Final Approach Was Used

The final approach was selected because it avoided the query constructs that had caused parser or expression-resolution problems during the lab.

It also kept the synthetic telemetry in a single controlled structure.

This made it easier to:

- Validate the raw data
- Reconstruct individual events
- Inspect timestamps
- Convert field types
- Calculate intervals
- Group network activity
- Compare hosts
- Compare destinations
- Perform periodicity analysis

The goal was to establish a stable and reproducible query rather than add complexity to the synthetic-data generation process.

## Validation

After the parsing issues were resolved, the resulting dataset supported the required fields:

```text
TimeGenerated
SourceHost
SourceIP
DestinationIP
DestinationDomain
DestinationPort
Protocol
BytesSent
BytesReceived
Action
```

The dataset supported:

- Repeated destination analysis
- Timestamp ordering
- Interval calculation
- Host comparison
- Destination comparison
- Periodicity analysis
- Traffic-volume review

The primary candidate produced:

```text
6 connections
5 consecutive 60-second intervals
```

The irregular comparison produced:

```text
152 seconds
215 seconds
```

The periodic comparison produced:

```text
600 seconds
600 seconds
```

These results confirmed that the final KQL structure supported the intended threat-hunting workflow.

## Troubleshooting Lesson

The main lesson from the data-generation stage was to simplify the query when the execution environment behaves differently from the expected syntax.

Instead of repeatedly adding constructs around a failing expression, the workflow was reduced to:

```text
Create
    ↓
Parse
    ↓
Validate
    ↓
Analyze
```

This also kept troubleshooting separate from the investigation hypothesis.

The broader SOC lesson is:

> Isolate the failing construct before changing the investigation logic.

A query problem should not be mistaken for an investigation finding.
