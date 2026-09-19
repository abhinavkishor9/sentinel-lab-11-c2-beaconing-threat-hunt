# Investigation Notes

## Lab 11 — C2 Beaconing Threat Hunt

## Investigation Objective

The objective of this investigation was to identify network communication patterns that may be consistent with C2 beaconing.

The hunt focused on repeated communication between the same source host and destination, followed by interval analysis and comparison against other network activity.

The initial hypothesis was:

> A host repeatedly communicating with the same external destination at regular intervals may exhibit behavior consistent with C2 beaconing.

The hypothesis was used to guide the hunt and was not treated as a conclusion.

## Data Source

The investigation used synthetic network telemetry generated directly in Microsoft Sentinel using KQL.

The telemetry contained:

- `TimeGenerated`
- `SourceHost`
- `SourceIP`
- `DestinationIP`
- `DestinationDomain`
- `DestinationPort`
- `Protocol`
- `BytesSent`
- `BytesReceived`
- `Action`

The final validated dataset contained:

```text
15 network events
```

## Initial Baseline

The synthetic dataset contained multiple hosts and destinations to provide comparison activity.

The primary host was:

```text
DESKTOP-LAB01
```

Source IP:

```text
10.10.10.25
```

The initial grouping showed:

| Source Host | Destination IP | Destination Domain | Port | Connections |
| --- | --- | --- | --- | ---: |
| `DESKTOP-LAB01` | `203.0.113.50` | `update-check.example` | `443` | 6 |
| `DESKTOP-LAB03` | `198.51.100.20` | `software-update.example` | `443` | 3 |
| `DESKTOP-LAB01` | `93.184.216.34` | `example.com` | `443` | 3 |
| `DESKTOP-LAB02` | `203.0.113.50` | `update-check.example` | `443` | 2 |

The most frequently repeated relationship was:

```text
DESKTOP-LAB01 → 203.0.113.50
6 connections
```

This relationship was selected for deeper investigation.

## Primary Candidate

The primary candidate was:

```text
Source Host:         DESKTOP-LAB01
Source IP:           10.10.10.25
Destination IP:      203.0.113.50
Destination Domain:  update-check.example
Destination Port:    443
Protocol:            HTTPS
```

Six relevant events were observed.

## Candidate Communication Sequence

The candidate timestamps were:

| Event | Time (UTC) |
| --- | --- |
| 1 | `09:00:00` |
| 2 | `09:01:00` |
| 3 | `09:02:00` |
| 4 | `09:03:00` |
| 5 | `09:04:00` |
| 6 | `09:05:00` |

The sequence showed repeated communication at one-minute intervals.

## Interval Analysis

The intervals between consecutive candidate events were:

| Previous Event | Current Event | Interval |
| --- | --- | ---: |
| `09:00:00` | `09:01:00` | 60 seconds |
| `09:01:00` | `09:02:00` | 60 seconds |
| `09:02:00` | `09:03:00` | 60 seconds |
| `09:03:00` | `09:04:00` | 60 seconds |
| `09:04:00` | `09:05:00` | 60 seconds |

The candidate produced five consecutive 60-second intervals.

This was the strongest behavioral characteristic identified during the hunt.

The investigation does not treat this pattern as confirmed C2.

## Traffic Characteristics

The candidate communication consistently used:

```text
Protocol: HTTPS
Port:     443
```

The `BytesSent` values were:

```text
400
405
410
415
420
425
```

The `BytesReceived` values were:

```text
290
295
300
305
310
315
```

The relatively similar traffic volumes provide additional behavioral context.

They do not independently establish malicious activity.

## Irregular HTTPS Comparison

The same host also communicated with:

```text
Destination IP:      93.184.216.34
Destination Domain:  example.com
Destination Port:    443
Protocol:            HTTPS
```

The observed timestamps were:

```text
09:00:15
09:02:47
09:06:22
```

The intervals were:

```text
152 seconds
215 seconds
```

This activity was irregular compared with the primary candidate.

The comparison was useful because it showed that the same host could generate HTTPS traffic without producing the same regular timing pattern.

## Periodic Comparison

A separate host, `DESKTOP-LAB03`, communicated with:

```text
Destination IP:      198.51.100.20
Destination Domain:  software-update.example
Destination Port:    443
Protocol:            HTTPS
```

The observed timestamps were:

```text
09:00:00
09:10:00
09:20:00
```

The intervals were:

```text
600 seconds
600 seconds
```

This activity was also periodic.

For the simulation, it represents a software-update communication pattern.

This comparison demonstrates:

```text
Periodic communication != confirmed C2
```

Regular timing is therefore treated as a hunting signal that requires additional context.

## Destination Usage Analysis

The candidate destination was contacted by two hosts:

```text
DESKTOP-LAB01
DESKTOP-LAB02
```

The destination usage was:

| Destination IP | Hosts | Connections |
| --- | ---: | ---: |
| `203.0.113.50` | 2 | 8 |
| `198.51.100.20` | 1 | 3 |

The fact that `203.0.113.50` was contacted by more than one host provides additional context.

However, the available telemetry does not determine whether the destination represents legitimate application infrastructure, malicious infrastructure, or another type of service.

## Evidence Summary

| Observation | Evidence | Interpretation |
| --- | --- | --- |
| Repeated communication | 6 connections from `DESKTOP-LAB01` to `203.0.113.50` | Worth investigating |
| Regular timing | 5 consecutive 60-second intervals | Strong periodicity |
| HTTPS | Port `443` | Consistent protocol |
| Similar traffic volume | Gradually changing byte counts | Supporting context |
| Multiple hosts | 2 hosts contacted `203.0.113.50` | Requires additional context |
| Irregular comparison | 152-second and 215-second intervals | Non-periodic comparison |
| Periodic comparison | 600-second and 600-second intervals | Demonstrates periodicity is not unique to C2 |

## Assessment

The primary activity is assessed as:

```text
Possible C2 beaconing pattern
Requires further investigation
```

The directly supported behavioral observation is:

> `DESKTOP-LAB01` repeatedly communicated with `203.0.113.50` at consistent 60-second intervals.

The evidence does not establish:

- Confirmed C2
- Confirmed malware
- Confirmed compromise
- Malicious ownership of the destination
- The process responsible for the connection
- Persistence
- Command execution
- Credential access
- User compromise

## Evidence Boundary

The investigation stops at the network-behavior finding because the available telemetry is limited.

There is no process information showing which executable initiated the connections.

There is also no:

- Process lineage
- Command line
- DNS history
- Endpoint security telemetry
- Threat-intelligence enrichment
- Persistence evidence
- Malware artifact
- User activity correlation
- Packet-level network inspection

Without those sources, the periodic network behavior cannot be reliably attributed to a malicious process or confirmed C2 infrastructure.

## Recommended Next Investigation

The next investigation stage would correlate the network activity with endpoint, identity, and external context.

Recommended checks:

1. Identify the process responsible for the network connection.
2. Review the process parent and child relationships.
3. Examine the command line.
4. Investigate DNS resolution for the destination.
5. Check destination reputation and ownership.
6. Search for the destination across the environment.
7. Review endpoint detection and response telemetry.
8. Check for persistence mechanisms.
9. Review authentication and user activity.
10. Determine whether the communication continues over a longer period.
11. Compare the destination against other known application traffic.
12. Review whether additional hosts exhibit the same timing pattern.

## Final Investigation Conclusion

The hunt identified a highly regular network communication pattern from:

```text
DESKTOP-LAB01
        ↓
203.0.113.50
```

The six observed connections occurred at one-minute intervals, producing five consecutive 60-second gaps.

This makes the activity a meaningful C2 beaconing candidate.

However, the available network telemetry is insufficient to confirm malicious activity.

The investigation therefore maintains the distinction between:

```text
Observable behavior
        ↓
Hunting lead
        ↓
Additional evidence required
        ↓
Final assessment
```

> Follow the evidence, not the assumption.
