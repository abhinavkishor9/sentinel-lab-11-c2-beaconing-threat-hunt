# Sentinel Lab 11 — C2 Beaconing Threat Hunt

## Overview

This lab demonstrates a threat-hunting workflow in Microsoft Sentinel for identifying network communication patterns that may be consistent with C2 beaconing.

The investigation uses synthetic network telemetry created directly in KQL. The focus is on identifying repeated communication, measuring connection intervals, comparing different communication patterns, and determining what additional evidence would be required for further investigation.

The investigation follows an evidence-driven approach:

> Periodicity is a hunting signal, not a conclusion.

## Objectives

- Create and validate synthetic network telemetry using KQL.
- Establish a baseline for the simulated network activity.
- Identify repeated host-to-destination relationships.
- Calculate intervals between consecutive connections.
- Identify highly regular communication patterns.
- Compare regular communication with irregular HTTPS activity.
- Compare the primary candidate against another periodic communication pattern.
- Review destination usage across multiple hosts.
- Examine protocol, port, and traffic-volume characteristics.
- Document evidence and telemetry limitations.
- Identify the additional telemetry required for further investigation.

## Lab Environment

| Component | Details |
| --- | --- |
| Platform | Microsoft Sentinel |
| Query Language | Kusto Query Language (KQL) |
| Telemetry | Synthetic network connection data |
| Lab Type | Threat Hunt |
| Primary Host | `DESKTOP-LAB01` |
| Source IP | `10.10.10.25` |
| Primary Destination | `203.0.113.50` |
| Primary Domain | `update-check.example` |
| Port | `443` |
| Protocol | HTTPS |

## Scenario

A SOC analyst is performing a proactive threat hunt for possible C2 beaconing.

The synthetic dataset contains three different communication patterns:

1. A highly regular connection pattern from `DESKTOP-LAB01`.
2. Irregular HTTPS activity from the same host.
3. A separate periodic pattern from `DESKTOP-LAB03`.

The purpose is to determine whether the primary pattern is sufficiently unusual to become a hunting lead while demonstrating why periodicity alone cannot establish C2.

## Synthetic Dataset

The final validated dataset contained:

- 15 network events
- Multiple source hosts
- Multiple destinations
- HTTPS communication over port `443`
- Regular and irregular communication patterns

The telemetry included the following fields:

| Field | Description |
| --- | --- |
| `TimeGenerated` | Event timestamp |
| `SourceHost` | Host generating the connection |
| `SourceIP` | Source IP address |
| `DestinationIP` | Remote destination |
| `DestinationDomain` | Destination domain |
| `DestinationPort` | Destination port |
| `Protocol` | Network protocol |
| `BytesSent` | Bytes sent |
| `BytesReceived` | Bytes received |
| `Action` | Network action |

The final working data-generation approach used a single raw string column and reconstructed the individual fields after ingestion.

The general parsing workflow was:

```text
Create raw data
    ↓
Split records
    ↓
Expand records
    ↓
Split fields
    ↓
Convert data types
    ↓
Analyze network behavior
```

## Investigation Workflow

The hunt followed these stages:

1. Create synthetic network telemetry.
2. Validate the generated events.
3. Establish the communication baseline.
4. Identify repeated host-to-destination relationships.
5. Calculate connection intervals.
6. Examine the consistency of the intervals.
7. Compare the candidate against irregular HTTPS activity.
8. Compare the candidate against another periodic activity pattern.
9. Review destination usage across hosts.
10. Review traffic characteristics.
11. Document evidence and limitations.
12. Identify next investigation steps.

## Baseline Analysis

The initial grouping of the synthetic data produced the following relationships:

| Source Host | Destination IP | Destination Domain | Port | Connections |
| --- | --- | --- | --- | ---: |
| `DESKTOP-LAB01` | `203.0.113.50` | `update-check.example` | `443` | 6 |
| `DESKTOP-LAB03` | `198.51.100.20` | `software-update.example` | `443` | 3 |
| `DESKTOP-LAB01` | `93.184.216.34` | `example.com` | `443` | 3 |
| `DESKTOP-LAB02` | `203.0.113.50` | `update-check.example` | `443` | 2 |

The primary repeated relationship was:

```text
DESKTOP-LAB01 → 203.0.113.50
6 connections
```

This relationship was selected for deeper timing analysis.

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

The six connections occurred at:

```text
09:00:00 UTC
09:01:00 UTC
09:02:00 UTC
09:03:00 UTC
09:04:00 UTC
09:05:00 UTC
```

## Periodicity Analysis

The intervals between consecutive candidate connections were:

```text
60 seconds
60 seconds
60 seconds
60 seconds
60 seconds
```

The candidate therefore demonstrated five consecutive one-minute intervals.

This is a strong periodicity signal within the synthetic dataset.

The investigation treats this as a hunting lead rather than proof of C2:

```text
Repeated communication
        +
Highly regular timing
        ↓
Beaconing candidate
        ↓
Additional context required
```

Not:

```text
Periodic communication
        ↓
Confirmed C2
```

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

The calculated intervals were:

```text
152 seconds
215 seconds
```

This provides an irregular comparison from the same host.

The comparison demonstrates that HTTPS communication does not automatically produce a regular beacon-like pattern.

## Periodic Comparison

`DESKTOP-LAB03` communicated with:

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

This is also periodic activity.

For the simulation, this represents a separate software-update pattern and demonstrates why periodicity alone cannot establish C2.

```text
Periodic communication != confirmed C2
```

## Destination Usage

The candidate destination was contacted by two hosts:

| Destination IP | Hosts | Connections |
| --- | ---: | ---: |
| `203.0.113.50` | 2 | 8 |
| `198.51.100.20` | 1 | 3 |

`203.0.113.50` was contacted by:

```text
DESKTOP-LAB01
DESKTOP-LAB02
```

for a total of:

```text
8 connections
```

Multiple hosts communicating with the same destination provides additional context, but it does not establish whether the destination is legitimate or malicious.

## Traffic Characteristics

The primary candidate consistently used:

```text
Protocol: HTTPS
Port:     443
```

The observed `BytesSent` values were:

```text
400
405
410
415
420
425
```

The observed `BytesReceived` values were:

```text
290
295
300
305
310
315
```

The relatively similar traffic volumes provide supporting behavioral context.

They are not independently sufficient to establish malicious activity.

## Evidence Summary

| Observation | Evidence | Interpretation |
| --- | --- | --- |
| Repeated communication | 6 connections from `DESKTOP-LAB01` to `203.0.113.50` | Worth investigating |
| Regular timing | 5 consecutive 60-second intervals | Strong periodicity |
| HTTPS traffic | Port `443` | Consistent with web-based communication |
| Similar traffic volumes | Gradually changing byte counts | Supporting context only |
| Multiple hosts | 2 hosts contacted `203.0.113.50` | Requires additional context |
| Periodic comparison | `DESKTOP-LAB03` communicated every 600 seconds | Periodicity is not unique to C2 |
| Irregular comparison | `DESKTOP-LAB01` intervals of 152 and 215 seconds | Provides a non-periodic baseline |

## Assessment

The primary communication pattern is:

```text
Possible C2 beaconing pattern
Requires further investigation
```

The evidence supports the following observation:

> `DESKTOP-LAB01` repeatedly communicated with `203.0.113.50` at consistent 60-second intervals.

The evidence does not establish:

- Confirmed C2
- Confirmed malware
- Confirmed compromise
- Malicious ownership of the destination
- The process responsible for the connection
- Persistence
- Command execution

## Telemetry Limitations

The dataset is synthetic and limited to network-level information.

The investigation does not contain:

- Process creation telemetry
- Process lineage
- Process command lines
- DNS history
- Endpoint security alerts
- Threat-intelligence enrichment
- Persistence artifacts
- Malware artifacts
- User activity
- Packet-level inspection
- Additional endpoint indicators

Without these sources, the network pattern cannot be converted into a confirmed compromise finding.

## MITRE ATT&CK Context

The HTTPS communication can be conceptually associated with:

| Technique | Name | Lab Relevance |
| --- | --- | --- |
| `T1071.001` | Web Protocols | The simulated candidate uses HTTPS over port 443 |

This is a conceptual mapping based on the observed protocol.

The lab does not establish confirmed adversary activity or prove that the observed communication represents a real ATT&CK technique execution.

## Recommended Next Investigation

A real SOC investigation would correlate the network activity with additional telemetry.

Recommended checks include:

1. Identify the process responsible for the network connection.
2. Review the process parent and child relationships.
3. Examine command-line arguments.
4. Investigate DNS resolution associated with the destination.
5. Check destination reputation and ownership.
6. Search for the destination across other endpoints.
7. Review endpoint detection and response telemetry.
8. Check for persistence mechanisms.
9. Correlate the activity with authentication and user events.
10. Determine whether the communication continues outside the current observation window.

## Key Takeaway

The hunt identified a highly regular outbound communication pattern from:

```text
DESKTOP-LAB01 → 203.0.113.50
```

The five consecutive 60-second intervals make the activity a meaningful hunting candidate.

However, the investigation deliberately maintains the distinction between an observable network behavior and a confirmed security finding.

```text
Behavior
    ↓
Pattern
    ↓
Context
    ↓
Correlation
    ↓
Additional Evidence
    ↓
Assessment
```

> Follow the evidence, not the assumption.
