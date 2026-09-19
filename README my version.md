# sentinel-lab-11-c2-beaconing-threat-hunt
## Overview
Command-and-Control (C2) beaconing is a communication behavior in which malware periodically communicates with remote infrastructure after establishing a presence on a system.

A compromised endpoint does not necessarily maintain a continuous connection to an attacker. Instead, malware may periodically wake up, establish a network connection, send or receive a small amount of information, and then wait before communicating again.

A simplified example looks like this:

09:00:00 → Connect
09:01:00 → Connect
09:02:00 → Connect
09:03:00 → Connect
09:04:00 → Connect
09:05:00 → Connect

The repeated timing is interesting because it can indicate an automated process rather than normal interactive user activity.

However, periodic communication by itself is not evidence of malicious C2.

Legitimate software can also communicate on a schedule. Examples include:

Software update services
Endpoint management agents
Monitoring software
Synchronization services
Backup applications
Scheduled application tasks

This means that a SOC analyst should not investigate beaconing by asking only:

"Is this connection repeated?"

A better question is:

"Does this host show a repeated and unusual communication pattern that, together with other evidence, could indicate C2 activity?"

What makes beaconing interesting?

Several characteristics can be examined together.

1. Repeated destination

The same endpoint repeatedly contacts the same external IP or domain.

DESKTOP-LAB01 → 203.0.113.50
DESKTOP-LAB01 → 203.0.113.50
DESKTOP-LAB01 → 203.0.113.50

2. Regular timing

The connections occur at predictable intervals.

60 seconds
60 seconds
60 seconds
60 seconds

3. Consistent communication characteristics

The destination port and protocol may remain consistent.

For example:

Destination: 203.0.113.50
Port: 443
Protocol: HTTPS

4. Similar traffic volume

Beacon traffic may exchange relatively small and similar amounts of data each time.

For example:

400 bytes
405 bytes
410 bytes
415 bytes

This is not proof of malware, but it adds behavioral context.

Beaconing and jitter

Attackers may deliberately vary beacon intervals to make the pattern less obvious.

Instead of:

60s
60s
60s
60s

the communication might look like:

58s
63s
61s
59s
62s

This variation is commonly referred to as jitter.

The underlying behavior can still be periodic even though the intervals are not identical.

This lab uses a very obvious one-minute pattern so that the detection methodology is easy to understand.

Why comparison is important

Suppose an analyst discovers:

60s
60s
60s
60s
60s

That is potentially interesting.

But suppose another endpoint produces:

600s
600s
600s

That is also periodic.

Without additional context, both could be classified as beaconing.

This is why the analyst must compare the behavior with other network activity and consider the destination, host, application, and other available telemetry.

This lab demonstrates a threat-hunting workflow in Microsoft Sentinel for identifying network communication patterns that may be consistent with C2 beaconing.

The investigation uses synthetic network telemetry created directly in KQL. The focus is on identifying repeated communication, measuring connection intervals, comparing different communication patterns, and determining what additional evidence would be required for further investigation.

The investigation follows an evidence-driven approach:

> Periodicity is a hunting signal, not a conclusion.

## Objectives

- Understand how C2 beaconing can appear as repeated outbound network communication with relatively consistent timing.
- Build and analyze synthetic network telemetry in Microsoft Sentinel using KQL without relying on external network logs.
- Identify repeated communication between a source host and destination that may warrant further investigation.
- Calculate communication intervals between consecutive events to measure the regularity of network activity.
- Compare highly periodic traffic against irregular HTTPS communication to distinguish stronger hunting signals from normal variability.
- Compare different periodic communication patterns to avoid treating periodicity alone as proof of malicious activity.
- Analyze destination usage across multiple hosts to determine whether a communication pattern is isolated or shared.
- Examine basic traffic characteristics such as destination port, protocol, bytes sent, and bytes received as supporting evidence.
- Document the difference between an observed beaconing pattern and confirmed command-and-control activity.
- Identify telemetry gaps that prevent attribution of the network activity to a specific process, application, user, or malicious technique.
- Practice an evidence-driven threat-hunting workflow in which periodicity is treated as a detection signal rather than a final conclusion.
- Develop follow-up investigation steps that could strengthen or weaken the C2 beaconing hypothesis using endpoint, DNS, process, authentication, and threat-intelligence telemetry.
  
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

A SOC analyst is investigating unusual outbound HTTPS communication from an internal workstation. The available telemetry does not contain endpoint process information or security alerts, so the investigation begins with network-level observations rather than an assumed compromise.

The analyst creates a controlled synthetic dataset in Microsoft Sentinel representing network connections from several lab hosts. The objective is to determine whether any communication pattern shows characteristics that could justify further investigation for possible C2 beaconing.

The investigation focuses on:

- Repeated connections from the same source host to the same destination.
- Consistency of the time interval between connections.
- Comparison between regular and irregular HTTPS communication.
- Comparison with another legitimate-looking periodic communication pattern.
- Destination usage across multiple hosts.
- Basic traffic characteristics such as protocol, port, and data volume.

The primary activity of interest involves `DESKTOP-LAB01` communicating with the same HTTPS destination at regular intervals. This pattern is compared with other network activity to determine whether the observed periodicity is unusual within the synthetic dataset.

The analyst must avoid treating periodic communication as proof of C2 activity. Instead, the result should be documented as a hunting signal that requires additional evidence.

The investigation therefore ends by identifying what additional telemetry would be required to strengthen or weaken the hypothesis, including:

- Process and command-line information.
- Parent/child process relationships.
- DNS resolution activity.
- Endpoint security alerts.
- File and persistence artifacts.
- Destination reputation or ownership information.
- Authentication and user activity.
- Similar network communication from other endpoints.

The scenario demonstrates an evidence-driven approach to network threat hunting: identify the pattern, measure it, compare it with other activity, document the evidence boundary, and determine the next investigative steps.


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

