# Investigation Timeline

## Lab 11 — C2 Beaconing Threat Hunt

> The timestamps below are synthetic event timestamps from the lab dataset.

## Event Timeline

| Time (UTC) | Source Host | Destination | Port | Protocol | Investigation Context |
| --- | --- | --- | --- | --- | --- |
| `09:00:00` | `DESKTOP-LAB01` | `203.0.113.50` | `443` | HTTPS | Primary candidate |
| `09:00:00` | `DESKTOP-LAB02` | `203.0.113.50` | `443` | HTTPS | Destination comparison |
| `09:00:00` | `DESKTOP-LAB03` | `198.51.100.20` | `443` | HTTPS | Periodic comparison |
| `09:00:15` | `DESKTOP-LAB01` | `93.184.216.34` | `443` | HTTPS | Irregular comparison |
| `09:01:00` | `DESKTOP-LAB01` | `203.0.113.50` | `443` | HTTPS | Primary candidate |
| `09:02:00` | `DESKTOP-LAB01` | `203.0.113.50` | `443` | HTTPS | Primary candidate |
| `09:02:47` | `DESKTOP-LAB01` | `93.184.216.34` | `443` | HTTPS | Irregular comparison |
| `09:03:00` | `DESKTOP-LAB01` | `203.0.113.50` | `443` | HTTPS | Primary candidate |
| `09:04:00` | `DESKTOP-LAB01` | `203.0.113.50` | `443` | HTTPS | Primary candidate |
| `09:04:00` | `DESKTOP-LAB02` | `203.0.113.50` | `443` | HTTPS | Destination comparison |
| `09:05:00` | `DESKTOP-LAB01` | `203.0.113.50` | `443` | HTTPS | Primary candidate |
| `09:06:22` | `DESKTOP-LAB01` | `93.184.216.34` | `443` | HTTPS | Irregular comparison |
| `09:10:00` | `DESKTOP-LAB03` | `198.51.100.20` | `443` | HTTPS | Periodic comparison |
| `09:20:00` | `DESKTOP-LAB03` | `198.51.100.20` | `443` | HTTPS | Periodic comparison |

## Primary Candidate Sequence

The primary candidate was:

```text
DESKTOP-LAB01
        ↓
203.0.113.50
```

The observed sequence was:

```text
09:00:00
09:01:00
09:02:00
09:03:00
09:04:00
09:05:00
```

The calculated intervals were:

```text
60s
60s
60s
60s
60s
```

This produced five consecutive one-minute intervals.

## Candidate Interval Timeline

| Previous Event | Current Event | Interval |
| --- | --- | ---: |
| `09:00:00` | `09:01:00` | 60 seconds |
| `09:01:00` | `09:02:00` | 60 seconds |
| `09:02:00` | `09:03:00` | 60 seconds |
| `09:03:00` | `09:04:00` | 60 seconds |
| `09:04:00` | `09:05:00` | 60 seconds |

## Irregular Activity Sequence

The same host communicated with:

```text
DESKTOP-LAB01
        ↓
93.184.216.34
```

Observed timestamps:

```text
09:00:15
09:02:47
09:06:22
```

Calculated intervals:

```text
152s
215s
```

The activity was irregular compared with the primary candidate.

This provided a comparison point for evaluating the regularity of the candidate communication.

## Periodic Comparison Sequence

`DESKTOP-LAB03` communicated with:

```text
198.51.100.20
```

Observed timestamps:

```text
09:00:00
09:10:00
09:20:00
```

Calculated intervals:

```text
600s
600s
```

This activity was also periodic.

The comparison demonstrates that regular communication can occur in activity that is not being treated as C2 within the simulation.

## Destination Usage Timeline

The candidate destination was:

```text
203.0.113.50
```

It was contacted by:

```text
DESKTOP-LAB01
DESKTOP-LAB02
```

Total observed connections:

```text
8
```

This destination-level context was reviewed after identifying the primary periodic communication pattern.

## Investigation Milestones

### 1. Synthetic Dataset Created

Synthetic network events were generated using KQL.

### 2. Data Parsing Validated

The raw event structure was split into individual records and fields.

### 3. Baseline Established

The initial grouping identified repeated source-to-destination relationships.

### 4. Primary Candidate Identified

The following relationship had six observed connections:

```text
DESKTOP-LAB01 → 203.0.113.50
```

### 5. Periodicity Measured

The six candidate events produced five consecutive 60-second intervals.

### 6. Irregular Activity Compared

The primary candidate was compared against:

```text
DESKTOP-LAB01 → 93.184.216.34
```

with intervals of:

```text
152s
215s
```

### 7. Periodic Activity Compared

The candidate was also compared against:

```text
DESKTOP-LAB03 → 198.51.100.20
```

with intervals of:

```text
600s
600s
```

### 8. Destination Context Reviewed

The candidate destination was contacted by two hosts and accounted for eight connections in the dataset.

### 9. Evidence Limitations Documented

The available telemetry was network-level synthetic data and did not contain process, DNS, endpoint, identity, or threat-intelligence context.

### 10. Final Assessment

The activity was documented as:

```text
Possible C2 beaconing pattern
Requires further investigation
```

The available telemetry did not support describing the activity as confirmed C2 or confirmed compromise.

## Timeline Summary

```text
09:00:00
Candidate communication begins
        ↓
09:01:00
60-second recurrence
        ↓
09:02:00
60-second recurrence
        ↓
09:03:00
60-second recurrence
        ↓
09:04:00
60-second recurrence
        ↓
09:05:00
60-second recurrence
        ↓
Regular periodic behavior identified
        ↓
Irregular HTTPS activity compared
        ↓
Separate periodic activity compared
        ↓
Destination usage reviewed
        ↓
Possible C2 beaconing candidate identified
        ↓
Additional telemetry required
```

## Evidence Progression

The investigation progressed from observable network activity toward an evidence-based assessment:

```text
Repeated communication
        ↓
Regular timing
        ↓
Destination consistency
        ↓
Comparison with other activity
        ↓
Destination context
        ↓
Telemetry limitations
        ↓
Further investigation required
```

## Final Investigation Principle

The timeline demonstrates the distinction between a behavioral indicator and a confirmed finding.

```text
Periodic behavior
        ↓
Hunting signal
        ↓
Context and correlation
        ↓
Additional evidence
        ↓
Assessment
```

> Periodicity is an indicator to investigate, not proof of compromise.
