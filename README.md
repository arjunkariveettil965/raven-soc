# AI-SOC Copilot

A GenAI-driven Security Operations platform for small and medium-sized
businesses.

The platform is inspired by Microsoft Sentinel, Microsoft Security
Copilot, Microsoft Defender XDR and Splunk risk-based alerting.

## Current Foundation

The current version implements the foundational security analytics
pipeline:

1. CSV security-log ingestion
2. ASIM-inspired log normalization
3. Rule-based event-burst detection
4. Security alert generation
5. Device-level event aggregation
6. Device inventory enrichment
7. Business-criticality scoring
8. Device risk ranking
9. Response recommendations
10. Simulated device-isolation decisions

## Current Architecture

```text
Raw Security Logs
        ↓
ASIM-Inspired Normalization
        ↓
Rule-Based Detection
        ↓
Security Alerts
        ↓
Device-Level Aggregation
        ↓
Inventory and Criticality Enrichment
        ↓
Risk Scoring
        ↓
Response Recommendation
        ↓
Simulated Isolation