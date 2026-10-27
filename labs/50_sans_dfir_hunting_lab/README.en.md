# Lab 50: ArtifactHunter — SANS DFIR Threat Hunting Lab

## Overview
Interactive enterprise digital forensics and incident response (DFIR) lab based on SANS FOR508 & FOR572 methodologies.

## Stages
1. **Evidence of Execution**: Prefetch (PECmd) and ShimCache/Amcache triage.
2. **FileSystem & Deletion Carving**: NTFS $MFT Data Run, $LogFile, and USN Journal analysis.
3. **Memory Injection & DKOM Triage**: Volatility 3/Rekall DKOM unlinking and RWX VAD inspection.
4. **Network Carving & Supertimeline**: SANS FOR572 tshark packet carving, Plaso timeline correlation, and automated SOAR isolation.

## Quickstart
```bash
vhack lab start 50
vhack lab test 50
vhack solve 50
```
