# Field Tools

This folder contains practical field utilities built around the Angry IP Scanner repository.

## Site Network Scanner MVP

`site_network_scanner.py` is a local browser-based scanner for authorized customer-site network discovery.

It focuses on:

- IP cameras
- NVR / DVR devices
- Managed switches
- Routers and web-managed network equipment
- Basic device classification for field reports

## Run

From the repository root:

```bash
python field-tools/site_network_scanner.py
```

Then open:

```text
http://127.0.0.1:8765
```

The app usually opens the browser automatically.

## What it does

- Guesses the local `/24` network range.
- Lets the technician override the CIDR range manually.
- Checks common CCTV and network-management ports:
  - `80`, `443`, `554`, `8000`, `8080`, `8443`, `37777`, `22`, `23`
- Reads the local ARP cache for MAC addresses.
- Applies simple vendor hints for common field equipment.
- Classifies detected devices as:
  - `IP Camera / NVR`
  - `Managed Network Device`
  - `Web Device`
  - `Unknown`
- Exports reports as:
  - CSV
  - HTML

## Safety

Use only on networks you own or have explicit authorization to scan.

This tool does not exploit, brute force, bypass authentication, or change devices. It performs discovery and basic TCP connection checks only.

## Next planned steps

1. Import CSV exported from Angry IP Scanner.
2. Add stronger OUI/vendor matching.
3. Add SNMP read-only discovery for managed switches where credentials are provided.
4. Add ONVIF discovery for cameras.
5. Add a polished customer-facing PDF report.
