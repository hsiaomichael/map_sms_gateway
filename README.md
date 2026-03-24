# MAP SMS Gateway README

## Overview

`map_sms_gateway.py` is a **lab-use GSM MAP / SIGTRAN SMS gateway** that runs over the following protocol stack:

**SCTP → M3UA → MTP3 → SCCP (UDT or XUDT) → TCAP → MAP**

It is designed for interoperability testing, troubleshooting, and functional simulation of SMS-related MAP flows in a lab environment.

The script supports:

- **MO-FSM** (`mo-forwardSM`) origination
- **MT-FSM** (`mt-forwardSM`) origination
- **SRI-SM** (`sendRoutingInfoForSM`) request/response handling
- **alertServiceCentre** send/receive
- **reportSM-DeliveryStatus** receive/ack
- **anyTimeSubscriberInformation (ATSI)** receive/response
- **Long SMS / concatenated SMS** for **GSM-7** and **UCS-2**
- Configurable outbound SCCP mode: **UDT** or **XUDT**
- Interactive menu, statistics, logging, and simple load testing

> **Important:** This script is intended for **lab use only** and is **not for production deployment**.

---



Recommended run command:

```bash
python3 map_sms_gateway.py --config map_sms_gateway.ini
```

---

## Main capabilities

### 1) MAP SMS flows

The gateway can act in multiple roles depending on the operation:

- **Respond to incoming `sendRoutingInfoForSM`** using configurable MSISDN matching rules and return an IMSI + routing number.
- **Originate MT SMS** by first sending **SRI-SM**, then using the returned IMSI/NNN to send **MT-FSM**.
- **Originate MO SMS** directly using **MO-FSM**.
- **Acknowledge / reject incoming MT-FSM** depending on the configured mode:
  - `success`
  - `absent`
  - `busy`
- **Send `alertServiceCentre`** toward the SMSC to trigger retry of buffered MT messages.
- **Receive `reportSM-DeliveryStatus`** and reply with a TCAP/MAP acknowledgement.
- **Receive ATSI** and return an empty subscription profile response.

### 2) SMS encoding

The script supports:

- **GSM 7-bit** short messages
- **UCS-2** short messages (e.g. Chinese text)
- **Concatenated SMS** using UDH
- **SMS-SUBMIT** TPDU generation for MO messages
- **SMS-DELIVER** TPDU generation for MT messages

### 3) SCCP mode selection

This updated version supports **both SCCP UDT and SCCP XUDT**:

- Outbound SCCP message type is selected from the INI file.
- Inbound SCCP decoding automatically handles **both UDT and XUDT**.

---

## Requirements

### Operating system

- Linux system with SCTP support
- Python 3

### Typical environment

You normally use this script in a SIGTRAN/MAP lab with:

- a remote **SMSC / STP / HLR / MSC simulator**
- SCCP + TCAP + MAP traffic over **M3UA/SCTP**

### Python modules used by the script

The script uses standard Python modules such as:

- `socket`
- `struct`
- `threading`
- `logging`
- `configparser`
- `traceback`

No third-party Python package is required by the script itself.

---

## Configuration file structure

The INI file is divided into sections.

### `[transport]`

Controls bind address, SCTP port, and log settings.

Example:

```ini
[transport]
sctp_host = 0.0.0.0
sctp_port = 2905
log_file = map_sms_gateway.log
log_level = INFO
```

### `[signaling]`

Defines point codes and main global titles used by the gateway.

Example fields:

- `local_pc`
- `remote_pc`
- `local_gt`
- `remote_gt`
- `hlr_gt`
- `msc_gt`
- `vlr_gt`
- `smsc_gt`
- `fsmsc_gt`

### `[m3ua]`

Controls M3UA and SCCP-related routing values:

- `route_context`
- `network_indicator`
- `ssn`
- `called_ssn`
- `calling_ssn`

### `[sccp]`

**New section** for outbound SCCP connectionless message type.

```ini
[sccp]
message_type = xudt
hop_counter = 15
```

Supported values:

- `message_type = xudt`
- `message_type = udt`

Notes:

- `hop_counter` is used only for **XUDT** mode.
- In **UDT** mode, the script sends SCCP UDT without hop counter.
- The receive path automatically decodes both UDT and XUDT regardless of this setting.

### `[imsi]`

Defines default MCC/MNC used when the script generates IMSI values.

Example:

```ini
[imsi]
imsi_mcc = 440
imsi_mnc = 11
```

### `[examples]`

Used only for interactive menu defaults.

### `[housekeeping]`

Controls stale dialogue cleanup.

Example:

```ini
[housekeeping]
dialogue_ttl = 120
cleanup_interval = 30
```

### `[map]`

Controls runtime MAP behavior.

Example:

```ini
[map]
mt_response_mode = success
alert_sc_acn = 0.4.0.0.1.0.23.2
```

`mt_response_mode` values:

- `success`
- `absent`
- `busy`

### `[sri_table]`

Defines SRI-SM response mapping rules.

Supported key styles:

- exact MSISDN match
- prefix wildcard: `12345*`
- suffix wildcard: `*6789`
- substring wildcard: `*999*`

Example:

```ini
[sri_table]
81707* = 817085811991,440110111111111
8170858* = 817085811991,44011*
886932222222 = 886932000001,466920222222222
886936* = 886936000001,46601*
```

Value format:

```text
NNN_GT,IMSI
```

### `[menu_presets]`

Predefined message texts for the interactive menu.

---

## Starting the gateway

Run:

```bash
python3 map_sms_gateway_udt_xudt_fixed.py --config map_sms_gateway_udt_xudt_fixed.ini
```

Optional CLI overrides:

```bash
python3 map_sms_gateway_udt_xudt_fixed.py \
  --config map_sms_gateway_udt_xudt_fixed.ini \
  --port 2905 \
  --log-level DEBUG
```

Command-line arguments:

- `--config` : path to INI file
- `--port` : overrides `[transport] sctp_port`
- `--log-level` : overrides `[transport] log_level`

---

## Interactive menu

When run in a TTY, the script shows a menu similar to the following functions:

- send MO short GSM-7
- send MT short GSM-7
- send MO long GSM-7
- send MT long GSM-7
- send MO short UCS-2
- send MT short UCS-2
- send MO long UCS-2
- send MT long UCS-2
- status
- reload config
- toggle log level
- show statistics
- send `alertServiceCentre`
- toggle MT-FSM response mode
- exit

### Exit behavior

This updated version supports all of the following from the menu / console:

- `0`
- `exit`
- `quit`

Each of them triggers graceful shutdown.

---

## Direct commands

The console also supports direct commands.

### MO SMS

```text
mo <oa> <da> <text> [--smsc GT]
```

Example:

```text
mo 1.1.817085811401 1.1.817085811402 hello from mo
```

### MT SMS

```text
mt <oa> <da-msisdn> <text> [--smsc GT]
```

Example:

```text
mt 1.1.817085811401 1.1.817085811402 hello from mt
```

### alertServiceCentre

```text
alert <msisdn> [--smsc GT]
```

Example:

```text
alert 1.1.817085811402
```

### MT response mode

```text
mtmode [success|absent|busy]
```

Example:

```text
mtmode absent
```

### Utility commands

```text
status
stats
stats reset
reload
stopload
menu
help
exit
```

---

## SCCP UDT / XUDT behavior

### Outbound behavior

The script reads the SCCP mode from the INI file:

```ini
[sccp]
message_type = xudt
```

or

```ini
[sccp]
message_type = udt
```

- If set to **`xudt`**, outbound SCCP is encoded as **XUDT**.
- If set to **`udt`**, outbound SCCP is encoded as **UDT**.

### Inbound behavior

The receive path checks the SCCP message type byte and automatically decodes:

- `0x09` → UDT
- `0x11` → XUDT

This allows the gateway to interoperate with peers that use either SCCP connectionless format.

---

## Logging

Logs are written to the file defined in:

```ini
[transport]
log_file = map_sms_gateway.log
```

Log levels:

- `ERROR`
- `INFO`
- `DEBUG`

At startup the script logs important runtime information such as:

- bind host/port
- local and remote point codes
- local and remote GTs
- route context
- network indicator
- configured SCCP mode
- SRI table size

The gateway also logs individual MAP/TCAP transactions with details such as:

- OPC / DPC
- TID
- calling GT / called GT
- MAP operation name
- SMS preview (when available)

---

## Statistics

The script maintains counters for both outgoing and incoming traffic.

Examples include:

### Outgoing

- `mo_sent`
- `mo_acked`
- `mo_aborted`
- `mo_timeout`
- `mt_sent`
- `mt_acked`
- `mt_aborted`
- `mt_timeout`
- `sri_sent`
- `sri_acked`
- `sri_aborted`
- `sri_timeout`
- `alert_sc_sent`
- `alert_sc_acked`

### Incoming

- `sri_rx`
- `sri_resp_sent`
- `mt_rx`
- `mt_resp_sent`
- `mt_rejected_absent`
- `mt_rejected_busy`
- `mo_rx`
- `alert_sc_rx`
- `alert_sc_resp_sent`
- `rsmds_rx`
- `rsmds_resp_sent`
- `atsi_rx`
- `atsi_resp_sent`

Use:

```text
stats
```

To reset counters:

```text
stats reset
```

---

## Typical test scenarios

### 1) MO short message

1. Start the gateway.
2. Ensure ASP state becomes active.
3. Send an MO SMS using menu option or direct `mo` command.
4. Check logs or `tshark` for `mo-forwardSM` and the return result.

### 2) MT message via SRI-SM

1. Populate `[sri_table]` or rely on auto-IMSI generation.
2. Send an MT SMS using the `mt` command.
3. The script sends **SRI-SM**.
4. After SRI response, the script sends **MT-FSM** toward the returned routing address.

### 3) Absent subscriber / MWI retry flow

1. Set:

```text
mtmode absent
```

2. Receive or send an MT message.
3. The gateway replies with `absentSubscriberSM`.
4. Later send:

```text
alert <msisdn>
```

5. The SMSC should retry the buffered MT message.

### 4) UDT / XUDT interop test

1. Set `[sccp] message_type = xudt` and confirm decoding works in Wireshark/tshark.
2. Change `[sccp] message_type = udt`.
3. Reload config or restart the script.
4. Confirm the peer still accepts the connectionless MAP traffic.

---

## Troubleshooting

### Problem: only “TCAP XUDT” is shown and MAP does not dissect cleanly

Possible causes:

- SCCP fixed-part pointers are incorrect
- peer expects UDT but you are sending XUDT
- peer expects XUDT but you are sending UDT
- malformed called/calling SCCP address encoding

Actions:

1. Verify `[sccp] message_type`.
2. Try the opposite SCCP mode.
3. Capture with `tshark -V -O sccp,tcap,map`.
4. Check whether SCCP called/calling addresses and data pointer are decoded correctly.

### Problem: no active ASP connection

Check:

- SCTP port reachability
- M3UA ASPUP / ASPAC exchange
- point code / route context / NI values

### Problem: MT message sent but no delivery

Check:

- SRI table mapping
- returned IMSI / NNN
- SCCP called GT / calling GT
- SMSC/MSC expectations for SSN

### Problem: long SMS not reassembled by peer

Check:

- GSM-7 vs UCS-2 encoding
- UDH content
- peer support for concatenated SMS

---

## Notes / limitations

- This script is a **lab utility** and not a production SMSC/HLR/MSC implementation.
- It uses a focused subset of MAP and SCCP behavior for SMS testing.
- It supports UDT/XUDT **for connectionless MAP transport**, but does not implement full SCCP segmentation/reassembly logic.
- Logging is designed for visibility and troubleshooting rather than carrier-grade performance.

---

## Example INI SCCP section

### XUDT mode

```ini
[sccp]
message_type = xudt
hop_counter = 15
```

### UDT mode

```ini
[sccp]
message_type = udt
hop_counter = 15
```

> In UDT mode, `hop_counter` is ignored.

---

## Suggested tshark filters

Show TCAP only:

```bash
tshark -i any -Y "tcap" -t ad
```

Show SCCP + TCAP + MAP verbose decode:

```bash
tshark -i any -V -O sccp,tcap,map -t ad
```

Show only MAP traffic:

```bash
tshark -i any -Y "gsm_map" -t ad
```

---

## Summary

This gateway is useful when you need a practical MAP/SMS lab tool that can:

- simulate SRI/MT/MO flows
- test SMS retry logic
- send/receive AlertSC and delivery status traffic
- exercise both **SCCP UDT** and **SCCP XUDT** transport modes
- provide detailed logs and counters during interop testing


