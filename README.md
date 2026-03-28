# MAP SMS Gateway — User Guide

## Overview

`map_sms_gateway.py` is a lab-oriented MAP/SIGTRAN SMS gateway script that implements a GSM MAP stack over:

- **SCTP**
- **M3UA**
- **SCCP (UDT/XUDT)**
- **TCAP**
- **MAP**

The script is intended for SMS-related MAP interoperability and lab testing.

---

## Main Files

Use the following filenames in your working directory:

- `map_sms_gateway.py`
- `map_sms_gateway.ini`

---

## Main Features

### Supported MAP procedures

- **MO-FSM (`mo-forwardSM`) origination**
- **MT-FSM (`mt-forwardSM`) origination via SRI-SM lookup**
- **Incoming `sendRoutingInfoForSM` response generation**
- **Incoming `mt-forwardSM` response generation**
- **`alertServiceCentre` origination and response handling**
- **`reportSM-DeliveryStatus` response handling**
- **`anyTimeSubscriberInformation` response handling**
- **Concatenated SMS support** for GSM-7 and UCS-2 test messages
- **Interactive console menu** and direct command mode

### Response rule engine

This version supports rule-based response sections in the INI file:

```ini
[response_rule:<rule_name>]
```

Rules can match by:

- exact MSISDN
- prefix (`88693*`)
- suffix (`*2222`)
- substring (`*93222*`)
- IMSI (`imsi:44011*`)

The engine uses **longest-match wins** behavior.

### Enhanced logging

The main `Send/Recv` log line shows:

- `invoke`
- `returnResultLast`
- `returnError`
- `reject`

It also tries to decode MAP errors inline.

### TID-based transaction correlation

For pending outbound transactions, the script correlates TCAP END / ReturnError PDUs back to the original flow for:

- MO-FSM
- MT-FSM
- SRI-SM
- `alertServiceCentre`

### Corrected MAP error handling

This script version includes corrected SMS-related MAP error naming/decoding for the tested SMS cases.

---

## Running the Script

### Basic run

```bash
python3 map_sms_gateway.py --config map_sms_gateway.ini
```

### Optional CLI arguments

```bash
python3 map_sms_gateway.py   --config map_sms_gateway.ini   --port 2905   --log-level INFO
```

Arguments:

- `--config` : path to the INI file
- `--port` : overrides `[transport] sctp_port`
- `--log-level` : overrides `[transport] log_level`

---

## INI File Structure

### `[transport]`

Controls listener and log output.

Example:

```ini
[transport]
sctp_host = 0.0.0.0
sctp_port = 2905
log_file = map_sms_gateway.log
log_level = INFO
```

### `[signaling]`

Contains point codes and GT values used by the gateway.

Typical fields:

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

M3UA routing and SSN configuration.

Typical fields:

- `route_context`
- `network_indicator`
- `ssn`
- `called_ssn`
- `calling_ssn`

### `[sccp]`

SCCP connectionless message behavior.

Typical fields:

- `message_type = udt | xudt`
- `hop_counter`

### `[imsi]`

Default MCC/MNC used for generated IMSI values.

### `[examples]`

Default OA / DA prompts shown in the menu.

### `[housekeeping]`

Timeout and cleanup intervals.

### `[map]`

MAP behavior defaults.

Important field:

```ini
mt_response_mode = success
```

Supported values in this corrected script:

- `success`
- `absent`
- `busy`
- `error` (rule-driven use case)

### `[sri_table]`

Static or wildcard mapping of **MSISDN -> NNN/IMSI** for SRI-SM success responses.

Example:

```ini
[sri_table]
81707* = 817085811991,440110111111111
886932222222 = 886932000001,466920222222222
```

### `[menu_presets]`

Preloaded text for interactive menu options.

---

## Response Rule Engine

### Rule format

```ini
[response_rule:<name>]
match = 817085811402
sri_action = error
sri_error = unknownSubscriber
```

### Supported fields

- `match` / `patterns` / `prefixes`
- `sri_action = success | error`
- `sri_error = <MAP error name>`
- `sri_nnn = <NNN/MSC GT>`
- `sri_imsi = <IMSI template>`
- `mt_action = success | error | absent | busy`
- `mt_error = <MAP error name>`

### Match examples

```ini
match = 817085811402
match = 8170858114*
match = *1402
match = *5811*
match = imsi:44011*
```

### Example rules

#### SRI-SM unknownSubscriber

```ini
[response_rule:sri_unknownsubscriber_demo]
match = 817085811402
sri_action = error
sri_error = unknownSubscriber
```

#### SRI-SM absentSubscriberSM

```ini
[response_rule:sri_absentsubscriber_demo]
match = 817085811402
sri_action = error
sri_error = absentSubscriberSM
```

#### SRI-SM absentSubscriberSM by prefix

```ini
[response_rule:sri_absentsubscriber_prefix_demo]
match = 8170858114*
sri_action = error
sri_error = absentSubscriberSM
```

#### MT-FSM subscriberBusyForMT-SMS

```ini
[response_rule:mtfsm_busy_demo]
match = 8170858114*
mt_action = error
mt_error = subscriberBusyForMT-SMS
```

#### MT-FSM memoryCapacityExceeded by IMSI

```ini
[response_rule:mtfsm_memory_full_by_imsi_demo]
match = imsi:44011*
mt_action = error
mt_error = memoryCapacityExceeded
```

---

## Interactive Menu

When started in a terminal, the script prints an interactive menu.

Common options include:

- **1** → MO GSM-7 short
- **2** → MT GSM-7 short
- **3** → MO GSM-7 long
- **4** → MT GSM-7 long
- **5** → MO UCS-2 short
- **6** → MT UCS-2 short
- **7** → MO UCS-2 long
- **8** → MT UCS-2 long
- **9** → status
- **10** → reload config
- **11** → toggle log level
- **12 / s** → statistics
- **13** → `alertServiceCentre`
- **14** → toggle MT-FSM response mode
- **0 / exit** → stop the server

---

## Direct Console Commands

### MO-FSM

```bash
mo <oa> <da> <text> [--smsc GT]
```

Example:

```bash
mo 1.1.817085811401 1.1.817085811402 mo test 123
```

### MT-FSM via SRI-SM

```bash
mt <oa> <da-msisdn> <text> [--smsc GT]
```

Example:

```bash
mt 1.1.817085811401 1.1.817085811402 mt test 456
```

### `alertServiceCentre`

```bash
alert <msisdn> [--smsc GT]
```

### MT response mode

```bash
mtmode success
mtmode absent
mtmode busy
```

### Other commands

```bash
status
stats
stats reset
reload
menu
stopload
exit
```

---

## Logging Behavior

The main log line shows:

- direction (`Send` / `Recv`)
- OPC / DPC
- TCAP transaction ID
- calling GT / called GT
- SCA when available
- MAP operation or TCAP primitive
- component type (`invoke`, `returnResultLast`, `returnError`, `reject`)
- decoded MAP error when possible
- OA / DA and TPDU preview for MO/MT SMS flows

Example:

```text
Send 641   -> 2120  TID=d0480700 817085811990 -> 817090514560       SCA=-              sendRoutingInfoForSM returnError ReturnError code=1 (unknownSubscriber)
```

---

## Troubleshooting

### No response generated

Check:

- SCTP association is up
- M3UA ASP is active
- point codes / GTs / SSNs are correct
- the remote peer is sending SCCP UDT/XUDT with parseable TCAP data

### Wrong rule matched

Check:

- the `match` value in the INI
- whether the request carries **MSISDN** or only **IMSI**
- whether a more specific rule also matches (longest match wins)

### MT-FSM rule not matching

Remember MT-FSM commonly carries **IMSI** in `SM-RP-DA`, so for some cases use:

```ini
match = imsi:44011*
```

### SRI-SM returns success instead of error

Check:

- the `response_rule` section name
- `sri_action = error`
- `sri_error = <valid MAP error name>`
- the rule actually matches the MSISDN in the incoming SRI-SM invoke

---

## Recommended Project Layout

```text
map_sms_gateway.py
map_sms_gateway.ini
README.md
```

Where:

- `map_sms_gateway.py` is the corrected gateway script
- `map_sms_gateway.ini` is the matching configuration
- `README.md` is this documentation

