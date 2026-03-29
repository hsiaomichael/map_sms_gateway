# PROMPT.md

## Master Prompt for Generating `map_sms_gateway.py` and `map_sms_gateway.ini`

Use the following prompt with an LLM when you want it to generate a complete lab-use Python MAP/SIGTRAN SMS gateway and its matching INI configuration.

---

```text
Generate a complete lab-use Python MAP/SIGTRAN SMS gateway with exactly these output files:

1. map_sms_gateway.py
2. map_sms_gateway.ini

Do NOT generate placeholders, pseudo-code, stubs, summaries, or partial files.
Return the FULL contents of both files in separate code blocks.
The Python must be runnable and self-contained except for standard Linux SCTP socket support.
Do not use external telecom libraries such as pycrate. Build BER/TCAP/MAP/SCCP/M3UA helpers directly in Python.

========================================
GOAL
========================================

Create a Python 3 script named map_sms_gateway.py that acts as a GSM MAP / SIGTRAN SMS gateway for lab testing over:

- SCTP
- M3UA
- SCCP (UDT and XUDT)
- TCAP
- MAP

The script must support:

- MO-FSM origination
- MT-FSM origination via SRI-SM
- incoming SRI-SM handling
- incoming MT-FSM handling
- alertServiceCentre handling
- reportSM-DeliveryStatus handling
- anyTimeSubscriberInformation handling
- concatenated SMS support for GSM-7 and UCS-2
- interactive console menu
- direct command interface
- statistics and status display
- config reload
- detailed structured logging

Also generate a matching map_sms_gateway.ini with all required sections and realistic defaults.

========================================
IMPLEMENTATION CONSTRAINTS
========================================

- Use Python 3 only.
- Prefer standard library only:
  - socket
  - struct
  - threading
  - logging
  - logging.handlers
  - time
  - random
  - sys
  - json
  - configparser
  - traceback
  - datetime
  - typing
- The script must work on Linux where socket.IPPROTO_SCTP is available.
- No pycrate, no scapy, no external ASN.1 library, no external SS7/MAP dependency.
- Implement BER/ASN.1 helpers manually.
- Implement M3UA header/parameter encoding manually.
- Implement SCCP UDT/XUDT encoding manually.
- Implement enough TCAP parsing/building manually for the supported SMS flows.
- Implement enough MAP invoke/result/error encoding manually for the supported SMS flows.
- This is for LAB / interoperability testing only, not production.

========================================
FEATURES REQUIRED
========================================

1) CONFIG LOADING
- Read configuration from map_sms_gateway.ini using configparser.
- Use sections:
  - [transport]
  - [signaling]
  - [m3ua]
  - [sccp]
  - [imsi]
  - [examples]
  - [housekeeping]
  - [map]
  - [sri_table]
  - [menu_presets]
- Also support dynamic rule sections:
  - [response_rule:<rule_name>]

2) RESPONSE RULE ENGINE
Implement a rule engine with longest-match-wins behavior.

Rules may match:
- exact MSISDN
- prefix (example: 8170858114*)
- suffix (example: *1402)
- substring (example: *5811*)
- IMSI pattern (example: imsi:44011*)

Each [response_rule:<name>] section can include:
- match = ...
- sri_action = success | error
- sri_error = MAP error name
- sri_nnn = GT/NNN override for SRI success
- sri_imsi = IMSI or wildcard template
- mt_action = success | error | absent | busy
- mt_error = MAP error name

Use the rule engine for:
- incoming SRI-SM responses
- incoming MT-FSM responses

3) SRI-SM HANDLING
For incoming sendRoutingInfoForSM:
- decode target MSISDN if possible
- find matching response rule
- if sri_action=error, return MAP ReturnError
- if sri_action=success, return ReturnResultLast with IMSI + NNN
- if no rule matches, fall back to [sri_table] or generated IMSI + configured MSC/NNN

4) MT-FSM HANDLING
For incoming mt-forwardSM:
- parse IMSI/MSISDN target if possible
- find matching response rule
- support:
  - success
  - absentSubscriberSM
  - subscriberBusyForMT-SMS
  - generic MAP ReturnError by name
  - sm-DeliveryFailure with subcause support for:
    - memoryCapacityExceeded
    - equipmentProtocolError
    - equipmentNotSM-Equipped
    - unknownServiceCentre
    - sc-Congestion
    - invalidSME-Address
    - subscriberNotSC-Subscriber

5) MO-FSM ORIGINATION
- Build SMS-SUBMIT TPDU
- Support GSM-7 and UCS-2
- Support concatenated SMS for long MO messages
- Send MO-FSM as TCAP BEGIN transactions
- Track pending TX by OTID/TID for logging and acknowledgments

6) MT-FSM ORIGINATION VIA SRI-SM
- Send SRI-SM first
- Parse SRI-SM response IMSI + NNN
- Build SMS-DELIVER TPDU
- Send MT-FSM after SRI-SM success
- Support concatenated SMS long message handling
- Track pending SRI and MT dialogues

7) MENU / CONSOLE
Interactive menu with options similar to:
- 1 MO short
- 2 MT short
- 3 MO long
- 4 MT long
- 5 MO UCS2 short
- 6 MT UCS2 short
- 7 MO UCS2 long
- 8 MT UCS2 long
- 9 status
- 10 reload
- 11 log level toggle
- 12 stats
- 13 alertServiceCentre
- 14 MT response mode toggle
- 0 exit

Direct command interface:
- mo <oa> <da> <text> [--smsc GT]
- mt <oa> <da-msisdn> <text> [--smsc GT]
- alert <msisdn> [--smsc GT]
- mtmode success|absent|busy
- status
- stats
- stats reset
- reload
- menu
- stopload
- exit

8) LOAD TEST SUPPORT
Support menu-driven repeated send with:
- message count
- TPS
- {n} substitution
- {n:02d}, {n:03d}, etc.
Allow varying OA, DA, and text.

9) LOGGING
Implement structured logging with timestamps.
Main Send/Recv log line must show:
- direction
- OPC / DPC
- TID
- calling GT
- called GT
- SCA if available
- operation name or TCAP primitive
- component suffix:
  - invoke
  - returnResultLast
  - returnError
  - reject
- decoded error if possible
- OA / DA and text preview for SMS flows

Examples of desired style:
- sendRoutingInfoForSM invoke
- sendRoutingInfoForSM returnError ReturnError code=1 (unknownSubscriber)
- mo-forwardSM returnError ReturnError code=31 (subscriberBusyForMT-SMS)

10) TID / FLOW CORRELATION
Use stored pending transaction state so incoming TCAP END / ReturnError logs are correlated back to:
- MO-FSM
- MT-FSM
- SRI-SM
- alertServiceCentre
instead of only logging generic TCAP-END where possible.

11) MAP ERROR TABLE
Use a corrected MAP error lookup for the SMS-related values.
At minimum make sure these names/codes are mapped correctly:
- 1 = unknownSubscriber
- 6 = absentSubscriberSM
- 19 or 21 facilityNotSupported depending how you choose to structure generic/common mapping, but be consistent internally
- 31 = subscriberBusyForMT-SMS
- 32 = sm-DeliveryFailure
- 33 = messageWaitingListFull
- 34 = systemFailure
- 35 = dataMissing
- 36 = unexpectedDataValue
- 71 = unknownAlphabet
- 72 = ussd-Busy

Also support sm-DeliveryFailure subcause mapping:
- memoryCapacityExceeded
- equipmentProtocolError
- equipmentNotSM-Equipped
- unknownServiceCentre
- sc-Congestion
- invalidSME-Address
- subscriberNotSC-Subscriber

12) BUG FIX REQUIREMENT
Ensure there is NO bug where a local variable such as ct is used before assignment in the TCAP END handling path.
Be careful with SRI-SM error correlation code inside _handle_sccp.

========================================
INI REQUIREMENTS
========================================

Generate map_sms_gateway.ini with realistic defaults and these sections:
- [transport]
- [signaling]
- [m3ua]
- [sccp]
- [imsi]
- [examples]
- [housekeeping]
- [map]
- [sri_table]
- [menu_presets]

Also include example response rules:
- sri_unknownsubscriber_demo
- sri_absentsubscriber_demo
- sri_absentsubscriber_prefix_demo
- sri_success_override_demo
- mtfsm_absent_demo
- mtfsm_busy_demo
- mtfsm_memory_full_by_imsi_demo

Example rules must include:
- exact SRI unknownSubscriber
- exact SRI absentSubscriberSM
- prefix SRI absentSubscriberSM
- MT busy
- MT absent
- MT memoryCapacityExceeded by IMSI

========================================
OUTPUT FORMAT
========================================

Return ONLY:

1. a heading: map_sms_gateway.py
2. a Python code block with the full file content
3. a heading: map_sms_gateway.ini
4. an INI code block with the full file content

Do not omit any lines.
Do not summarize.
Do not explain unless there is an unavoidable ambiguity.
```

---

## Suggested Usage Notes

- Use this prompt when you want an LLM to generate a **complete one-shot version** of `map_sms_gateway.py` and `map_sms_gateway.ini`.
- If the model still produces incomplete output, first ask it for an architecture/design spec, then ask it to generate the final files in a second step.
- If you want the model to also generate documentation, append:

```text
Also generate a third file:
- README.md

The README must assume the runtime filenames are:
- map_sms_gateway.py
- map_sms_gateway.ini
```

