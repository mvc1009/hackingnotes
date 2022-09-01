---
title: OPSEC Infrastructure
category: Red Team
order: 2
---

# Command & Control (C2)

Command and Control server as known as C2 or C&C is a computer controlled by an attacker which is used to send commannds to systems compromised by malware and receive stolen data from a target network.

During the inital compromise phase, a malicious payload is executed that will call back to infrastructure controlled by the adversary.

This payload is commonly referred to as an "implant", "agent" or "RAT" (Remote Access Trojan).

The server is the central control point of an engagement and allows an adversary to issue commands to compromised endpoints and receive the results.

There are differents C2 with different capabilities, but in general they have the ability to execute different flavours of code and tooling to facilitate the adversarial objectives, such as shell commands, PowerShell, native executables, reflective DLLs and .NET as well as network pivoting and defence evasion.

The agent can communicate with the infrastructure over different protocols such as HTTP(S), DNS, SMB and moreover.

There are a list of C2 frameworks that can be filtered by their features and capabilities.

* [https://www.thec2matrix.com/matrix](https://www.thec2matrix.com/matrix)

# Redirector


# Domain Fronting


# Domain Borrowing

