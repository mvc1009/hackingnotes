---
title: Introduction
category: Red Team
order: 1
---

# Red Team

**Red Teaming** is the process of using tactics, techniques and procedures (TTPs) to emulate a real-world threat, with the goal of measuting the effectiveness of the people, processes and technologies used to defend an environment.

*Read Teaming* is often confused with *Penetration Testing*, but there are some key differences.

On one hand a *Pentest* is focused into identifying as many vulnerabilities as possible, demostrate how those may be exploited, and provide some contextual risk ratings. Normally Pentest are part ofa complicance requirement for example a montlhy or annual assessments.


On the other hand, red teams have a clear objective defined by the organization, gain access to a particular system, email accounts, database or file shares. The organizations are defending "something" and compromising the confidentiality, integrity and availability of that "something" represents a tangible risk which can be financial or reputational.

A Red Team will emulate a real-life threat to the organization. To challenge the detection and response capabilities, they need to reach the objective without getting caught, part of this is not compromising unnecessarily high-privileged accounts such as Domain Admins.


## Operations Security (OPSEC)

*Operations Security*, known as OPSEC is a term originating in the U.S military and adopted by the information security community. It's generally used to describe the ease with which actions can be observerd by enemy intelligence.

From the perspective of a *Red Team*, this would be a measure of how easy your actions can be observed and subsequently interrupted by a *Blue Team*.


## Threat Model

The role of a *Red Team* is to emulate a genuine threat to the organization. Can vary from low-skilled script kiddies to a more capable and oranised hacktivist group, or even APTs and nation-states.

Once a threat has been identified, the team would build a corresponding threat profile. This threat profile will define how the team will emulate this trheat by identifying its intent, motivations, capabilities, habits, TTPs and so on.

MITRE ATT&CK is a great source to find these tactics and techniques.

* [https://attack.mitre.org/matrices/enterprise/](https://attack.mitre.org/matrices/enterprise/)


## Breach Model

The Breach Model outlines the means by which the red team will gain access to the target environment.

This is usually by attempting to gain access in accordance with the threat or provided by the organization often called *"Assume Breach"*.

It is important to have a backup plan in the event access if a assume breach is not chosend and the red team is not able to gain initial access.

A compromise could be to revert to an assumed breach if the red team has not gained access in the first 25% of engagement timeframe.

This is critical because **red team assessments are more about detection and response, rather than prevention**, so those portions of the assessment are more important than trying to "prove" a breach can happen in the first place.