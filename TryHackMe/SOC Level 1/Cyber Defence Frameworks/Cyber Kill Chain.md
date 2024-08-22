Military concept of target identification, decision and order to attack the target and target destruction

**Attack phases:**

- Reconnaissance
- Weaponization
- Delivery
- Exploitation
- Installation
- Command & Control
- Actions on Objectives

## Reconnaissance

OSINT (Open-Source Intelligence): The first step of the attacker to find out things like company's size, email address and phone numbers

## Weaponization

The phase in which the attacker will get is payload ready

## Delivery

In this phase the attacker choose how to deliver the payload or malware

**Some techniques:**

- Phishing or spear phishing (targeting individual person)
- Distributing affected USB drives
- Watering hole attack, where the attacker targets a visited website for example with a drive-by download where the attacker do something like malicious pop-up asking to download a fake browser extension

## Exploitation

Lateral movement: techniques to move deeper into a network

Zero-day Exploit: Unknown exploit

## Installation

When the attacker installs a persistent backdoor

Timestomping: A technique to avoid detection by modifying the file's timestamps including the modify, access, create and change times

## Command & Control

When the attacker opens up the C2 channel, and the infected host will constantly communicate with the C2 channel (C2 beaconing or C&C)

Internet Relay Chat (IRC): Was the traditional C2 channel but modern security solutions can easily detect

Today it's most common to use HTTP, HTTPS and DNS

DNS Tunneling: Where the victim makes regular DNS requests to a DNS server owned by the attacker

## Actions On Objectives (Exfiltration)

The phase in which the attacker finally achieves his goals and also moves around the system and privilege excalating