## What is Yara?

Yara can identify information based on both binary and textual patterns, Those patterns are labeled by rules.

## Intro to Yara rules

2 arguments required for every `Yara` command:

1. The rule file we create.
2. Name of file, directory or process id we want to use the rule for.

Example - `yara myrule.yar somedirectory`

## Yara modules

Cuckoo: A sandbox that lets you generate rules based on the behaviors discovered from malware.

Python PE: Allows you to create Yara rules based on Windows Portable Executable (PE) strocture.

## Other tools and Yara

LOKI: Free open source IOC scanner, checks File name, Yara rule, hash and C2 back connect.

THOR: multi-platform IOC and YARA scanner.

FENRIR: Updated version of the previous 2 tools.

YAYA: Helping manage multiple Yara rule repositories, starts by adding a set of high quality rules and lets researchers add or disable rules, currently only works on Linux.

## Creating Yara rules with YarGen

1. Check the strings in a suspicious file
2. Update yarGen - `python3 yarGen.py --update`
3. Generate the rule - `python3 yarGen.py -m suspicious-file --excludegood -o suspicious-file.yar`

## Valhalla

_Valhalla boosts your detection capabilities with the power of thousands of hand-crafted high-quality YARA rules._