# SAST or AI, or SAST and AI?

Supporting materials for the research article published on Medium.

## What's This?

A structured comparison of classic SAST tools vs. AI agents for vulnerability detection.
No opinions, just results.

## Tools Tested

- Semgrep SAST (free version)
- Snyk SAST (free version)
- Cursor (Pro, auto model selection)
- Claude Code (Pro plan)

## Targets

All machines are from the Retired section of Hack The Box (VIP+ required):

| Machine | Difficulty | Key Vulnerabilities |
|---|---|---|
| Spiky Tamagotchi | Easy | Object Type Injection, RCE via Node.js code injection |
| Nexus Void | Medium | .NET Insecure Deserialization, SQL Injection |
| UnEarthly Shop | Hard | MongoDB Pipeline Injection, PHP POP chain RCE |

## Repo Structure

## Repo Structure
```
/prompts        # Prompts used for AI agents
/results        # Raw scan output from each tool
  /Spiky Tamagotchi
      /claude.md
      /cursor.md
      /semgrep.md
      /snyk.md
  /Nexus Void
      /claude.md
      /cursor.md
      /semgrep.md
      /snyk.md
  /UnEarthly Shop
      /claude.md
      /cursor.md
      /semgrep.md
      /snyk.md
```

## Disclaimer

All targets are retired HackTheBox machines with official writeups and source code provided for research purposes. No live systems were tested.