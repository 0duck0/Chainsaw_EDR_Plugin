# Chainsaw_EDR_Plugin

## Purpose

I am attempting to find a solution to enhance the "on-premise" implementation of Carbon Black EDR with the use of Sigma rules.  The query/alerting capability is not nearly as robust as the Cloud EDR version.  I plan to use some broad queries/watchlists to focus on suspicious behavior, then use the API to export surrounding events and scan the JSON formatted process documents/events with Sigma rules.  Depending on the outcome, I would automate the creation of a security event (ticket/case) and possibly a memory/RAM image or process crashdump file for futher analysis.

## Plan
Leverage the capability already included in Chainsaw [https://labs.withsecure.com/tools/chainsaw] to scan JSON formatted exports from Carbon Black EDR via API with Sigma rules.
I wanted to see if I could write a field:value mapping between Sigma and Cb EDR to search and generate alerts from JSON files that are exported from Carbon Black EDR (formerly CB Response).  

## Thoughts
Python scripts perform faster than PowerShell but in order to share cyber defense information as widely as possible, I typically script with PowerShell since it comes packaged with Windows and in my experience, many cyber defenders don't have access to Python.

I have written scripts to export specified events from Carbon Black EDR via the REST API endpoints for various integrations and automated triage.  I'm hoping this will be another capability that I can include as a portable cyber response tool without needing to stand up an ELK stack.  
