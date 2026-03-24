# Qualys Cloud Agent Troubleshooting Scripts

Automated diagnostic and troubleshooting tools for the Qualys Cloud Agent. Collects system, network, and agent health data without requiring specific Qualys knowledge.

## Getting Started

See the full documentation and scripts in the [Qualys Cloud Agent Troubleshooting Scripts](Qualys%20Cloud%20Agent%20Troubleshooting%20Scripts/) folder.

| Platform | Script | Requirements |
|----------|--------|--------------|
| Windows | `qualys_agent_troubleshoot.ps1` | PowerShell 5.1, Administrator |
| Linux | `qualys_agent_troubleshoot.py` | Python 3.6+, Root access |

## Quick Start

### Windows

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\qualys_agent_troubleshoot.ps1
```

### Linux

```bash
sudo python3 qualys_agent_troubleshoot.py
```

## Disclaimer

These tools are provided as-is with no warranty. Use at your own risk. Always review scripts before running them in your environment.

## Author

Brian Canaday
