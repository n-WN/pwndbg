# llm-tui-diff

```text
usage: llm-tui-diff [-h] [--format {json,pretty}] [--sections [SECTIONS ...]]

```

Get TUI differential output for LLM analysis.

This command returns a structured representation of recent TUI changes that can be used by LLMs for analysis and automated pwn challenge solving.

**Aliases:** llm-tui

## Optional arguments

|Short|Long|Help|
| :--- | :--- | :--- |
|-h|--help|show this help message and exit|
||--format {json,pretty}|Output format for the TUI differential data (default: pretty)|
||--sections [SECTIONS ...]|Specific TUI sections to include (default: all)|

## Examples

### Get all TUI changes in pretty format
```bash
(pwndbg) llm-tui-diff
```

### Get TUI changes in JSON format for programmatic use
```bash
(pwndbg) llm-tui-diff --format json
```

### Get only specific sections
```bash
(pwndbg) llm-tui-diff --sections disasm registers stack
```

## Output Structure

The command outputs information about:
- **Current State**: Current content of each TUI section
- **Recent Changes**: History of recent TUI state changes with timestamps
- **Command History**: History of recent command executions
- **Configuration**: Current LLM integration settings

### JSON Format

```json
{
  "current_state": {
    "disasm": ["mov eax, ebx", "add eax, 1"],
    "registers": ["EAX: 0x1000", "EBX: 0x2000"],
    "stack": ["0x7fff0000: 0x12345678"]
  },
  "recent_changes": [
    {
      "timestamp": 1234567890.0,
      "section": "disasm",
      "lines": ["mov eax, ebx", "add eax, 1"],
      "diff": {
        "added": ["add eax, 1"],
        "removed": [],
        "changed_count": 1
      },
      "registers": {
        "pc": "0x1000",
        "sp": "0x7fff0000",
        "bp": "0x7fff0008"
      }
    }
  ],
  "command_history": [
    {
      "command": "info registers",
      "output": "...",
      "success": true,
      "timestamp": 1234567890.0
    }
  ],
  "timestamp": 1234567890.0,
  "enabled": true
}
```

## Prerequisites

- LLM integration must be enabled: `set llm-enabled on`
- Target process should be running to capture meaningful TUI changes

## Configuration

Related configuration parameters:
- `llm-enabled`: Enable/disable LLM integration
- `llm-capture-interval`: How frequently to capture TUI changes (seconds)
- `llm-diff-threshold`: Minimum lines changed to trigger capture
- `llm-max-history`: Maximum history entries to keep

## Use Cases

- **Automated Analysis**: Feed TUI changes to LLM for automated pwn challenge analysis
- **State Monitoring**: Track how the debugger state changes over time
- **Integration**: Build external tools that monitor pwndbg's TUI state
- **Debugging**: Debug complex exploitation scenarios with AI assistance