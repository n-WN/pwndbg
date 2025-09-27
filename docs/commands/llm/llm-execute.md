# llm-execute

```text
usage: llm-execute [-h] [--context CONTEXT] [--format {json,pretty}] command

```

Execute a pwndbg command through the LLM interface.

This provides a structured way for LLMs to execute commands and get formatted responses suitable for automated analysis.

**Aliases:** llm-exec

## Positional arguments

|Positional Argument|Help|
| :--- | :--- |
|command|The pwndbg command to execute|

## Optional arguments

|Short|Long|Help|
| :--- | :--- | :--- |
|-h|--help|show this help message and exit|
||--context CONTEXT|JSON context to pass with the command|
||--format {json,pretty}|Output format for the command result (default: pretty)|

## Examples

### Execute a simple command
```bash
(pwndbg) llm-execute "info registers"
```

### Execute with context and JSON output
```bash
(pwndbg) llm-execute --context '{"reason": "check_registers"}' --format json "info registers"
```

### Execute multiple commands for analysis
```bash
(pwndbg) llm-execute "x/10i $pc"
(pwndbg) llm-execute "telescope $rsp 20"
(pwndbg) llm-execute "vmmap"
```

## Output Structure

### Pretty Format
```
Command: info registers - SUCCESS
Output:
rax            0x0                 0
rbx            0x0                 0
rcx            0x0                 0
...
```

### JSON Format
```json
{
  "command": "info registers",
  "output": "rax            0x0                 0\nrbx            0x0                 0\n...",
  "success": true,
  "timestamp": 1234567890.0,
  "context": {
    "reason": "check_registers"
  }
}
```

## Context Parameter

The `--context` parameter accepts JSON data that can provide additional information about why the command is being executed. This helps with:
- **Traceability**: Understanding why a command was executed
- **Analysis**: Providing context for automated analysis
- **Debugging**: Tracking command execution flow

Example context values:
```json
{"reason": "initial_analysis"}
{"step": "vulnerability_detection", "target": "buffer_overflow"}
{"phase": "exploitation", "attempt": 3}
```

## Error Handling

When a command fails, the output includes error information:

```json
{
  "command": "invalid_command",
  "output": "",
  "success": false,
  "error": "Undefined command: \"invalid_command\".",
  "timestamp": 1234567890.0,
  "context": {}
}
```

## Command History

All executed commands are tracked and can be retrieved using `llm-tui-diff` to see the command history along with TUI changes.

## Security Considerations

- Commands are executed with the same privileges as the current pwndbg session
- Be cautious when executing commands that modify the target process
- The interface provides no additional sandboxing beyond normal pwndbg security

## Use Cases

- **Automated Exploitation**: Let LLMs execute commands as part of automated pwn workflows
- **Interactive Analysis**: Provide structured command execution for LLM-assisted debugging
- **Batch Processing**: Execute multiple commands with proper result tracking
- **External Integration**: Allow external tools to execute pwndbg commands safely