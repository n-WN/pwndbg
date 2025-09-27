# llm-status

```text
usage: llm-status [-h]

```

Show the current status of LLM integration.

**Aliases:** llm-status

## Optional arguments

|Short|Long|Help|
| :--- | :--- | :--- |
|-h|--help|show this help message and exit|

## Output Information

The command displays:

### Configuration Status
- **Enabled**: Whether LLM integration is currently enabled
- **Capture Interval**: How frequently TUI changes are captured (seconds)
- **Diff Threshold**: Minimum number of changed lines to trigger capture
- **Max History**: Maximum number of TUI state snapshots kept in memory

### Capture Status
- **Sections Tracked**: Number of TUI sections currently being monitored
- **Recent Changes**: Number of recent TUI state changes captured
- **Active Sections**: List of TUI sections with current state

### Usage Information
- Commands available for LLM integration
- Configuration parameters that can be modified

## Example Output

```
═══════════════════════════════════════════════════════════════
                         LLM Integration Status
═══════════════════════════════════════════════════════════════

Enabled: Yes
Capture Interval: 1.0s
Diff Threshold: 10 lines
Max History: 50 entries

Capture Status:
Sections tracked: 5
Recent changes: 12
Active sections: disasm, registers, stack, backtrace, code

Usage:
  llm-tui-diff     - Get current TUI differential output
  llm-execute <cmd> - Execute command through LLM interface
  llm-status       - Show this status information

Configuration:
  set llm-enabled on/off
  set llm-capture-interval <seconds>
  set llm-diff-threshold <lines>
```

## Configuration Parameters

The following parameters can be configured to control LLM integration behavior:

### `llm-enabled`
- **Type**: Boolean (on/off)
- **Default**: off
- **Description**: Master switch for LLM integration functionality

```bash
(pwndbg) set llm-enabled on
```

### `llm-capture-interval`
- **Type**: Float (seconds)
- **Default**: 1.0
- **Description**: Minimum time between TUI state captures to avoid overwhelming the system

```bash
(pwndbg) set llm-capture-interval 0.5
```

### `llm-diff-threshold`
- **Type**: Integer (lines)
- **Default**: 10
- **Description**: Minimum number of changed lines required to trigger a TUI state capture

```bash
(pwndbg) set llm-diff-threshold 5
```

### `llm-max-history`
- **Type**: Integer (entries)
- **Default**: 50
- **Description**: Maximum number of TUI state snapshots to keep in memory

```bash
(pwndbg) set llm-max-history 100
```

## Troubleshooting

### LLM Integration Not Available
If you see "LLM hooks are not available", this indicates:
- The LLM integration module failed to load
- Required dependencies might be missing
- There may be an import error in the LLM hooks module

### No Sections Tracked
If sections tracked shows 0:
- Ensure `llm-enabled` is set to `on`
- Check that TUI is active and showing context
- Verify that the target process is running

### No Recent Changes
If recent changes shows 0:
- The TUI content may not be changing significantly
- Consider lowering `llm-diff-threshold`
- Check that the debugger is actively stepping through code

## Performance Considerations

- Higher capture frequency (`llm-capture-interval`) increases memory usage
- Lower diff threshold (`llm-diff-threshold`) creates more history entries
- Large history size (`llm-max-history`) uses more memory but provides more context

## Integration with External Tools

External tools can check LLM status by:
1. Parsing the output of `llm-status`
2. Using the configuration parameters to understand current settings
3. Monitoring the capture status to determine if data is being collected