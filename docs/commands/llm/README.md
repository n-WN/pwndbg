# LLM Integration

Pwndbg's LLM integration provides hooks and commands to capture TUI differential output and enable interaction with the debugger for automated pwn challenge solving. This system allows Large Language Models (LLMs) to monitor pwndbg's state changes and execute commands in a structured way.

## Overview

The LLM integration consists of three main components:

1. **TUI State Capture**: Automatically captures changes in pwndbg's TUI sections (registers, disassembly, stack, etc.)
2. **Command Interface**: Provides structured command execution for LLMs
3. **Configuration System**: Configurable parameters to control capture behavior

## Quick Start

### Enable LLM Integration
```bash
(pwndbg) set llm-enabled on
```

### Check Status
```bash
(pwndbg) llm-status
```

### Get Current TUI State
```bash
(pwndbg) llm-tui-diff
```

### Execute Commands
```bash
(pwndbg) llm-execute "info registers"
```

## Commands

| Command | Description |
|---------|-------------|
| [`llm-tui-diff`](llm-tui-diff.md) | Get TUI differential output for LLM analysis |
| [`llm-execute`](llm-execute.md) | Execute pwndbg commands through LLM interface |
| [`llm-status`](llm-status.md) | Show LLM integration status and configuration |

## Architecture

### TUI State Capture System

The capture system monitors changes in pwndbg's TUI sections:
- **Registers**: Register values and changes
- **Disassembly**: Assembly instructions around PC
- **Stack**: Stack memory content
- **Code**: Source code (if available)
- **Backtrace**: Call stack information
- **Custom sections**: Any other TUI sections

### Rate Limiting and Filtering

To avoid overwhelming the system:
- **Capture Interval**: Minimum time between captures
- **Diff Threshold**: Only capture when sufficient lines have changed
- **History Limit**: Maximum number of state snapshots to keep

### Thread Safety

All capture operations are thread-safe using locks to ensure:
- Consistent state when multiple threads access capture data
- Safe callback execution
- Proper history management

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `llm-enabled` | `off` | Master switch for LLM integration |
| `llm-capture-interval` | `1.0` | Seconds between captures |
| `llm-diff-threshold` | `10` | Lines changed to trigger capture |
| `llm-max-history` | `50` | Maximum history entries |

## Use Cases

### Automated Pwn Challenge Solving

LLMs can monitor TUI changes to:
- Detect when registers change during stepping
- Analyze stack corruption patterns
- Track memory layout changes
- Identify exploitation opportunities

Example workflow:
1. LLM enables monitoring: `set llm-enabled on`
2. LLM starts debugging process
3. System captures TUI changes automatically
4. LLM analyzes changes via `llm-tui-diff --format json`
5. LLM executes appropriate commands via `llm-execute`

### Interactive Debugging Assistant

LLMs can assist with debugging by:
- Suggesting next debugging steps based on current state
- Identifying suspicious patterns in memory/registers
- Recommending breakpoints or watchpoints
- Providing context-aware analysis

### External Tool Integration

External tools can integrate by:
- Parsing JSON output from `llm-tui-diff`
- Executing commands via `llm-execute`
- Monitoring configuration via `llm-status`
- Registering callbacks for real-time updates

## API Reference

### Python API

For advanced integration, the Python API provides direct access:

```python
from pwndbg.gdblib.llm_hooks import get_tui_differential_output, execute_llm_command

# Get current TUI state
state = get_tui_differential_output()

# Execute command
result = execute_llm_command("info registers", context={"purpose": "analysis"})
```

### Callback System

Register callbacks for real-time TUI change notifications:

```python
from pwndbg.gdblib.llm_hooks import tui_capture

def my_callback(diff_entry):
    print(f"TUI section {diff_entry['section']} changed")

tui_capture.register_callback(my_callback)
```

## Security Considerations

- LLM commands execute with the same privileges as pwndbg
- No additional sandboxing is provided
- Be cautious with commands that modify the target process
- Consider the security implications of automated command execution

## Performance Impact

- Minimal overhead when disabled
- Configurable capture frequency to balance responsiveness vs. resources
- Memory usage scales with history size and capture frequency
- Thread-safe operations may introduce slight synchronization overhead

## Troubleshooting

### Common Issues

**LLM integration not available**
- Check that the LLM hooks module loaded correctly
- Verify no import errors in pwndbg startup

**No TUI changes captured**
- Ensure `llm-enabled` is `on`
- Check that TUI is active and showing content
- Verify the target process is running

**High memory usage**
- Reduce `llm-max-history`
- Increase `llm-capture-interval`
- Increase `llm-diff-threshold`

### Debug Information

Use `llm-status` to check:
- Current configuration values
- Number of sections being tracked
- Recent capture activity

## Examples

### Basic LLM Workflow

```bash
# Setup
(pwndbg) set llm-enabled on
(pwndbg) set llm-capture-interval 0.5

# Start debugging
(pwndbg) file ./target
(pwndbg) break main
(pwndbg) run

# Get initial state
(pwndbg) llm-tui-diff --format json > initial_state.json

# Execute analysis commands
(pwndbg) llm-execute "info registers"
(pwndbg) llm-execute "telescope $rsp 20"
(pwndbg) llm-execute "vmmap"

# Step and capture changes
(pwndbg) step
(pwndbg) llm-tui-diff --format json > after_step.json
```

### Advanced Integration

```python
# External Python script example
import json
import subprocess

def get_pwndbg_state():
    result = subprocess.run(
        ['gdb', '-batch', '-ex', 'llm-tui-diff --format json'],
        capture_output=True, text=True
    )
    return json.loads(result.stdout)

def analyze_state(state):
    # LLM analysis logic here
    if 'registers' in state['current_state']:
        # Analyze register changes
        pass
    
    # Suggest next commands
    return ['step', 'info registers']

# Main analysis loop
state = get_pwndbg_state()
commands = analyze_state(state)
for cmd in commands:
    subprocess.run(['gdb', '-batch', '-ex', f'llm-execute "{cmd}"'])
```

## Contributing

To extend the LLM integration:

1. **Add new capture sections**: Modify `TUIStateCapture` to track additional TUI elements
2. **Create new commands**: Add commands to `pwndbg/commands/llm.py`
3. **Extend callbacks**: Add new callback types for different events
4. **Improve filtering**: Add more sophisticated diff detection

See the implementation in:
- `pwndbg/gdblib/llm_hooks.py` - Core capture system
- `pwndbg/commands/llm.py` - User commands
- `pwndbg/gdblib/tui/context.py` - TUI integration