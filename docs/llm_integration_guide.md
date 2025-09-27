# LLM Integration Guide for Pwndbg

This guide explains how to integrate Large Language Models (LLMs) with pwndbg for automated debugging assistance.

## Overview

The LLM integration system allows LLMs to:
- Receive debugging context equivalent to TUI output
- Monitor debugging events automatically  
- Execute safe pwndbg commands
- Analyze debugging state and provide insights

## Quick Start

### 1. Basic Usage

```bash
# Get current debugging context
llm context

# Get context in different formats
llm context --format json
llm context --format text
llm context --format structured

# Save context to file
llm context --save /tmp/debug_context.json

# View context history
llm history

# Test the system
llm test
```

### 2. Enable Automatic Context Updates

```bash
# Enable automatic context sending on debugging events
set llm-auto-context on

# Configure which events trigger updates
set llm-hook-events stop,start,cont

# Set output format for context data
set llm-context-format json
```

## Programming Interface

### Handler Registration

Register functions to receive debugging context automatically:

```python
import pwndbg.commands.llm_integration as llm

def my_handler(context):
    """Process debugging context from pwndbg."""
    event_type = context.get("event_type")
    print(f"Received {event_type} event")
    
    # Access process information
    if "basic_info" in context:
        info = context["basic_info"]
        if info.get("available"):
            proc = info["process"]
            print(f"PID: {proc.get('pid')}")
            print(f"Alive: {proc.get('alive')}")

# Register the handler
llm.register_llm_handler(my_handler)

# Unregister when done
llm.unregister_llm_handler(my_handler)
```

### Context Formats

#### JSON Format
```python
context = llm.get_comprehensive_context()
json_output = llm.format_context_for_llm(context, "json")
# Returns structured JSON data suitable for API calls
```

#### Text Format  
```python
text_output = llm.format_context_for_llm(context, "text")
# Returns human-readable text similar to TUI output:
# === Process Information ===
# PID: 1234
# Status: Alive
# Architecture: x86_64
# 
# === Registers ===
# pc  : 0x0000000012345678
# sp  : 0x0000000087654321
```

#### Structured Format
```python
structured_output = llm.format_context_for_llm(context, "structured")
# Returns organized sections:
# [PROCESS_INFO]
# pid: 1234
# alive: True
# 
# [REGISTERS]
# pc: 305419896
# sp: 2271560481
```

### Safe Command Execution

Execute pwndbg commands programmatically:

```python
# Execute safe commands
result = llm.execute_pwndbg_command("vmmap")
if result["success"]:
    print(result["output"])
else:
    print(f"Error: {result['error']}")

# Safe commands include: vmmap, disasm, registers, stack, backtrace, etc.
# Destructive commands are blocked for security
```

### Complete API Reference

```python
api = llm.get_llm_interaction_api()

# Available functions:
api["get_context"]()         # Get comprehensive context
api["get_basic_info"]()      # Get basic debugging info  
api["execute_command"](cmd)  # Execute safe command
api["register_handler"](fn)  # Register event handler
api["unregister_handler"](fn) # Unregister handler
api["format_context"](ctx, fmt) # Format context data
api["notify_handlers"](event) # Trigger handler notifications
api["capture_tui"]()         # Capture TUI-equivalent data
```

## Context Data Structure

The context dictionary contains:

```python
{
    "timestamp": "unique_identifier",
    "event_type": "stop|start|continue|manual",
    "basic_info": {
        "available": True,
        "process": {
            "pid": 1234,
            "alive": True,
            "is_remote": False,
            "arch": "x86_64"
        },
        "registers": {
            "pc": "0x12345678",
            "sp": "0x87654321"
        },
        "threads": {
            "count": 1,
            "current_index": 0
        },
        "memory": {
            "total_pages": 10,
            "sample_ranges": [...]
        }
    },
    "tui_sections": {
        "regs": "register output...",
        "disasm": "disassembly output...", 
        "stack": "stack output...",
        "backtrace": "backtrace output..."
    }
}
```

## Event-Driven Programming

### Event Types

- `stop`: Process stopped (breakpoint, signal, etc.)
- `start`: Process started/attached
- `continue`: Process resumed execution  
- `manual`: Manually triggered context update

### Automatic Event Handling

```python
@llm.register_llm_handler  # Alternative registration method
def auto_analyzer(context):
    """Automatically analyze debugging state."""
    if context["event_type"] == "stop":
        # Analyze why the process stopped
        basic = context.get("basic_info", {})
        if basic.get("available"):
            pc = basic.get("registers", {}).get("pc")
            if pc:
                print(f"Stopped at: {pc}")
                # Send to LLM for analysis...
```

## Integration Examples

### OpenAI Integration

```python
import openai
import pwndbg.commands.llm_integration as llm

def openai_debug_assistant(context):
    """Send debugging context to OpenAI for analysis."""
    # Format context for LLM
    formatted = llm.format_context_for_llm(context, "text")
    
    # Create prompt
    prompt = f"""
    I'm debugging a program. Here's the current state:
    
    {formatted}
    
    Please analyze this and suggest debugging steps.
    """
    
    # Call OpenAI API
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    
    print("🤖 LLM Analysis:")
    print(response.choices[0].message.content)

# Register for automatic analysis on stop events
llm.register_llm_handler(openai_debug_assistant)
```

### Local LLM Integration

```python
import requests
import pwndbg.commands.llm_integration as llm

def local_llm_analysis(context):
    """Send context to local LLM (e.g., Ollama)."""
    if context["event_type"] != "stop":
        return
        
    formatted = llm.format_context_for_llm(context, "text")
    
    # Local LLM API call
    response = requests.post("http://localhost:11434/api/generate", json={
        "model": "codellama",
        "prompt": f"Analyze this debugging context:\n{formatted}",
        "stream": False
    })
    
    if response.ok:
        result = response.json()
        print("🦙 Local LLM Analysis:")
        print(result.get("response", "No response"))

llm.register_llm_handler(local_llm_analysis)
```

### File-Based Integration

```python
import json
import pwndbg.commands.llm_integration as llm

def file_logger(context):
    """Log debugging context to file for external processing."""
    log_file = "/tmp/pwndbg_context.jsonl"
    
    # Append context as JSON lines
    with open(log_file, "a") as f:
        json.dump(context, f, default=str)
        f.write("\n")

llm.register_llm_handler(file_logger)
```

## Configuration Options

| Parameter | Default | Description |
|-----------|---------|-------------|
| `llm-auto-context` | `False` | Auto-send context on debugging events |
| `llm-context-format` | `json` | Format for context data (json/text/structured) |
| `llm-hook-events` | `stop` | Events that trigger updates (comma-separated) |

## Security Considerations

- Only safe, read-only commands are allowed in `execute_pwndbg_command()`
- Destructive commands (quit, kill, etc.) are blocked
- Handler exceptions are caught to prevent crashes
- Context data is sanitized before sending

## Troubleshooting

### Common Issues

1. **Import Error**: Ensure pwndbg is properly installed and the module is available
2. **No Context Data**: Check that a debugging session is active
3. **Handler Not Called**: Verify `llm-auto-context` is enabled and events are configured
4. **Command Execution Failed**: Ensure the command is in the safe command list

### Debug Mode

```python
# Enable verbose logging
import pwndbg.commands.llm_integration as llm

def debug_handler(context):
    print(f"Debug: Received context with keys: {list(context.keys())}")

llm.register_llm_handler(debug_handler)
```

## Advanced Usage

### Custom Context Processors

```python
def enhanced_context_processor(context):
    """Add custom analysis to context."""
    # Add custom fields
    context["custom_analysis"] = analyze_custom_data()
    
    # Modify existing data
    if "basic_info" in context:
        context["basic_info"]["custom_field"] = "custom_value"
    
    return context

# Process context before sending to other handlers
def main_handler(context):
    enhanced = enhanced_context_processor(context)
    # Send enhanced context to LLM...
```

### Integration with External Tools

```python
def ghidra_integration(context):
    """Integrate with Ghidra for enhanced analysis."""
    if "tui_sections" in context and "disasm" in context["tui_sections"]:
        disasm = context["tui_sections"]["disasm"]
        # Send to Ghidra for analysis
        # Get enhanced function information
        # Combine with LLM analysis
```

## Example Scripts

Complete examples are available in:
- `examples/llm_integration_example.py` - Comprehensive demonstration
- `tests/unit_tests/test_llm_integration.py` - Test cases and usage patterns

Load the example script in pwndbg:
```bash
source examples/llm_integration_example.py
setup_llm_integration_example()
```

## Contributing

To extend the LLM integration system:

1. Add new context capture methods in `capture_tui_equivalent_context()`
2. Extend safe command list in `execute_pwndbg_command()`
3. Add new output formats in `format_context_for_llm()`
4. Create new event handlers for additional debugging events

## License

This LLM integration system is part of pwndbg and follows the same license terms.