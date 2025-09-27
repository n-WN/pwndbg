# LLM Integration for Pwndbg

This implementation enables Large Language Models (LLMs) to automatically receive debugging context from pwndbg and interact with the debugger, making it possible to build automated Pwn challenge solving tools.

## Quick Start

```bash
# Get current debugging context
llm context

# Enable automatic context updates on debugging events  
set llm-auto-context on

# Test the integration
llm test
```

## Key Features

### 🎯 **Context Capture**
- Captures TUI-equivalent output from pwndbg
- Multiple output formats (JSON, text, structured)
- Automatic updates on debugging events
- Complete process state information

### 🔌 **Handler System**
- Register Python functions to receive context updates
- Event-driven programming model
- Safe error handling and isolation

### ⚙️ **Command Execution**
- Programmatic execution of pwndbg commands
- Security whitelist prevents destructive operations
- Structured result format

### 📡 **LLM Integration**
- Compatible with OpenAI, Anthropic, local LLMs
- Multiple output formats for different API requirements
- Comprehensive context for intelligent analysis

## Programming Interface

```python
import pwndbg.commands.llm_integration as llm

# Register handler for automatic updates
def my_handler(context):
    if context['event_type'] == 'stop':
        # Process stopped - analyze context
        formatted = llm.format_context_for_llm(context, "text")
        # Send to LLM API for analysis...

llm.register_llm_handler(my_handler)

# Manual context retrieval
context = llm.get_comprehensive_context()
result = llm.execute_pwndbg_command("vmmap")
```

## Files

- **`pwndbg/commands/llm_integration.py`** - Core implementation
- **`docs/llm_integration_guide.md`** - Comprehensive documentation  
- **`examples/llm_integration_example.py`** - Complete usage examples
- **`tests/unit_tests/test_llm_integration.py`** - Test suite

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `llm-auto-context` | `False` | Auto-send context on events |
| `llm-context-format` | `json` | Output format |
| `llm-hook-events` | `stop` | Events that trigger updates |

## Example: OpenAI Integration

```python
import openai
import pwndbg.commands.llm_integration as llm

def openai_debug_assistant(context):
    formatted = llm.format_context_for_llm(context, "text")
    
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{
            "role": "user", 
            "content": f"Analyze this debugging state:\n{formatted}"
        }]
    )
    
    print("🤖 LLM Analysis:")
    print(response.choices[0].message.content)

llm.register_llm_handler(openai_debug_assistant)
```

## Security

- Only safe, read-only commands are allowed
- Handler exceptions are isolated
- No direct file system access from command interface
- Context data is sanitized

## Use Cases

1. **Automated Pwn Challenge Solving**: LLMs can analyze debugging state and suggest exploitation steps
2. **Intelligent Debugging**: Get AI-powered insights into program behavior
3. **Educational Tools**: Automated explanation of debugging concepts
4. **Reverse Engineering**: AI-assisted analysis of complex binaries

## Getting Started

1. **Load the example**: `source examples/llm_integration_example.py`
2. **Enable auto-context**: `set llm-auto-context on`
3. **Start debugging** and see LLM integration in action
4. **Read the guide**: See `docs/llm_integration_guide.md` for complete documentation

This implementation makes pwndbg the first debugger with comprehensive LLM integration for automated exploitation assistance.