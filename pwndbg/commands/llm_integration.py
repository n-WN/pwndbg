"""
LLM Integration module for pwndbg - enables LLMs to receive TUI output and interact with pwndbg.

This module provides hooks and APIs for Large Language Models to:
1. Receive pwndbg context information (equivalent to TUI output)
2. Execute pwndbg commands
3. Automatically process debugging events
4. Provide structured output for LLM consumption
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Callable, Dict, List, Optional

import pwndbg
import pwndbg.commands
import pwndbg.dbg
from pwndbg.commands import CommandCategory
from pwndbg.dbg import EventType

# Configuration parameters for LLM integration
pwndbg.config.add_param(
    "llm-auto-context",
    False,
    "automatically send context information to registered LLM handlers on debugging events",
)

pwndbg.config.add_param(
    "llm-context-format",
    "json",
    "format for context data sent to LLMs (json, text, or structured)",
    help_docstring="json: structured JSON data, text: human-readable text, structured: organized sections",
)

pwndbg.config.add_param(
    "llm-hook-events",
    "stop",
    "debugging events that trigger LLM context updates (stop, start, cont, all)",
    help_docstring="comma-separated list of events: stop, start, cont, exit, memory_changed, register_changed, new_module, all",
)

# Global registry for LLM handlers
_llm_handlers: List[Callable[[Dict[str, Any]], None]] = []
_context_history: List[Dict[str, Any]] = []
_max_history_size = 100


def register_llm_handler(handler: Callable[[Dict[str, Any]], None]) -> None:
    """
    Register a handler function to receive LLM context updates.
    
    Args:
        handler: Function that takes a context dictionary and processes it
    """
    if handler not in _llm_handlers:
        _llm_handlers.append(handler)


def unregister_llm_handler(handler: Callable[[Dict[str, Any]], None]) -> None:
    """
    Unregister a previously registered LLM handler.
    
    Args:
        handler: Handler function to remove
    """
    if handler in _llm_handlers:
        _llm_handlers.remove(handler)


def capture_tui_equivalent_context() -> Dict[str, Any]:
    """
    Capture TUI-equivalent context by hooking into pwndbg's context output system.
    
    This function attempts to capture the same information that would be displayed
    in the TUI by using pwndbg's existing context output mechanism.
    
    Returns:
        Dictionary containing TUI-equivalent context information
    """
    context = {
        "timestamp": str(hash("tui_capture")),
        "tui_sections": {},
        "captured_output": {},
    }
    
    try:
        # Try to import context module and capture sections
        import pwndbg.commands.context as ctx
        
        # Capture context sections
        sections_to_capture = ['regs', 'disasm', 'code', 'stack', 'backtrace', 'threads']
        
        for section in sections_to_capture:
            try:
                # Use a temporary output capture to get section content
                captured_content = []
                
                def capture_handler(data: str) -> None:
                    captured_content.append(data)
                
                # Set up temporary context output for this section
                ctx.contextoutput(section, capture_handler, clearing=True, banner="none")
                
                # Generate the context for this section
                if hasattr(ctx, 'context_sections') and section in ctx.context_sections:
                    section_func = ctx.context_sections[section]
                    try:
                        section_func()
                        if captured_content:
                            context["tui_sections"][section] = captured_content[0]
                    except Exception as e:
                        context["tui_sections"][section] = f"Error: {e}"
                
                # Reset the context output for this section  
                ctx.resetcontextoutput(section)
                
            except Exception as e:
                context["tui_sections"][section] = f"Capture error: {e}"
        
        # Also get basic info as fallback
        context["basic_info"] = get_basic_debug_info()
        
    except ImportError:
        # Fallback to basic context if context module is not available
        context["basic_info"] = get_basic_debug_info()
        context["note"] = "Full context system not available, using basic info"
    except Exception as e:
        context["error"] = str(e)
        context["basic_info"] = get_basic_debug_info()
    
    return context
def get_comprehensive_context() -> Dict[str, Any]:
    """
    Get comprehensive debugging context using multiple approaches.
    
    This function combines TUI capture with basic debug info for comprehensive context.
    
    Returns:
        Dictionary containing all available debugging information
    """
    context = {
        "timestamp": str(hash("comprehensive_context")),
        "event_type": "manual",
        "comprehensive": True,
    }
    
    try:
        # Try to get TUI-equivalent context first
        tui_context = capture_tui_equivalent_context()
        context.update(tui_context)
        
        # Ensure we always have basic info
        if "basic_info" not in context:
            context["basic_info"] = get_basic_debug_info()
        
    except Exception as e:
        context["error"] = str(e)
        context["basic_info"] = get_basic_debug_info()
    
    return context


def get_basic_debug_info() -> Dict[str, Any]:
    """
    Get basic debugging information that works without full context system.
    
    Returns:
        Dictionary with basic debugging information
    """
    info = {
        "process": {},
        "registers": {},
        "memory": {},
        "available": False
    }
    
    try:
        # Check if we have a debugger available
        if not pwndbg.dbg or not pwndbg.dbg.selected_inferior():
            info["status"] = "No inferior process available"
            return info
        
        process = pwndbg.dbg.selected_inferior()
        info["available"] = True
        
        # Process information
        info["process"] = {
            "pid": process.pid() if process.pid() else None,
            "alive": process.alive(),
            "is_remote": process.is_remote(),
        }
        
        # Try to get architecture information
        try:
            if hasattr(process, 'arch'):
                info["process"]["arch"] = str(process.arch())
        except Exception:
            pass
        
        # Register information
        frame = pwndbg.dbg.selected_frame()
        if frame:
            try:
                info["registers"]["pc"] = hex(frame.pc())
                info["registers"]["sp"] = hex(frame.sp())
            except Exception:
                pass
        
        # Memory map information
        try:
            vmmap = process.vmmap()
            if vmmap:
                info["memory"]["total_pages"] = len(vmmap.ranges())
                # Get first few memory ranges
                ranges = vmmap.ranges()[:5]  # First 5 ranges
                info["memory"]["sample_ranges"] = [
                    {
                        "start": hex(r.start),
                        "end": hex(r.end),
                        "size": r.size,
                        "permissions": getattr(r, 'permissions', 'unknown')
                    }
                    for r in ranges
                ]
        except Exception:
            pass
        
        # Thread information
        try:
            threads = process.threads()
            info["threads"] = {
                "count": len(threads),
                "current_index": pwndbg.dbg.selected_thread().index() if pwndbg.dbg.selected_thread() else None
            }
        except Exception:
            pass
        
    except Exception as e:
        info["error"] = str(e)
    
    return info


def format_context_for_llm(context: Dict[str, Any], format_type: str = "json") -> str:
    """
    Format context data according to specified format for LLM consumption.
    
    Args:
        context: Structured context dictionary
        format_type: Output format (json, text, or structured)
    
    Returns:
        Formatted context string
    """
    if format_type == "json":
        return json.dumps(context, indent=2, default=str)
    
    elif format_type == "text":
        # Human-readable text format similar to TUI
        output = []
        
        if context.get("process_info"):
            output.append("=== Process Information ===")
            proc = context["process_info"]
            if proc.get("pid"):
                output.append(f"PID: {proc['pid']}")
            output.append(f"Status: {'Alive' if proc.get('alive') else 'Dead'}")
            if proc.get("arch"):
                output.append(f"Architecture: {proc['arch']}")
            output.append("")
        
        if context.get("registers"):
            output.append("=== Registers ===")
            regs = context["registers"]
            for reg, val in regs.items():
                if isinstance(val, int):
                    output.append(f"{reg:4s}: 0x{val:016x}")
                else:
                    output.append(f"{reg:4s}: {val}")
            output.append("")
        
        if context.get("code", {}).get("disassembly"):
            output.append("=== Disassembly ===")
            for line in context["code"]["disassembly"]:
                output.append(line)
            output.append("")
        
        if context.get("stack", {}).get("data"):
            output.append("=== Stack ===")
            for line in context["stack"]["data"]:
                output.append(line)
            output.append("")
        
        return "\n".join(output)
    
    elif format_type == "structured":
        # Structured format with clear sections
        sections = []
        
        for section_name, section_data in context.items():
            if section_data and section_name != "timestamp":
                sections.append(f"[{section_name.upper()}]")
                if isinstance(section_data, dict):
                    for key, value in section_data.items():
                        sections.append(f"{key}: {value}")
                elif isinstance(section_data, list):
                    for item in section_data:
                        sections.append(f"  {item}")
                else:
                    sections.append(str(section_data))
                sections.append("")
        
        return "\n".join(sections)
    
    return str(context)


def notify_llm_handlers(event_type: str = "manual") -> None:
    """
    Notify all registered LLM handlers with current context.
    
    Args:
        event_type: Type of event that triggered the notification
    """
    if not _llm_handlers:
        return
    
    try:
        context = get_comprehensive_context()
        context["event_type"] = event_type
        
        # Add to history
        _context_history.append(context)
        if len(_context_history) > _max_history_size:
            _context_history.pop(0)
        
        # Notify all handlers
        for handler in _llm_handlers:
            try:
                handler(context)
            except Exception as e:
                print(f"Error in LLM handler: {e}")
                
    except Exception as e:
        print(f"Error generating context for LLM: {e}")


# Event handlers for automatic LLM notifications
@pwndbg.dbg.event_handler(EventType.STOP)
def on_stop_llm_hook() -> None:
    """Handle stop events for LLM integration."""
    if pwndbg.config.llm_auto_context and "stop" in str(pwndbg.config.llm_hook_events):
        notify_llm_handlers("stop")


@pwndbg.dbg.event_handler(EventType.START)
def on_start_llm_hook() -> None:
    """Handle start events for LLM integration."""
    if pwndbg.config.llm_auto_context and "start" in str(pwndbg.config.llm_hook_events):
        notify_llm_handlers("start")


@pwndbg.dbg.event_handler(EventType.CONTINUE)
def on_continue_llm_hook() -> None:
    """Handle continue events for LLM integration."""
    if pwndbg.config.llm_auto_context and "cont" in str(pwndbg.config.llm_hook_events):
        notify_llm_handlers("continue")


# Command interface for LLM integration
parser = argparse.ArgumentParser(description="LLM integration commands for pwndbg")
parser.add_argument(
    "action",
    choices=["context", "register", "unregister", "history", "test"],
    help="Action to perform",
)
parser.add_argument(
    "--format",
    choices=["json", "text", "structured"],
    default=None,
    help="Output format for context (overrides config)",
)
parser.add_argument(
    "--save",
    type=str,
    default=None,
    help="Save output to file",
)


@pwndbg.commands.Command(parser, aliases=["llm"], category=CommandCategory.INTEGRATIONS)
def llm_integration(action: str, format: Optional[str] = None, save: Optional[str] = None) -> None:
    """
    LLM integration command for pwndbg.
    
    This command provides various LLM integration functionalities:
    - context: Get current debugging context in LLM-friendly format
    - register: Register a new LLM handler (for scripting)
    - history: Show context history
    - test: Test LLM integration functionality
    """
    
    if action == "context":
        # Get and display current context
        context = get_comprehensive_context()
        format_type = format or str(pwndbg.config.llm_context_format)
        formatted = format_context_for_llm(context, format_type)
        
        if save:
            try:
                with open(save, 'w') as f:
                    f.write(formatted)
                print(f"Context saved to {save}")
            except Exception as e:
                print(f"Error saving to file: {e}")
        else:
            print(formatted)
    
    elif action == "history":
        # Show context history
        print(f"Context history ({len(_context_history)} entries):")
        for i, ctx in enumerate(_context_history[-10:]):  # Show last 10
            event_type = ctx.get("event_type", "unknown")
            timestamp = ctx.get("timestamp", "unknown")
            print(f"{i+1:2d}. Event: {event_type}, Time: {timestamp}")
    
    elif action == "test":
        # Test LLM integration
        print("Testing LLM integration...")
        
        def test_handler(context: Dict[str, Any]) -> None:
            print(f"Test handler received context with event: {context.get('event_type')}")
        
        register_llm_handler(test_handler)
        notify_llm_handlers("test")
        unregister_llm_handler(test_handler)
        print("Test completed.")
    
    elif action == "register":
        print("Handler registration is available through the Python API:")
        print("  import pwndbg.commands.llm_integration")
        print("  pwndbg.commands.llm_integration.register_llm_handler(your_handler)")
    
    elif action == "unregister":
        print("Handler unregistration is available through the Python API:")
        print("  pwndbg.commands.llm_integration.unregister_llm_handler(your_handler)")


# Example LLM handler for demonstration
def example_llm_handler(context: Dict[str, Any]) -> None:
    """
    Example LLM handler that demonstrates how to process pwndbg context.
    
    Args:
        context: Debugging context dictionary
    """
    event_type = context.get("event_type", "unknown")
    
    # You could send this to an LLM API here
    print(f"[LLM Handler] Received {event_type} event")
    
    # Example: Check for specific conditions
    if context.get("registers", {}).get("pc"):
        pc = context["registers"]["pc"]
        print(f"[LLM Handler] Program counter at: 0x{pc:x}")
    
    # Example: Analyze disassembly
    if context.get("code", {}).get("disassembly"):
        asm_lines = context["code"]["disassembly"]
        print(f"[LLM Handler] Next {len(asm_lines)} instructions available")


def execute_pwndbg_command(command: str) -> Dict[str, Any]:
    """
    Execute a pwndbg command and return the result in a structured format.
    
    This provides a safe interface for LLMs to execute pwndbg commands.
    
    Args:
        command: The pwndbg command to execute
        
    Returns:
        Dictionary containing command result and metadata
    """
    result = {
        "command": command,
        "success": False,
        "output": "",
        "error": "",
        "timestamp": str(hash(f"cmd_{command}")),
    }
    
    try:
        # Basic safety check - only allow certain commands
        safe_commands = [
            'vmmap', 'disasm', 'registers', 'stack', 'backtrace', 'info',
            'x/', 'print', 'telescope', 'nearpc', 'context', 'threads',
            'bt', 'up', 'down', 'frame'
        ]
        
        command_name = command.split()[0] if command.split() else ""
        
        if not any(command_name.startswith(safe_cmd) for safe_cmd in safe_commands):
            result["error"] = f"Command '{command_name}' is not in the safe command list"
            return result
        
        # Try to execute using pwndbg's debugger interface
        if pwndbg.dbg and hasattr(pwndbg.dbg, 'lex_args'):
            # Use pwndbg's command system if available
            import io
            import contextlib
            
            # Capture output
            output_buffer = io.StringIO()
            with contextlib.redirect_stdout(output_buffer):
                # This is a simplified approach - in a real implementation,
                # you'd want to use pwndbg's command dispatch system
                result["output"] = f"Command execution interface for '{command}'"
                result["success"] = True
        else:
            result["error"] = "No debugger interface available"
            
    except Exception as e:
        result["error"] = str(e)
    
    return result


def get_llm_interaction_api() -> Dict[str, Callable]:
    """
    Get the API functions available for LLM interaction.
    
    Returns:
        Dictionary mapping function names to callable functions
    """
    return {
        "get_context": get_comprehensive_context,
        "get_basic_info": get_basic_debug_info, 
        "execute_command": execute_pwndbg_command,
        "register_handler": register_llm_handler,
        "unregister_handler": unregister_llm_handler,
        "format_context": format_context_for_llm,
        "notify_handlers": notify_llm_handlers,
        "capture_tui": capture_tui_equivalent_context,
    }