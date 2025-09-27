"""
LLM integration commands for automated pwn challenge solving.

This module provides commands to interact with the LLM TUI capture system
and enable automated assistance for pwn challenges.
"""

from __future__ import annotations

import argparse
import json
import pprint
from typing import Any
from typing import Dict
from typing import Optional

import pwndbg
import pwndbg.color.message as M
import pwndbg.commands
from pwndbg.commands import CommandCategory

try:
    from pwndbg.gdblib.llm_hooks import execute_llm_command
    from pwndbg.gdblib.llm_hooks import get_tui_differential_output
    from pwndbg.gdblib.llm_hooks import tui_capture
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False


parser = argparse.ArgumentParser(description="Get TUI differential output for LLM analysis")
parser.add_argument(
    "--format",
    choices=["json", "pretty"],
    default="pretty",
    help="Output format for the TUI differential data"
)
parser.add_argument(
    "--sections",
    nargs="*",
    help="Specific TUI sections to include (default: all)"
)


@pwndbg.commands.Command(parser, aliases=["llm-tui"], category=CommandCategory.CONTEXT)
def llm_tui_diff(format="pretty", sections=None):
    """
    Get the current TUI differential output for LLM consumption.
    
    This command returns a structured representation of recent TUI changes
    that can be used by LLMs for analysis and automated pwn challenge solving.
    """
    if not LLM_AVAILABLE:
        print(M.error("LLM hooks are not available. Check your installation."))
        return
    
    try:
        diff_data = get_tui_differential_output()
        
        # Filter by sections if specified
        if sections:
            current_state = {k: v for k, v in diff_data["current_state"].items() if k in sections}
            recent_changes = [
                change for change in diff_data["recent_changes"] 
                if change.get("section") in sections
            ]
            diff_data["current_state"] = current_state
            diff_data["recent_changes"] = recent_changes
        
        if format == "json":
            print(json.dumps(diff_data, indent=2))
        else:
            _print_pretty_diff(diff_data)
            
    except Exception as e:
        print(M.error(f"Failed to get TUI differential output: {e}"))


def _print_pretty_diff(diff_data: Dict[str, Any]) -> None:
    """Print TUI differential data in a human-readable format."""
    print(M.banner("TUI Differential Output"))
    
    print(f"Enabled: {M.success('Yes') if diff_data['enabled'] else M.error('No')}")
    print(f"Timestamp: {diff_data['timestamp']}")
    print()
    
    # Current state
    current_state = diff_data.get("current_state", {})
    if current_state:
        print(M.subheader("Current TUI State:"))
        for section, lines in current_state.items():
            print(f"  {M.green(section)}: {len(lines)} lines")
        print()
    
    # Recent changes
    recent_changes = diff_data.get("recent_changes", [])
    if recent_changes:
        print(M.subheader(f"Recent Changes ({len(recent_changes)} entries):"))
        for i, change in enumerate(recent_changes[-5:]):  # Show last 5
            section = change.get("section", "unknown")
            timestamp = change.get("timestamp", 0)
            diff_info = change.get("diff", {})
            changed_count = diff_info.get("changed_count", 0)
            
            print(f"  {i+1}. {M.blue(section)} - {changed_count} changes at {timestamp}")
            
            if "registers" in change and change["registers"]:
                regs = change["registers"]
                print(f"     Registers: PC={regs.get('pc', 'N/A')}, SP={regs.get('sp', 'N/A')}")
        print()
    
    # Command history
    cmd_history = diff_data.get("command_history", [])
    if cmd_history:
        print(M.subheader(f"Recent Commands ({len(cmd_history)} entries):"))
        for cmd in cmd_history[-3:]:  # Show last 3
            success = M.success("✓") if cmd.get("success", False) else M.error("✗")
            print(f"  {success} {cmd.get('command', 'unknown')}")
        print()


execute_parser = argparse.ArgumentParser(description="Execute a pwndbg command through LLM interface")
execute_parser.add_argument("command", help="The pwndbg command to execute")
execute_parser.add_argument(
    "--context",
    help="JSON context to pass with the command",
    default=None
)
execute_parser.add_argument(
    "--format",
    choices=["json", "pretty"],
    default="pretty",
    help="Output format for the command result"
)


@pwndbg.commands.Command(execute_parser, aliases=["llm-exec"], category=CommandCategory.CONTEXT)
def llm_execute(command, context=None, format="pretty"):
    """
    Execute a pwndbg command through the LLM interface.
    
    This provides a structured way for LLMs to execute commands and get
    formatted responses suitable for automated analysis.
    """
    if not LLM_AVAILABLE:
        print(M.error("LLM hooks are not available. Check your installation."))
        return
    
    try:
        # Parse context if provided
        parsed_context = None
        if context:
            try:
                parsed_context = json.loads(context)
            except json.JSONDecodeError as e:
                print(M.error(f"Invalid JSON context: {e}"))
                return
        
        # Execute command
        result = execute_llm_command(command, parsed_context)
        
        if format == "json":
            print(json.dumps(result, indent=2))
        else:
            _print_pretty_command_result(result)
            
    except Exception as e:
        print(M.error(f"Failed to execute command: {e}"))


def _print_pretty_command_result(result: Dict[str, Any]) -> None:
    """Print command execution result in a human-readable format."""
    command = result.get("command", "unknown")
    success = result.get("success", False)
    output = result.get("output", "")
    error = result.get("error", "")
    
    status = M.success("SUCCESS") if success else M.error("FAILED")
    print(f"Command: {M.blue(command)} - {status}")
    
    if output:
        print(M.subheader("Output:"))
        print(output)
    
    if error:
        print(M.subheader("Error:"))
        print(M.error(error))


status_parser = argparse.ArgumentParser(description="Show LLM integration status")


@pwndbg.commands.Command(status_parser, aliases=["llm-status"], category=CommandCategory.CONTEXT)
def llm_status():
    """Show the current status of LLM integration."""
    if not LLM_AVAILABLE:
        print(M.error("LLM hooks are not available. Check your installation."))
        return
    
    print(M.banner("LLM Integration Status"))
    
    # Configuration status
    enabled = bool(pwndbg.config.llm_enabled)
    print(f"Enabled: {M.success('Yes') if enabled else M.error('No')}")
    print(f"Capture Interval: {pwndbg.config.llm_capture_interval}s")
    print(f"Diff Threshold: {pwndbg.config.llm_diff_threshold} lines")
    print(f"Max History: {pwndbg.config.llm_max_history} entries")
    print()
    
    # Current capture status
    if tui_capture:
        current_state = tui_capture.get_current_state()
        recent_changes = tui_capture.get_recent_changes(5)
        
        print(M.subheader("Capture Status:"))
        print(f"Sections tracked: {len(current_state)}")
        print(f"Recent changes: {len(recent_changes)}")
        
        if current_state:
            print("Active sections:", ", ".join(current_state.keys()))
    
    print()
    print(M.subheader("Usage:"))
    print("  llm-tui-diff     - Get current TUI differential output")
    print("  llm-execute <cmd> - Execute command through LLM interface")
    print("  llm-status       - Show this status information")
    print()
    print("Configuration:")
    print("  set llm-enabled on/off")
    print("  set llm-capture-interval <seconds>")
    print("  set llm-diff-threshold <lines>")


# Register callback for demonstration (can be used by external LLM systems)
def _example_llm_callback(diff_entry: Dict[str, Any]) -> None:
    """Example callback that could be used by an LLM system."""
    # This is just a placeholder - real LLM integration would implement
    # sophisticated analysis here
    section = diff_entry.get("section", "unknown")
    changes = diff_entry.get("diff", {}).get("changed_count", 0)
    
    if changes > 20:  # Significant change threshold
        print(M.notice(f"LLM: Significant change detected in {section} ({changes} lines)"))


# Register the example callback if LLM is available
if LLM_AVAILABLE and tui_capture:
    tui_capture.register_callback(_example_llm_callback)