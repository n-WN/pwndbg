#!/usr/bin/env python3
"""
LLM Integration Demo Script

This script demonstrates how to use pwndbg's LLM integration features
for automated pwn challenge analysis.

Usage:
    # In pwndbg:
    (pwndbg) source examples/llm_integration_demo.py
    (pwndbg) llm-demo
"""

import argparse
import json
import time
from typing import Dict, List, Any

import pwndbg
import pwndbg.commands
from pwndbg.commands import CommandCategory


def analyze_register_changes(current_state: Dict[str, Any], previous_state: Dict[str, Any]) -> List[str]:
    """
    Analyze register changes between two states and suggest next actions.
    
    This is a simplified example of how an LLM might analyze register changes.
    """
    suggestions = []
    
    current_regs = current_state.get("registers", [])
    previous_regs = previous_state.get("registers", [])
    
    # Simple heuristic: if registers section changed significantly
    if len(current_regs) != len(previous_regs):
        suggestions.append("Registers changed - investigate with 'info registers'")
    
    # Look for common patterns
    for line in current_regs:
        if "0x" in line and ("41414141" in line or "42424242" in line):
            suggestions.append("Potential buffer overflow detected - check stack with 'telescope $rsp'")
        elif "rip" in line.lower() and "0x" in line:
            suggestions.append("Check instruction pointer - examine with 'x/5i $rip'")
    
    return suggestions


def analyze_stack_changes(current_state: Dict[str, Any]) -> List[str]:
    """
    Analyze stack content for potential vulnerabilities or interesting patterns.
    """
    suggestions = []
    
    stack_lines = current_state.get("stack", [])
    
    for line in stack_lines:
        if "41414141" in line or "AAAA" in line:
            suggestions.append("Stack corruption detected - potential buffer overflow")
        elif "ret" in line.lower() and "0x" in line:
            suggestions.append("Return address on stack - check for ROP opportunities")
        elif "libc" in line:
            suggestions.append("libc address on stack - potential for ASLR leak")
    
    return suggestions


def automated_analysis_demo():
    """
    Demonstrate automated analysis using LLM integration.
    """
    try:
        # Import LLM functions
        from pwndbg.gdblib.llm_hooks import get_tui_differential_output, execute_llm_command
        
        print("Starting LLM Integration Demo...")
        print("=" * 50)
        
        # Check if LLM integration is enabled
        if not pwndbg.config.llm_enabled:
            print("LLM integration is disabled. Enabling it now...")
            pwndbg.config.llm_enabled = True
        
        # Get current TUI state
        print("1. Getting current TUI state...")
        state = get_tui_differential_output()
        
        print(f"   - Enabled: {state['enabled']}")
        print(f"   - Sections tracked: {len(state['current_state'])}")
        print(f"   - Recent changes: {len(state['recent_changes'])}")
        
        if not state['current_state']:
            print("   No TUI state captured yet. Make sure debugger is active.")
            return
        
        # Analyze current state
        print("\n2. Analyzing current state...")
        
        # Analyze registers
        register_suggestions = analyze_register_changes(state['current_state'], {})
        if register_suggestions:
            print("   Register Analysis:")
            for suggestion in register_suggestions:
                print(f"     - {suggestion}")
        
        # Analyze stack
        stack_suggestions = analyze_stack_changes(state['current_state'])
        if stack_suggestions:
            print("   Stack Analysis:")
            for suggestion in stack_suggestions:
                print(f"     - {suggestion}")
        
        # Execute some analysis commands
        print("\n3. Executing analysis commands...")
        
        analysis_commands = [
            ("info registers", "Get current register values"),
            ("telescope $rsp 10", "Examine stack content"),
            ("vmmap", "Check memory mappings"),
        ]
        
        for cmd, description in analysis_commands:
            print(f"   Executing: {cmd} ({description})")
            try:
                result = execute_llm_command(cmd, {"purpose": "automated_analysis"})
                if result["success"]:
                    print(f"     ✓ Success - {len(result['output'].splitlines())} lines of output")
                else:
                    print(f"     ✗ Failed - {result.get('error', 'Unknown error')}")
            except Exception as e:
                print(f"     ✗ Exception - {e}")
        
        # Show recent command history
        print("\n4. Recent command history:")
        for i, change in enumerate(state['recent_changes'][-3:]):
            timestamp = change.get('timestamp', 0)
            section = change.get('section', 'unknown')
            lines_count = len(change.get('lines', []))
            print(f"   {i+1}. {section}: {lines_count} lines at {time.ctime(timestamp)}")
        
        print("\n5. Demo complete!")
        print("   You can now use the LLM integration commands:")
        print("     - llm-tui-diff: Get TUI differential output")
        print("     - llm-execute: Execute commands through LLM interface")
        print("     - llm-status: Check integration status")
        
    except ImportError:
        print("LLM hooks not available. Make sure pwndbg is properly configured.")
    except Exception as e:
        print(f"Demo failed with error: {e}")
        import traceback
        traceback.print_exc()


def callback_demo():
    """
    Demonstrate the callback system for real-time TUI change monitoring.
    """
    print("Setting up real-time TUI change monitoring...")
    
    change_count = [0]  # Use list for closure
    
    def monitor_callback(diff_entry):
        """Callback function that gets called on TUI changes."""
        change_count[0] += 1
        section = diff_entry.get('section', 'unknown')
        lines_changed = diff_entry.get('diff', {}).get('changed_count', 0)
        
        print(f"[Monitor] Change #{change_count[0]}: {section} ({lines_changed} lines changed)")
        
        # Simple analysis
        if lines_changed > 5:
            print(f"[Monitor] Significant change in {section} - consider investigation")
    
    try:
        from pwndbg.gdblib.llm_hooks import tui_capture
        
        # Register our callback
        tui_capture.register_callback(monitor_callback)
        print("Callback registered. TUI changes will be monitored in real-time.")
        print("Use 'llm-demo-stop-monitor' to stop monitoring.")
        
        # Store callback reference globally so we can unregister it later
        pwndbg.llm_demo_callback = monitor_callback
        
    except ImportError:
        print("LLM hooks not available for callback demo.")


def stop_monitor_demo():
    """Stop the real-time monitoring callback."""
    try:
        from pwndbg.gdblib.llm_hooks import tui_capture
        
        if hasattr(pwndbg, 'llm_demo_callback'):
            tui_capture.unregister_callback(pwndbg.llm_demo_callback)
            delattr(pwndbg, 'llm_demo_callback')
            print("Real-time monitoring stopped.")
        else:
            print("No monitoring callback was active.")
            
    except ImportError:
        print("LLM hooks not available.")


# Register pwndbg commands for the demo
@pwndbg.commands.Command(
    argparse.ArgumentParser(description="Run LLM integration demonstration"),
    category=CommandCategory.INTEGRATIONS
)
def llm_demo():
    """Run a demonstration of LLM integration features."""
    automated_analysis_demo()


@pwndbg.commands.Command(
    argparse.ArgumentParser(description="Start real-time TUI change monitoring"),
    category=CommandCategory.INTEGRATIONS
)
def llm_demo_monitor():
    """Start real-time TUI change monitoring demo."""
    callback_demo()


@pwndbg.commands.Command(
    argparse.ArgumentParser(description="Stop real-time TUI change monitoring"),
    category=CommandCategory.INTEGRATIONS
)
def llm_demo_stop_monitor():
    """Stop real-time TUI change monitoring demo."""
    stop_monitor_demo()


if __name__ == "__main__":
    print("This script should be sourced in pwndbg, not run directly.")
    print("Usage: (pwndbg) source examples/llm_integration_demo.py")
else:
    print("LLM Integration Demo loaded. Use 'llm-demo' to start.")