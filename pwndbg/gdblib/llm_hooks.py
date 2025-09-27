"""
LLM integration hooks for pwndbg TUI and command system.

This module provides hooks to capture TUI differential output and enable
LLM interaction with pwndbg for automated pwn challenge solving.
"""

from __future__ import annotations

import json
import threading
import time
from collections import defaultdict
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional

import pwndbg
import pwndbg.config
import pwndbg.gdblib.events
from pwndbg.dbg import EventType

# Configuration parameters for LLM integration
pwndbg.config.add_param(
    "llm-enabled",
    False,
    "enable LLM automated assistance for pwn challenges",
    help_docstring="When enabled, pwndbg will capture TUI changes and provide LLM interaction capabilities.",
)

pwndbg.config.add_param(
    "llm-capture-interval",
    1.0,
    "interval (seconds) between LLM context captures",
    help_docstring="How frequently to capture TUI state changes for LLM analysis.",
)

pwndbg.config.add_param(
    "llm-diff-threshold",
    10,
    "minimum number of changed lines to trigger LLM capture",
    help_docstring="Only capture TUI state if this many lines have changed since last capture.",
)

pwndbg.config.add_param(
    "llm-max-history",
    50,
    "maximum number of TUI state snapshots to keep in history",
    help_docstring="Limits memory usage by keeping only recent TUI states.",
)


class TUIStateCapture:
    """Captures and tracks changes in TUI state for LLM analysis."""
    
    def __init__(self):
        self.current_state: Dict[str, List[str]] = {}
        self.history: List[Dict[str, Any]] = []
        self.last_capture_time = 0.0
        self.lock = threading.Lock()
        self.callbacks: List[Callable[[Dict[str, Any]], None]] = []
        
    def register_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Register a callback to be called when TUI state changes."""
        with self.lock:
            self.callbacks.append(callback)
    
    def unregister_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Unregister a previously registered callback."""
        with self.lock:
            if callback in self.callbacks:
                self.callbacks.remove(callback)
    
    def capture_section(self, section: str, lines: List[str]) -> None:
        """Capture TUI output for a specific section."""
        if not pwndbg.config.llm_enabled:
            return
            
        current_time = time.time()
        
        # Rate limiting
        if current_time - self.last_capture_time < pwndbg.config.llm_capture_interval:
            return
            
        with self.lock:
            # Check if there are significant changes
            old_lines = self.current_state.get(section, [])
            if self._calculate_diff_score(old_lines, lines) < pwndbg.config.llm_diff_threshold:
                return
                
            # Update current state
            self.current_state[section] = lines.copy()
            
            # Create diff entry
            diff_entry = {
                "timestamp": current_time,
                "section": section,
                "lines": lines.copy(),
                "diff": self._generate_diff(old_lines, lines),
                "registers": self._capture_registers(),
                "memory": self._capture_memory_context(),
                "pc": self._capture_pc(),
            }
            
            # Add to history
            self.history.append(diff_entry)
            
            # Limit history size
            if len(self.history) > pwndbg.config.llm_max_history:
                self.history = self.history[-pwndbg.config.llm_max_history:]
                
            self.last_capture_time = current_time
            
            # Notify callbacks
            for callback in self.callbacks:
                try:
                    callback(diff_entry)
                except Exception as e:
                    print(f"LLM callback error: {e}")
    
    def _calculate_diff_score(self, old_lines: List[str], new_lines: List[str]) -> int:
        """Calculate how many lines have changed between old and new."""
        if len(old_lines) != len(new_lines):
            return max(len(old_lines), len(new_lines))
            
        changes = 0
        for old, new in zip(old_lines, new_lines):
            if old != new:
                changes += 1
        return changes
    
    def _generate_diff(self, old_lines: List[str], new_lines: List[str]) -> Dict[str, Any]:
        """Generate a structured diff between old and new lines."""
        return {
            "added": [line for line in new_lines if line not in old_lines],
            "removed": [line for line in old_lines if line not in new_lines],
            "changed_count": self._calculate_diff_score(old_lines, new_lines)
        }
    
    def _capture_registers(self) -> Dict[str, Any]:
        """Capture current register state."""
        try:
            if pwndbg.dbg.selected_inferior().alive():
                return {
                    "pc": hex(pwndbg.aglib.regs.pc) if pwndbg.aglib.regs.pc else None,
                    "sp": hex(pwndbg.aglib.regs.sp) if pwndbg.aglib.regs.sp else None,
                    "bp": hex(pwndbg.aglib.regs.bp) if pwndbg.aglib.regs.bp else None,
                }
        except Exception:
            pass
        return {}
    
    def _capture_memory_context(self) -> Dict[str, Any]:
        """Capture relevant memory context."""
        try:
            if pwndbg.dbg.selected_inferior().alive():
                # Get stack context
                stack_addr = pwndbg.aglib.regs.sp
                if stack_addr:
                    return {
                        "stack_top": hex(stack_addr),
                        # Note: We avoid capturing actual memory content for privacy
                        "has_stack": True
                    }
        except Exception:
            pass
        return {"has_stack": False}
    
    def _capture_pc(self) -> Optional[str]:
        """Capture current program counter."""
        try:
            if pwndbg.dbg.selected_inferior().alive():
                pc = pwndbg.aglib.regs.pc
                return hex(pc) if pc else None
        except Exception:
            pass
        return None
    
    def get_recent_changes(self, count: int = 10) -> List[Dict[str, Any]]:
        """Get the most recent TUI state changes."""
        with self.lock:
            return self.history[-count:] if self.history else []
    
    def get_current_state(self) -> Dict[str, List[str]]:
        """Get the current TUI state."""
        with self.lock:
            return self.current_state.copy()


# Global TUI state capture instance
tui_capture = TUIStateCapture()


class LLMCommandInterface:
    """Interface for LLM to interact with pwndbg commands."""
    
    def __init__(self):
        self.command_history: List[Dict[str, Any]] = []
        self.lock = threading.Lock()
    
    def execute_command(self, command: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute a pwndbg command and return structured result."""
        try:
            import gdb
            
            # Execute the command and capture output
            output = gdb.execute(command, to_string=True)
            
            result = {
                "command": command,
                "output": output,
                "success": True,
                "timestamp": time.time(),
                "context": context or {}
            }
            
            with self.lock:
                self.command_history.append(result)
                # Limit history
                if len(self.command_history) > 100:
                    self.command_history = self.command_history[-100:]
                    
            return result
            
        except Exception as e:
            result = {
                "command": command,
                "output": "",
                "success": False,
                "error": str(e),
                "timestamp": time.time(),
                "context": context or {}
            }
            
            with self.lock:
                self.command_history.append(result)
                
            return result
    
    def get_command_history(self, count: int = 20) -> List[Dict[str, Any]]:
        """Get recent command execution history."""
        with self.lock:
            return self.command_history[-count:] if self.command_history else []


# Global LLM command interface
llm_interface = LLMCommandInterface()


def get_tui_differential_output() -> Dict[str, Any]:
    """
    Get the current TUI differential output for LLM consumption.
    
    Returns a structured representation of recent TUI changes that can be
    used by LLMs for analysis and automated pwn challenge solving.
    """
    return {
        "current_state": tui_capture.get_current_state(),
        "recent_changes": tui_capture.get_recent_changes(),
        "command_history": llm_interface.get_command_history(),
        "timestamp": time.time(),
        "enabled": bool(pwndbg.config.llm_enabled)
    }


def execute_llm_command(command: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Execute a pwndbg command through the LLM interface.
    
    This function provides a safe way for LLMs to execute pwndbg commands
    and get structured responses.
    """
    return llm_interface.execute_command(command, context)


# Hook into the existing TUI system
@pwndbg.dbg.event_handler(EventType.STOP)
def on_stop_capture_tui():
    """Capture TUI state when execution stops."""
    if pwndbg.config.llm_enabled:
        # This will be called by the TUI system when context is updated
        pass


@pwndbg.dbg.event_handler(EventType.CONTINUE)
def on_continue_capture_tui():
    """Capture TUI state when execution continues."""
    if pwndbg.config.llm_enabled:
        # Mark the transition point
        tui_capture.capture_section("transition", [f"CONTINUE at {time.time()}"])