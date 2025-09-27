#!/usr/bin/env python3
"""
Example script demonstrating LLM integration with pwndbg.

This script shows how to:
1. Register handlers to receive debugging context
2. Process debugging events automatically
3. Send context to external LLM APIs
4. Execute pwndbg commands programmatically

Usage:
1. Load this script in pwndbg: `source examples/llm_integration_example.py`
2. Enable auto-context: `set llm-auto-context on`
3. Start debugging and see LLM integration in action
"""

import json
import sys
import os
from typing import Dict, Any

# Import pwndbg LLM integration
try:
    import pwndbg.commands.llm_integration as llm
    print("✓ LLM integration module loaded successfully")
except ImportError as e:
    print(f"✗ Failed to import LLM integration: {e}")
    sys.exit(1)


class ExampleLLMIntegration:
    """Example class showing LLM integration patterns."""
    
    def __init__(self):
        self.context_count = 0
        self.log_file = "/tmp/pwndbg_llm_integration.log"
        
    def setup(self):
        """Set up the LLM integration."""
        print("Setting up LLM integration example...")
        
        # Register our handlers
        llm.register_llm_handler(self.debug_context_handler)
        llm.register_llm_handler(self.log_context_handler)
        
        print(f"✓ Registered LLM handlers")
        print(f"✓ Context will be logged to: {self.log_file}")
        
    def debug_context_handler(self, context: Dict[str, Any]) -> None:
        """Handler that prints debug information about received context."""
        self.context_count += 1
        event_type = context.get("event_type", "unknown")
        
        print(f"\n[LLM Handler #{self.context_count}] Event: {event_type}")
        
        # Show basic process info
        if "basic_info" in context:
            basic = context["basic_info"]
            if basic.get("available"):
                proc = basic.get("process", {})
                print(f"  Process: PID={proc.get('pid', 'N/A')}, "
                      f"Alive={proc.get('alive', 'N/A')}, "
                      f"Arch={proc.get('arch', 'N/A')}")
                
                regs = basic.get("registers", {})
                if regs:
                    print(f"  Registers: PC={regs.get('pc', 'N/A')}, SP={regs.get('sp', 'N/A')}")
                
                threads = basic.get("threads", {})
                if threads:
                    print(f"  Threads: {threads.get('count', 0)} total, "
                          f"current={threads.get('current_index', 'N/A')}")
            else:
                print(f"  Status: {basic.get('status', 'No process info available')}")
        
        # Show captured TUI sections
        if "tui_sections" in context:
            sections = context["tui_sections"]
            if sections:
                print(f"  TUI Sections captured: {list(sections.keys())}")
            else:
                print("  No TUI sections captured")
    
    def log_context_handler(self, context: Dict[str, Any]) -> None:
        """Handler that logs context to a file."""
        try:
            with open(self.log_file, 'a') as f:
                timestamp = context.get("timestamp", "unknown")
                event_type = context.get("event_type", "unknown")
                f.write(f"\n=== Context Log Entry ===\n")
                f.write(f"Timestamp: {timestamp}\n")
                f.write(f"Event: {event_type}\n")
                f.write(f"Data: {json.dumps(context, indent=2, default=str)}\n")
        except Exception as e:
            print(f"Error logging context: {e}")
    
    def send_to_openai(self, context: Dict[str, Any]) -> None:
        """Example of sending context to OpenAI API."""
        # This is a mock implementation - replace with actual API call
        print("Sending context to OpenAI API...")
        
        # Format context for LLM consumption
        formatted = llm.format_context_for_llm(context, "text")
        
        # Mock API call
        prompt = f"""
        I'm debugging a program and here's the current state:
        
        {formatted}
        
        Can you analyze this debugging context and suggest next steps?
        """
        
        print(f"Prompt length: {len(prompt)} characters")
        print("Note: This is a mock - implement actual API call here")
    
    def demonstrate_command_execution(self):
        """Demonstrate command execution interface."""
        print("\nDemonstrating command execution interface...")
        
        safe_commands = ["vmmap", "info registers", "bt"]
        
        for cmd in safe_commands:
            print(f"\nExecuting: {cmd}")
            result = llm.execute_pwndbg_command(cmd)
            print(f"  Success: {result['success']}")
            if result['success']:
                print(f"  Output: {result['output']}")
            else:
                print(f"  Error: {result['error']}")
    
    def demonstrate_context_formats(self):
        """Demonstrate different context formats."""
        print("\nDemonstrating context formats...")
        
        # Get current context
        context = llm.get_comprehensive_context()
        
        formats = ["json", "text", "structured"]
        for fmt in formats:
            print(f"\n--- {fmt.upper()} Format ---")
            formatted = llm.format_context_for_llm(context, fmt)
            # Show first 200 chars to avoid spam
            preview = formatted[:200] + "..." if len(formatted) > 200 else formatted
            print(preview)
    
    def cleanup(self):
        """Clean up handlers."""
        print("\nCleaning up LLM integration example...")
        llm.unregister_llm_handler(self.debug_context_handler)
        llm.unregister_llm_handler(self.log_context_handler)
        print("✓ Handlers unregistered")


class AutomatedLLMAnalyzer:
    """Example of automated LLM-powered debugging analysis."""
    
    def __init__(self):
        self.analysis_count = 0
        
    def setup(self):
        """Set up automated analysis."""
        llm.register_llm_handler(self.analyze_debugging_state)
        print("✓ Automated LLM analyzer registered")
    
    def analyze_debugging_state(self, context: Dict[str, Any]) -> None:
        """Analyze debugging state and provide insights."""
        event_type = context.get("event_type", "unknown")
        
        # Only analyze on stop events to avoid spam
        if event_type != "stop":
            return
        
        self.analysis_count += 1
        print(f"\n🤖 [LLM Analysis #{self.analysis_count}] Analyzing debugging state...")
        
        # Basic analysis patterns
        analysis = []
        
        if "basic_info" in context:
            basic = context["basic_info"]
            
            # Check if process is alive
            if basic.get("available") and basic.get("process", {}).get("alive"):
                analysis.append("✓ Process is running and available for analysis")
                
                # Check for remote debugging
                if basic.get("process", {}).get("is_remote"):
                    analysis.append("📡 Remote debugging session detected")
                
                # Analyze registers
                regs = basic.get("registers", {})
                if regs:
                    pc = regs.get("pc", "")
                    if pc and "0x" in pc:
                        analysis.append(f"📍 Program counter: {pc}")
                        
                        # Simple heuristic analysis
                        addr = int(pc.replace("0x", ""), 16)
                        if addr < 0x1000:
                            analysis.append("⚠️  Low address - possible null pointer dereference")
                        elif addr > 0x7fffffffffff:
                            analysis.append("🔍 High address - possible stack/heap analysis needed")
            else:
                analysis.append("❌ Process not available or not running")
        
        # Check for captured TUI sections
        if "tui_sections" in context:
            sections = context["tui_sections"]
            if sections:
                analysis.append(f"📋 Captured sections: {', '.join(sections.keys())}")
                
                # Analyze specific sections
                if "disasm" in sections:
                    analysis.append("🔧 Disassembly available for instruction analysis")
                if "stack" in sections:
                    analysis.append("📚 Stack data available for memory analysis")
        
        # Print analysis
        if analysis:
            for item in analysis:
                print(f"   {item}")
        else:
            print("   📝 No specific insights available for current state")
    
    def cleanup(self):
        """Clean up automated analyzer."""
        llm.unregister_llm_handler(self.analyze_debugging_state)
        print("✓ Automated analyzer unregistered")


# Global instances for easy access
example_integration = ExampleLLMIntegration()
automated_analyzer = AutomatedLLMAnalyzer()


def setup_llm_integration_example():
    """Set up the LLM integration example."""
    print("=== Pwndbg LLM Integration Example ===")
    print("This example demonstrates how to integrate LLMs with pwndbg")
    print()
    
    # Set up components
    example_integration.setup()
    automated_analyzer.setup()
    
    print()
    print("🚀 LLM integration example is now active!")
    print()
    print("Try these commands:")
    print("  • Start debugging a program")
    print("  • Use 'llm context' to see current state")
    print("  • Use 'llm test' to test the integration")
    print("  • Enable auto-context: 'set llm-auto-context on'")
    print("  • Set event triggers: 'set llm-hook-events stop,start'")
    print()
    print("Use cleanup_llm_integration_example() to remove handlers")


def cleanup_llm_integration_example():
    """Clean up the LLM integration example."""
    example_integration.cleanup()
    automated_analyzer.cleanup()
    print("✓ LLM integration example cleaned up")


def demonstrate_all_features():
    """Demonstrate all LLM integration features."""
    print("=== LLM Integration Feature Demonstration ===")
    
    # Demonstrate context formats
    example_integration.demonstrate_context_formats()
    
    # Demonstrate command execution
    example_integration.demonstrate_command_execution()
    
    print("\n=== End of Demonstration ===")


# Auto-setup when script is loaded
if __name__ == "__main__":
    setup_llm_integration_example()
else:
    # When imported/sourced in pwndbg
    print("LLM integration example loaded. Use setup_llm_integration_example() to start.")