"""
Unit tests for LLM integration module.
"""

import json
import pytest
from unittest.mock import Mock, patch, MagicMock

# Mock pwndbg modules to avoid import issues in testing
import sys
sys.modules['pwndbg'] = Mock()
sys.modules['pwndbg.config'] = Mock()
sys.modules['pwndbg.commands'] = Mock()
sys.modules['pwndbg.dbg'] = Mock()
sys.modules['pwndbg.dbg.EventType'] = Mock()

# Mock the config objects
mock_config = Mock()
mock_config.add_param = Mock()
sys.modules['pwndbg'].config = mock_config

# Mock the dbg objects
mock_dbg = Mock()
mock_dbg.event_handler = Mock(return_value=lambda f: f)  # Return function unchanged
sys.modules['pwndbg'].dbg = mock_dbg

# Mock CommandCategory
from enum import Enum
class MockCommandCategory(str, Enum):
    INTEGRATIONS = "Integrations"

sys.modules['pwndbg.commands'].CommandCategory = MockCommandCategory

# Now we can import our module
import pwndbg.commands.llm_integration as llm_int


class TestLLMIntegration:
    """Test cases for LLM integration functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        # Clear handlers before each test
        llm_int._llm_handlers.clear()
        llm_int._context_history.clear()
    
    def test_handler_registration(self):
        """Test handler registration and unregistration."""
        def test_handler(context):
            pass
        
        # Test registration
        llm_int.register_llm_handler(test_handler)
        assert test_handler in llm_int._llm_handlers
        
        # Test duplicate registration prevention
        llm_int.register_llm_handler(test_handler)
        assert llm_int._llm_handlers.count(test_handler) == 1
        
        # Test unregistration
        llm_int.unregister_llm_handler(test_handler)
        assert test_handler not in llm_int._llm_handlers
    
    def test_context_formatting_json(self):
        """Test JSON context formatting."""
        test_context = {
            "process_info": {"pid": 1234, "alive": True},
            "registers": {"pc": 0x12345678, "sp": 0x87654321}
        }
        
        result = llm_int.format_context_for_llm(test_context, "json")
        
        # Should be valid JSON
        parsed = json.loads(result)
        assert parsed["process_info"]["pid"] == 1234
        assert parsed["registers"]["pc"] == 0x12345678
    
    def test_context_formatting_text(self):
        """Test text context formatting."""
        test_context = {
            "process_info": {"pid": 1234, "alive": True, "arch": "x86_64"},
            "registers": {"pc": 0x12345678, "sp": 0x87654321},
            "code": {"disassembly": ["mov eax, ebx", "push eax"]},
            "stack": {"data": ["0x01: value1", "0x02: value2"]}
        }
        
        result = llm_int.format_context_for_llm(test_context, "text")
        
        assert "=== Process Information ===" in result
        assert "PID: 1234" in result
        assert "Status: Alive" in result
        assert "Architecture: x86_64" in result
        assert "=== Registers ===" in result
        assert "pc  : 0x0000000012345678" in result
        assert "=== Disassembly ===" in result
        assert "mov eax, ebx" in result
        assert "=== Stack ===" in result
        assert "0x01: value1" in result
    
    def test_context_formatting_structured(self):
        """Test structured context formatting."""
        test_context = {
            "process_info": {"pid": 1234, "alive": True},
            "registers": {"pc": 0x12345678},
            "code": {"disassembly": ["mov eax, ebx"]}
        }
        
        result = llm_int.format_context_for_llm(test_context, "structured")
        
        assert "[PROCESS_INFO]" in result
        assert "pid: 1234" in result
        assert "[REGISTERS]" in result
        assert "pc: 305419896" in result  # 0x12345678 in decimal
        assert "[CODE]" in result
    
    def test_handler_notification(self):
        """Test handler notification system."""
        received_contexts = []
        
        def test_handler(context):
            received_contexts.append(context)
        
        llm_int.register_llm_handler(test_handler)
        
        # Mock get_comprehensive_context to return test data
        test_context = {"test": "data"}
        with patch.object(llm_int, 'get_comprehensive_context', return_value=test_context):
            llm_int.notify_llm_handlers("test_event")
        
        assert len(received_contexts) == 1
        assert received_contexts[0]["test"] == "data"
        assert received_contexts[0]["event_type"] == "test_event"
    
    def test_handler_notification_with_error(self):
        """Test handler notification with error handling."""
        def error_handler(context):
            raise Exception("Test error")
        
        def good_handler(context):
            self.good_handler_called = True
        
        self.good_handler_called = False
        
        llm_int.register_llm_handler(error_handler)
        llm_int.register_llm_handler(good_handler)
        
        test_context = {"test": "data"}
        with patch.object(llm_int, 'get_comprehensive_context', return_value=test_context):
            # This should not raise an exception
            llm_int.notify_llm_handlers("test_event")
        
        # Good handler should still be called despite error in first handler
        assert self.good_handler_called
    
    def test_context_history(self):
        """Test context history functionality."""
        test_contexts = [{"test": f"data{i}"} for i in range(3)]
        
        with patch.object(llm_int, 'get_comprehensive_context') as mock_get_context:
            for i, context in enumerate(test_contexts):
                mock_get_context.return_value = context
                llm_int.notify_llm_handlers(f"event_{i}")
        
        assert len(llm_int._context_history) == 3
        assert llm_int._context_history[0]["test"] == "data0"
        assert llm_int._context_history[2]["test"] == "data2"
    
    def test_context_history_limit(self):
        """Test context history size limit."""
        original_limit = llm_int._max_history_size
        llm_int._max_history_size = 2  # Set small limit for testing
        
        try:
            test_contexts = [{"test": f"data{i}"} for i in range(5)]
            
            with patch.object(llm_int, 'get_comprehensive_context') as mock_get_context:
                for i, context in enumerate(test_contexts):
                    mock_get_context.return_value = context
                    llm_int.notify_llm_handlers(f"event_{i}")
            
            # Should only keep the last 2 entries
            assert len(llm_int._context_history) == 2
            assert llm_int._context_history[0]["test"] == "data3"
            assert llm_int._context_history[1]["test"] == "data4"
        finally:
            llm_int._max_history_size = original_limit
    
    def test_basic_debug_info(self):
        """Test basic debug info gathering."""
        # Mock the debugger interface
        mock_process = Mock()
        mock_process.pid.return_value = 1234
        mock_process.alive.return_value = True
        mock_process.is_remote.return_value = False
        mock_process.arch.return_value = "x86_64"
        
        mock_frame = Mock()
        mock_frame.pc.return_value = 0x12345678
        mock_frame.sp.return_value = 0x87654321
        
        with patch.object(llm_int.pwndbg.dbg, 'selected_inferior', return_value=mock_process), \
             patch.object(llm_int.pwndbg.dbg, 'selected_frame', return_value=mock_frame):
            
            info = llm_int.get_basic_debug_info()
            
            assert info["available"] is True
            assert info["process"]["pid"] == 1234
            assert info["process"]["alive"] is True
            assert info["process"]["arch"] == "x86_64"
            assert info["registers"]["pc"] == "0x12345678"
            assert info["registers"]["sp"] == "0x87654321"
    
    def test_basic_debug_info_no_inferior(self):
        """Test basic debug info with no inferior process."""
        with patch.object(llm_int.pwndbg.dbg, 'selected_inferior', return_value=None):
            info = llm_int.get_basic_debug_info()
            
            assert "status" in info
            assert "No inferior process available" in info["status"]
            assert info["available"] is False
    
    def test_safe_command_execution(self):
        """Test safe command execution interface."""
        # Test safe command
        result = llm_int.execute_pwndbg_command("vmmap")
        assert result["command"] == "vmmap"
        assert "success" in result
        assert "output" in result
        
        # Test unsafe command
        result = llm_int.execute_pwndbg_command("quit")
        assert result["success"] is False
        assert "not in the safe command list" in result["error"]
    
    def test_api_interface(self):
        """Test LLM interaction API."""
        api = llm_int.get_llm_interaction_api()
        
        expected_functions = [
            "get_context", "get_basic_info", "execute_command",
            "register_handler", "unregister_handler", "format_context",
            "notify_handlers", "capture_tui"
        ]
        
        for func_name in expected_functions:
            assert func_name in api
            assert callable(api[func_name])
    
    def test_example_handler(self):
        """Test the example handler functionality."""
        # Test that example handler can be called without errors
        test_context = {
            "event_type": "test",
            "registers": {"pc": 0x12345678},
            "code": {"disassembly": ["mov eax, ebx", "push eax"]}
        }
        
        # This should not raise an exception
        llm_int.example_llm_handler(test_context)


if __name__ == "__main__":
    pytest.main([__file__])