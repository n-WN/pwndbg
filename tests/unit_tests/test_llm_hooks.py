"""
Unit tests for LLM hooks functionality.
"""

import unittest
from unittest.mock import Mock, patch
import threading
import time
import json


class TestTUIStateCapture(unittest.TestCase):
    """Test the TUIStateCapture class."""
    
    def setUp(self):
        # Mock pwndbg imports to avoid dependency issues in tests
        self.pwndbg_mock = Mock()
        self.config_mock = Mock()
        self.config_mock.llm_enabled = True
        self.config_mock.llm_capture_interval = 0.1
        self.config_mock.llm_diff_threshold = 1
        self.config_mock.llm_max_history = 10
        
        self.pwndbg_mock.config = self.config_mock
        self.pwndbg_mock.aglib.regs.pc = 0x1000
        self.pwndbg_mock.aglib.regs.sp = 0x7fff0000
        self.pwndbg_mock.aglib.regs.bp = 0x7fff0008
        self.pwndbg_mock.dbg.selected_inferior.return_value.alive.return_value = True
        
        # Mock the modules to avoid import errors
        modules_to_mock = [
            'pwndbg',
            'pwndbg.config',
            'pwndbg.aglib',
            'pwndbg.aglib.regs',
            'pwndbg.dbg',
            'pwndbg.gdblib.events',
        ]
        
        self.patchers = []
        for module in modules_to_mock:
            patcher = patch.dict('sys.modules', {module: self.pwndbg_mock})
            patcher.start()
            self.patchers.append(patcher)
        
        # Import after mocking
        from pwndbg.gdblib.llm_hooks import TUIStateCapture
        self.capture = TUIStateCapture()
    
    def tearDown(self):
        for patcher in self.patchers:
            patcher.stop()
    
    def test_capture_section_basic(self):
        """Test basic section capture functionality."""
        lines = ["line 1", "line 2", "line 3"]
        self.capture.capture_section("test_section", lines)
        
        current_state = self.capture.get_current_state()
        self.assertIn("test_section", current_state)
        self.assertEqual(current_state["test_section"], lines)
    
    def test_capture_section_diff_threshold(self):
        """Test that diff threshold prevents unnecessary captures."""
        # Set high threshold
        self.config_mock.llm_diff_threshold = 10
        
        lines1 = ["line 1", "line 2"]
        lines2 = ["line 1", "line 3"]  # Only 1 line different
        
        self.capture.capture_section("test_section", lines1)
        initial_history_len = len(self.capture.history)
        
        # This should not create a new history entry due to threshold
        self.capture.capture_section("test_section", lines2)
        self.assertEqual(len(self.capture.history), initial_history_len)
    
    def test_capture_section_rate_limiting(self):
        """Test rate limiting functionality."""
        # Set longer interval
        self.config_mock.llm_capture_interval = 1.0
        
        lines1 = ["line 1"]
        lines2 = ["line 2"]
        
        self.capture.capture_section("test_section", lines1)
        initial_history_len = len(self.capture.history)
        
        # Immediate second capture should be rate limited
        self.capture.capture_section("test_section", lines2)
        self.assertEqual(len(self.capture.history), initial_history_len)
    
    def test_callback_registration(self):
        """Test callback registration and execution."""
        callback_called = threading.Event()
        received_data = []
        
        def test_callback(data):
            received_data.append(data)
            callback_called.set()
        
        self.capture.register_callback(test_callback)
        lines = ["callback test line"]
        
        self.capture.capture_section("test_section", lines)
        
        # Wait for callback
        self.assertTrue(callback_called.wait(timeout=1.0))
        self.assertTrue(len(received_data) > 0)
        self.assertEqual(received_data[0]["section"], "test_section")
    
    def test_callback_unregistration(self):
        """Test callback unregistration."""
        callback_called = threading.Event()
        
        def test_callback(data):
            callback_called.set()
        
        self.capture.register_callback(test_callback)
        self.capture.unregister_callback(test_callback)
        
        lines = ["test line"]
        self.capture.capture_section("test_section", lines)
        
        # Callback should not be called
        self.assertFalse(callback_called.wait(timeout=0.5))
    
    def test_history_limit(self):
        """Test that history is limited to max_history entries."""
        self.config_mock.llm_max_history = 3
        self.config_mock.llm_capture_interval = 0.01  # Very short interval
        
        # Add more entries than the limit
        for i in range(5):
            lines = [f"line {i}"]
            self.capture.capture_section(f"section_{i}", lines)
            time.sleep(0.02)  # Wait for rate limiting
        
        # Should only have max_history entries
        self.assertLessEqual(len(self.capture.history), 3)
    
    def test_diff_calculation(self):
        """Test diff calculation between line sets."""
        old_lines = ["line 1", "line 2", "line 3"]
        new_lines = ["line 1", "line 2 modified", "line 4"]
        
        score = self.capture._calculate_diff_score(old_lines, new_lines)
        self.assertEqual(score, 2)  # 2 lines are different
        
        # Test with different lengths
        old_lines = ["line 1", "line 2"]
        new_lines = ["line 1", "line 2", "line 3"]
        
        score = self.capture._calculate_diff_score(old_lines, new_lines)
        self.assertEqual(score, 3)  # Max of the two lengths
    
    def test_disabled_capture(self):
        """Test that capture is disabled when llm_enabled is False."""
        self.config_mock.llm_enabled = False
        
        lines = ["test line"]
        self.capture.capture_section("test_section", lines)
        
        current_state = self.capture.get_current_state()
        self.assertEqual(len(current_state), 0)


class TestLLMCommandInterface(unittest.TestCase):
    """Test the LLMCommandInterface class."""
    
    def setUp(self):
        # Mock gdb
        self.gdb_mock = Mock()
        self.gdb_mock.execute.return_value = "command output"
        
        modules_to_mock = ['gdb']
        self.patchers = []
        for module in modules_to_mock:
            patcher = patch.dict('sys.modules', {module: self.gdb_mock})
            patcher.start()
            self.patchers.append(patcher)
        
        from pwndbg.gdblib.llm_hooks import LLMCommandInterface
        self.interface = LLMCommandInterface()
    
    def tearDown(self):
        for patcher in self.patchers:
            patcher.stop()
    
    def test_execute_command_success(self):
        """Test successful command execution."""
        result = self.interface.execute_command("info registers")
        
        self.assertTrue(result["success"])
        self.assertEqual(result["command"], "info registers")
        self.assertEqual(result["output"], "command output")
        self.assertIn("timestamp", result)
    
    def test_execute_command_failure(self):
        """Test command execution failure handling."""
        self.gdb_mock.execute.side_effect = Exception("GDB error")
        
        result = self.interface.execute_command("invalid command")
        
        self.assertFalse(result["success"])
        self.assertEqual(result["command"], "invalid command")
        self.assertEqual(result["error"], "GDB error")
    
    def test_command_history(self):
        """Test command history tracking."""
        self.interface.execute_command("command 1")
        self.interface.execute_command("command 2")
        
        history = self.interface.get_command_history()
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0]["command"], "command 1")
        self.assertEqual(history[1]["command"], "command 2")
    
    def test_command_history_limit(self):
        """Test that command history is limited."""
        # Execute more commands than the limit (100)
        for i in range(105):
            self.interface.execute_command(f"command {i}")
        
        history = self.interface.get_command_history(count=200)
        self.assertLessEqual(len(history), 100)


class TestLLMIntegrationFunctions(unittest.TestCase):
    """Test the integration functions."""
    
    def setUp(self):
        # Mock all dependencies
        self.pwndbg_mock = Mock()
        self.config_mock = Mock()
        self.config_mock.llm_enabled = True
        self.pwndbg_mock.config = self.config_mock
        
        modules_to_mock = [
            'pwndbg',
            'pwndbg.config',
            'pwndbg.gdblib.events',
            'pwndbg.dbg',
            'gdb',
            'time'
        ]
        
        self.patchers = []
        for module in modules_to_mock:
            if module == 'time':
                patcher = patch(module)
                mock_time = patcher.start()
                mock_time.time.return_value = 1234567890.0
            else:
                patcher = patch.dict('sys.modules', {module: self.pwndbg_mock})
                patcher.start()
            self.patchers.append(patcher)
    
    def tearDown(self):
        for patcher in self.patchers:
            patcher.stop()
    
    def test_get_tui_differential_output(self):
        """Test getting TUI differential output."""
        from pwndbg.gdblib.llm_hooks import get_tui_differential_output
        
        result = get_tui_differential_output()
        
        self.assertIn("current_state", result)
        self.assertIn("recent_changes", result)
        self.assertIn("command_history", result)
        self.assertIn("timestamp", result)
        self.assertIn("enabled", result)
    
    def test_execute_llm_command(self):
        """Test LLM command execution."""
        from pwndbg.gdblib.llm_hooks import execute_llm_command
        
        with patch('gdb.execute', return_value="test output"):
            result = execute_llm_command("test command")
            
            self.assertTrue(result["success"])
            self.assertEqual(result["command"], "test command")
            self.assertEqual(result["output"], "test output")


if __name__ == '__main__':
    unittest.main()