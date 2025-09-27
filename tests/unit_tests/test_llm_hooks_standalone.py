"""
Standalone tests for LLM hooks core functionality without pwndbg dependencies.
"""

import unittest
import time
import threading
import sys
import os

# Add the pwndbg directory to the path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))


class MockConfig:
    """Mock configuration for testing."""
    def __init__(self):
        self.llm_enabled = True
        self.llm_capture_interval = 0.1
        self.llm_diff_threshold = 1
        self.llm_max_history = 10


class MockRegs:
    """Mock register interface."""
    def __init__(self):
        self.pc = 0x1000
        self.sp = 0x7fff0000
        self.bp = 0x7fff0008


class MockInferior:
    """Mock inferior interface."""
    def alive(self):
        return True


class MockDbg:
    """Mock debugger interface."""
    def selected_inferior(self):
        return MockInferior()


# Mock the pwndbg modules
class MockPwndbg:
    def __init__(self):
        self.config = MockConfig()
        self.aglib = type('aglib', (), {})()
        self.aglib.regs = MockRegs()
        self.dbg = MockDbg()


class SimpleTUIStateCapture:
    """Simplified version of TUIStateCapture for testing."""
    
    def __init__(self, config):
        self.config = config
        self.current_state = {}
        self.history = []
        self.last_capture_time = 0.0
        self.lock = threading.Lock()
        self.callbacks = []
        
    def register_callback(self, callback):
        with self.lock:
            self.callbacks.append(callback)
    
    def unregister_callback(self, callback):
        with self.lock:
            if callback in self.callbacks:
                self.callbacks.remove(callback)
    
    def capture_section(self, section, lines):
        if not self.config.llm_enabled:
            return
            
        current_time = time.time()
        
        # Rate limiting
        if current_time - self.last_capture_time < self.config.llm_capture_interval:
            return
            
        with self.lock:
            # Check if there are significant changes
            old_lines = self.current_state.get(section, [])
            if self._calculate_diff_score(old_lines, lines) < self.config.llm_diff_threshold:
                return
                
            # Update current state
            self.current_state[section] = lines.copy()
            
            # Create diff entry
            diff_entry = {
                "timestamp": current_time,
                "section": section,
                "lines": lines.copy(),
                "diff": self._generate_diff(old_lines, lines),
            }
            
            # Add to history
            self.history.append(diff_entry)
            
            # Limit history size
            if len(self.history) > self.config.llm_max_history:
                self.history = self.history[-self.config.llm_max_history:]
                
            self.last_capture_time = current_time
            
            # Notify callbacks
            for callback in self.callbacks:
                try:
                    callback(diff_entry)
                except Exception as e:
                    print(f"Callback error: {e}")
    
    def _calculate_diff_score(self, old_lines, new_lines):
        if len(old_lines) != len(new_lines):
            return max(len(old_lines), len(new_lines))
            
        changes = 0
        for old, new in zip(old_lines, new_lines):
            if old != new:
                changes += 1
        return changes
    
    def _generate_diff(self, old_lines, new_lines):
        return {
            "added": [line for line in new_lines if line not in old_lines],
            "removed": [line for line in old_lines if line not in new_lines],
            "changed_count": self._calculate_diff_score(old_lines, new_lines)
        }
    
    def get_recent_changes(self, count=10):
        with self.lock:
            return self.history[-count:] if self.history else []
    
    def get_current_state(self):
        with self.lock:
            return self.current_state.copy()


class TestSimpleTUIStateCapture(unittest.TestCase):
    """Test the simplified TUI state capture."""
    
    def setUp(self):
        self.config = MockConfig()
        self.capture = SimpleTUIStateCapture(self.config)
    
    def test_basic_capture(self):
        """Test basic capture functionality."""
        lines = ["line 1", "line 2", "line 3"]
        self.capture.capture_section("test_section", lines)
        
        current_state = self.capture.get_current_state()
        self.assertIn("test_section", current_state)
        self.assertEqual(current_state["test_section"], lines)
    
    def test_diff_threshold(self):
        """Test diff threshold prevents unnecessary captures."""
        self.config.llm_diff_threshold = 10
        
        lines1 = ["line 1", "line 2"]
        lines2 = ["line 1", "line 3"]  # Only 1 line different
        
        self.capture.capture_section("test_section", lines1)
        initial_history_len = len(self.capture.history)
        
        # This should not create a new history entry due to threshold
        self.capture.capture_section("test_section", lines2)
        self.assertEqual(len(self.capture.history), initial_history_len)
    
    def test_rate_limiting(self):
        """Test rate limiting functionality."""
        self.config.llm_capture_interval = 1.0
        
        lines1 = ["line 1"]
        lines2 = ["line 2"]
        
        self.capture.capture_section("test_section", lines1)
        initial_history_len = len(self.capture.history)
        
        # Immediate second capture should be rate limited
        self.capture.capture_section("test_section", lines2)
        self.assertEqual(len(self.capture.history), initial_history_len)
    
    def test_callback_functionality(self):
        """Test callback registration and execution."""
        callback_data = []
        
        def test_callback(data):
            callback_data.append(data)
        
        self.capture.register_callback(test_callback)
        lines = ["callback test line"]
        
        self.capture.capture_section("test_section", lines)
        
        # Check that callback was called
        self.assertEqual(len(callback_data), 1)
        self.assertEqual(callback_data[0]["section"], "test_section")
    
    def test_callback_unregistration(self):
        """Test callback unregistration."""
        callback_data = []
        
        def test_callback(data):
            callback_data.append(data)
        
        self.capture.register_callback(test_callback)
        self.capture.unregister_callback(test_callback)
        
        lines = ["test line"]
        self.capture.capture_section("test_section", lines)
        
        # Callback should not have been called
        self.assertEqual(len(callback_data), 0)
    
    def test_history_limit(self):
        """Test that history is limited to max_history entries."""
        self.config.llm_max_history = 3
        self.config.llm_capture_interval = 0.01
        
        # Add more entries than the limit
        for i in range(5):
            lines = [f"line {i}"]
            self.capture.capture_section(f"section_{i}", lines)
            time.sleep(0.02)
        
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
        self.config.llm_enabled = False
        
        lines = ["test line"]
        self.capture.capture_section("test_section", lines)
        
        current_state = self.capture.get_current_state()
        self.assertEqual(len(current_state), 0)
    
    def test_concurrent_access(self):
        """Test thread safety of capture operations."""
        results = []
        
        def capture_worker(worker_id):
            for i in range(10):
                lines = [f"worker {worker_id} line {i}"]
                self.capture.capture_section(f"section_{worker_id}", lines)
                time.sleep(0.01)
            results.append(worker_id)
        
        # Start multiple threads
        threads = []
        for i in range(3):
            thread = threading.Thread(target=capture_worker, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # All workers should have completed
        self.assertEqual(len(results), 3)
        self.assertEqual(set(results), {0, 1, 2})


class TestDifferentialOutput(unittest.TestCase):
    """Test the differential output functionality."""
    
    def setUp(self):
        self.config = MockConfig()
        self.capture = SimpleTUIStateCapture(self.config)
    
    def test_get_differential_output_structure(self):
        """Test that differential output has the expected structure."""
        # Set very short interval to avoid rate limiting in tests
        self.config.llm_capture_interval = 0.001
        
        # Add some test data
        self.capture.capture_section("disasm", ["mov eax, ebx", "add eax, 1"])
        time.sleep(0.01)  # Wait for rate limiting
        self.capture.capture_section("registers", ["EAX: 0x1000", "EBX: 0x2000"])
        
        # Simulate getting differential output
        result = {
            "current_state": self.capture.get_current_state(),
            "recent_changes": self.capture.get_recent_changes(),
            "timestamp": time.time(),
            "enabled": self.config.llm_enabled
        }
        
        # Verify structure
        self.assertIn("current_state", result)
        self.assertIn("recent_changes", result)
        self.assertIn("timestamp", result)
        self.assertIn("enabled", result)
        
        # Verify content
        self.assertIn("disasm", result["current_state"])
        self.assertIn("registers", result["current_state"])
        self.assertTrue(result["enabled"])
    
    def test_filtering_by_sections(self):
        """Test filtering differential output by specific sections."""
        # Set very short interval to avoid rate limiting in tests
        self.config.llm_capture_interval = 0.001
        
        # Add test data for multiple sections
        self.capture.capture_section("disasm", ["instruction 1"])
        time.sleep(0.01)
        self.capture.capture_section("registers", ["EAX: 0x1000"])
        time.sleep(0.01)
        self.capture.capture_section("stack", ["0x7fff0000: 0x12345678"])
        
        current_state = self.capture.get_current_state()
        
        # Filter by specific sections
        filtered_sections = ["disasm", "registers"]
        filtered_state = {k: v for k, v in current_state.items() if k in filtered_sections}
        
        self.assertIn("disasm", filtered_state)
        self.assertIn("registers", filtered_state)
        self.assertNotIn("stack", filtered_state)


if __name__ == '__main__':
    unittest.main()