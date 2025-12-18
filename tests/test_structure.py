import sys
import os
import unittest

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class TestProjectStructure(unittest.TestCase):
    
    def test_imports(self):
        """Test that all modules can be imported."""
        try:
            from src.state import ReverseEngineeringState
            from src.agents.orchestrator import build_graph
            from src.agents.normalizer import normalize_code_node
            from src.tools.ghidra import analyze_binary_structure
        except ImportError as e:
            self.fail(f"Failed to import modules: {e}")

    def test_graph_build(self):
        """Test that the graph compiles without errors."""
        try:
            from src.agents.orchestrator import build_graph
            app = build_graph()
            self.assertIsNotNone(app)
        except Exception as e:
            self.fail(f"Failed to build graph: {e}")

if __name__ == '__main__':
    unittest.main()
