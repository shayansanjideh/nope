"""Flowguard: an MCP proxy whose decisions come from a Lean-verified monitor.

Python handles I/O only. Every allow/deny decision is made by the compiled Lean
engine (`flowguard-engine`), which runs `Flowguard.Monitor.step`.
"""

__version__ = "0.1.0"
