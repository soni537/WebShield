"""
conftest.py — Root pytest configuration for WebShield.

Ensures the project root is on sys.path so that modules like
`app`, `config`, `models`, `scanner`, etc. can be imported directly
by any test without path-prefix tricks.
"""
import os
import sys

# Add the project root (where this file lives) to sys.path
sys.path.insert(0, os.path.dirname(__file__))
