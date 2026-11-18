import os, sys

# Let the tests import app.py / detect.py / generate.py from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
