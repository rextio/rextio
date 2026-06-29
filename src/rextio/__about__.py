"""Package version, isolated from ``__init__`` side effects.

setuptools reads ``[tool.setuptools.dynamic] version = {attr = "rextio.__about__.__version__"}``
by parsing this module's AST, so keeping it to a single literal assignment avoids
importing the full package (and its runtime warnings) at build time.
"""

__version__ = "0.1.0a1"
