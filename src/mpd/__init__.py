"""mpd - a static detector for malicious open-source packages.

Nothing in this package ever executes, imports, installs or extracts to disk the code
it analyses. Packages are read as bytes and parsed (``ast`` for Python, pattern
analysis for JavaScript), so a hostile package cannot run anything on the analyst's
machine through this tool.
"""

__version__ = "0.1.0"
