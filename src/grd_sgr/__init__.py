"""grd-smartgridready — a SmartGridready test bench for energy management systems.

The tool plays the grid side of SmartGridready: it drives an EMS through the
EMS's own EID with the official CommHandler (as a DSO flexibility manager
would), serves the VSE dynamic-tariff API, and judges the declarations. See
README.md and docs/TEST_CATALOGUE.md.
"""

__version__ = "2.0.0"
