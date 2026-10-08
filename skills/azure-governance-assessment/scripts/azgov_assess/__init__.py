"""azgov_assess - Azure governance assessment engine for the AzGovViz Copilot CLI plugin.

Pipeline: AzGovViz (PowerShell) -> Azure Resource Graph inventory -> Azure/review-checklists
evaluation -> deterministic governance analysis -> self-contained HTML assessment report.

Only the Python standard library is used so the engine runs anywhere Python 3.9+ is available.
"""

__version__ = "1.1.0"
TOOL_NAME = "azgovviz-assessment"
