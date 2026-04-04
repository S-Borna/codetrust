# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""CodeTrust framework integrations.

Provides governance wrappers for popular AI agent frameworks:

- **LangChain**: ``CodeTrustGovernance`` callback handler
- **CrewAI**: ``CodeTrustCrew`` governed crew wrapper
- **OpenAI Agents SDK**: ``governed_agent`` tool wrapper

All framework dependencies are optional.  Install the extras you need::

    pip install codetrust[langchain]
    pip install codetrust[crewai]
    pip install codetrust[openai-agents]
    pip install codetrust[all-frameworks]
"""

from src.integrations.crewai import CodeTrustCrew
from src.integrations.langchain import CodeTrustGovernance
from src.integrations.openai_agents import governed_agent

__all__ = ["CodeTrustCrew", "CodeTrustGovernance", "governed_agent"]
