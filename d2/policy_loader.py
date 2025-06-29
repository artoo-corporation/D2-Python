# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

from abc import ABC, abstractmethod
from typing import Dict, Any


class PolicyLoader(ABC):
    """Abstract base class for all policy loaders."""
    
    @abstractmethod
    async def load_policy(self) -> Dict[str, Any]:
        """Load the policy bundle."""
        pass

    @abstractmethod
    def start(self):
        """Start any background tasks, like listeners or file watchers."""
        pass

    @abstractmethod
    async def shutdown(self):
        """Cleanly shut down any background tasks."""
        pass

    @abstractmethod
    def mode(self) -> str:
        """Return the current mode, e.g., 'cloud' or 'file'."""
        pass
