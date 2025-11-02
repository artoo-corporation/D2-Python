# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Helpers for logging plan limit enforcement warnings."""

from __future__ import annotations

import logging
from typing import Optional


PLAN_LIMIT_MESSAGE = (
    "⛔  Plan limit reached.  Upgrade to Essentials ($49/mo) or Pro ($199/mo) at "
    "https://artoo.love/"
)


def emit_plan_limit_warning(
    logger: Optional[logging.Logger] = None,
    *,
    message: Optional[str] = None,
) -> None:
    """Log a standardized plan-limit warning."""

    log = logger or logging.getLogger("d2.plan_limit")
    log.error(message or PLAN_LIMIT_MESSAGE)


__all__ = ["emit_plan_limit_warning", "PLAN_LIMIT_MESSAGE"]

