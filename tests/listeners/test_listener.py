"""Unit-tests for *d2.listener.PollingListener* internal helpers."""
import pytest

from d2.listener import PollingListener


@pytest.mark.anyio
async def test_maybe_update_interval(monkeypatch):
    """The helper clamps & applies server-supplied poll interval values."""
    async def _noop():  # noqa: D401 – dummy callback
        return None

    listener = PollingListener(
        bundle_url="http://example/bundle",
        update_callback=_noop,
        usage_reporter=None,
    )

    # Initial value comes from default (60) unless env overrides
    assert listener._interval >= 5  # pylint: disable=protected-access

    # Case 1: Valid header decreases interval
    listener._maybe_update_interval("30")  # pylint: disable=protected-access
    assert listener._interval == 30  # pylint: disable=protected-access

    # Case 2: Malformed header should *not* change the interval
    listener._maybe_update_interval("not-a-number")  # pylint: disable=protected-access
    assert listener._interval == 30  # unchanged

    # Case 3: Header below MIN_POLLING_INTERVAL_SECONDS clamps to constant
    listener._maybe_update_interval("1")  # pylint: disable=protected-access
    assert listener._interval == 1  # pylint: disable=protected-access 