import socket

import pytest

from sim.harness import SimClock, environment


def _reachable(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


def pytest_collection_modifyitems(config, items):
    if _reachable(5432) and _reachable(6379):
        return
    skip = pytest.mark.skip(reason="needs Postgres + Redis: docker compose up -d")
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip)


@pytest.fixture
async def env():
    async with environment(airlines=("AC", "SQ"), clock=SimClock()) as e:
        yield e
