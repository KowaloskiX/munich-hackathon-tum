from app.mockgen import FAKE_NODES


def test_mock_fleet_matches_two_router_demo() -> None:
    assert FAKE_NODES == ["esp-01", "esp-02"]
