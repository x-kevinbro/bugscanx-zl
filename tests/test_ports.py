from bugscanx.modules.scanners.port_scanner import ALL_PORTS, COMMON_PORTS, get_ports


def test_all_ports_includes_both_boundaries():
    assert 1 in ALL_PORTS
    assert 65535 in ALL_PORTS
    assert 0 not in ALL_PORTS
    assert 65536 not in ALL_PORTS
    assert len(ALL_PORTS) == 65535


def test_get_ports_selection():
    assert get_ports("Common ports") is COMMON_PORTS
    assert get_ports("All ports (1-65535)") is ALL_PORTS
