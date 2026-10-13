from service import Metrics, match


def test_requests_map_to_their_declared_route():
    assert match("GET", "/users/42") == "/users/{id}"
    assert match("GET", "/search?q=x") == "/search"
    assert match("POST", "/users/42") is None


def test_metrics_are_a_cumulative_histogram():
    m = Metrics()
    m.observe("GET", "/health", 200, 0.003)
    m.observe("GET", "/health", 200, 0.2)
    text = m.render()
    assert 'le="0.005"} 1' in text
    assert 'le="+Inf"} 2' in text


def test_every_component_has_its_signals():
    m = Metrics()
    m.record("messaging_process_duration_seconds", {"messaging_destination_name": "orders"}, 0.02)
    m.set("messaging_queue_depth", {"messaging_destination_name": "orders"}, 4)
    text = m.render()
    assert 'messaging_queue_depth{messaging_destination_name="orders"} 4' in text
    assert "process_resident_memory_bytes" in text
