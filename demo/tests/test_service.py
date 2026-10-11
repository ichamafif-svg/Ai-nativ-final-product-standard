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
