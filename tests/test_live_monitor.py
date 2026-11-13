"""Medición en vivo del agente (2.1.0): qué mide cada 2 segundos, cuándo empieza y cuándo se detiene."""
import io
import json
import re
import threading
import urllib.error

from agent import live_monitor as live
from agent import wifisense_agent as agent

SERVER = "https://wifisense.example.com"
KEY = "wsa_" + "k" * 43


class Response(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class NoContent(Response):
    status = 204


class FakeTime:
    def __init__(self):
        self.now, self.slept = 0.0, []

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


def fake_sampler(counters, clock, internet=42.0, gateway=3.0, link=None, open_port=53):
    """Un sampler con contadores, reloj y respuestas de red falsos (``counters`` se consume en orden)."""
    readings = iter(counters)

    def probe(host, port, timeout):
        if host == "1.1.1.1":
            return internet
        return gateway if port == open_port else None

    return live.LiveSampler(lambda: next(readings), lambda: link if link is not None else {"signalPercent": 71,
                            "rxRateMbps": 144.4, "txRateMbps": 72.2}, probe, "192.168.43.1", ("1.1.1.1", 443),
                            clock=clock)


# ----------------------------------------------------------------------------------------- lo que pide el servidor

def test_the_server_can_only_ask_for_numbers_within_limits():
    assert live.live_task_of({"live": True, "sampleSeconds": 2, "maxSeconds": 600}) == {"sampleSeconds": 2,
                                                                                         "maxSeconds": 600}
    assert live.live_task_of({"live": True, "sampleSeconds": 0, "maxSeconds": 99_999}) == {"sampleSeconds": 1,
                                                                                            "maxSeconds": 1800}
    assert live.live_task_of({"live": True}) == {"sampleSeconds": 2, "maxSeconds": 600}
    # cualquier otra cosa se ignora: el agente nunca ejecuta órdenes del servidor
    assert live.live_task_of({"live": True, "sampleSeconds": "2; del *", "command": "shutdown"}) == {
        "sampleSeconds": 2, "maxSeconds": 600}
    assert live.live_task_of({"live": True, "sampleSeconds": True}) == {"sampleSeconds": 2, "maxSeconds": 600}
    assert live.live_task_of({"live": False}) is None
    assert live.live_task_of({"live": "yes"}) is None
    assert live.live_task_of(None) is None


# ------------------------------------------------------------------------------------------------- las muestras

def test_the_traffic_of_this_moment_comes_from_the_counters():
    before = {"bytes.in": 1_000_000, "bytes.out": 200_000}
    after = {"bytes.in": 2_000_000, "bytes.out": 450_000}
    assert live.throughput(before, after, 2.0) == (4_000_000, 1_000_000)  # 1 MB en 2 s = 4 Mbps
    assert live.throughput(after, before, 2.0) == (None, None)  # contador que retrocede: no es confiable
    assert live.throughput(before, after, 0) == (None, None)
    assert live.throughput({}, after, 2.0) == (None, None)


def test_the_router_port_is_the_first_that_answers_and_none_means_unknown():
    assert live.pick_gateway_port("192.168.43.1", lambda h, p, t: 0.4 if p == 80 else None) == 80
    assert live.pick_gateway_port("192.168.43.1", lambda h, p, t: 0.4) == 53  # DNS primero (zona Wi-Fi del celular)
    assert live.pick_gateway_port("192.168.43.1", lambda h, p, t: None) is None
    assert live.pick_gateway_port(None, lambda h, p, t: 0.4) is None


def test_a_sample_has_the_traffic_both_latencies_and_the_wifi_link():
    fake = FakeTime()
    sampler = fake_sampler([{"bytes.in": 0, "bytes.out": 0}, {"bytes.in": 2_500_000, "bytes.out": 500_000}],
                           fake.clock)
    sampler.start()
    fake.now = 2.0

    sample = sampler.sample()

    assert sample == {"intervalMs": 2000, "downloadBps": 10_000_000, "uploadBps": 2_000_000, "internetMs": 42.0,
                      "gatewayMs": 3.0, "signalPercent": 71, "rxRateMbps": 144.4, "txRateMbps": 72.2}


def test_silence_from_internet_is_a_lost_sample_and_a_router_without_ports_is_unknown():
    fake = FakeTime()
    sampler = fake_sampler([{"bytes.in": 0, "bytes.out": 0}, {"bytes.in": 0, "bytes.out": 0}], fake.clock,
                           internet=None, open_port=None)
    sampler.start()
    fake.now = 2.0

    sample = sampler.sample()

    assert sample["internetLost"] is True and "internetMs" not in sample
    assert "gatewayMs" not in sample and "gatewayLost" not in sample  # no se cuenta como pérdida


def test_a_router_that_stops_answering_is_lost_and_a_broken_wifi_reading_does_not_stop_the_sample():
    fake = FakeTime()

    def link():
        raise OSError("netsh no respondió")

    answers = iter([0.5, None])  # al empezar contesta en el puerto 53; en la muestra ya no
    sampler = live.LiveSampler(lambda: {"bytes.in": 0, "bytes.out": 0}, link,
                               lambda h, p, t: 30.0 if h == "1.1.1.1" else next(answers), "192.168.1.1",
                               ("1.1.1.1", 443), clock=fake.clock)
    sampler.start()
    fake.now = 2.0

    sample = sampler.sample()

    assert sample["gatewayLost"] is True and sample["internetMs"] == 30.0
    assert "signalPercent" not in sample


def test_a_sample_never_carries_an_address():
    fake = FakeTime()
    sampler = fake_sampler([{"bytes.in": 0, "bytes.out": 0}, {"bytes.in": 10, "bytes.out": 10}], fake.clock,
                           link={"signalPercent": 50, "ssid": "Casa", "bssid": "aa:bb:cc:dd:ee:ff"})
    sampler.start()
    fake.now = 2.0

    text = json.dumps(sampler.sample())

    assert not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text)
    assert not re.search(r"([0-9a-f]{2}[:-]){5}[0-9a-f]{2}", text)
    assert "Casa" not in text  # el nombre de la red ya lo conoce el servidor por la clave


# ------------------------------------------------------------------------------------------------- la sesión

def endless_counters():
    value = 0
    while True:
        value += 1000
        yield {"bytes.in": value, "bytes.out": value}


def test_the_session_samples_every_2_seconds_until_nobody_is_watching():
    fake, sent = FakeTime(), []
    sampler = fake_sampler(endless_counters(), fake.clock)

    def send(sample):
        sent.append(fake.now)
        return len(sent) < 4  # el cuarto envío responde que ya nadie mira la página

    assert live.run_session({"sampleSeconds": 2, "maxSeconds": 600}, sampler, send, sleep=fake.sleep,
                            clock=fake.clock) == 4
    assert sent == [2.0, 4.0, 6.0, 8.0]


def test_the_session_ends_after_its_time_even_if_someone_keeps_watching():
    fake = FakeTime()
    sampler = fake_sampler(endless_counters(), fake.clock)

    count = live.run_session({"sampleSeconds": 2, "maxSeconds": 10}, sampler, lambda s: True, sleep=fake.sleep,
                             clock=fake.clock)

    assert count == 5 and fake.now == 10.0


def test_three_failed_deliveries_in_a_row_end_the_session_and_one_success_resets_them():
    fake, results = FakeTime(), iter([True, "fail", "fail", True, "fail", "fail", "fail", True])
    sampler = fake_sampler(endless_counters(), fake.clock)

    def send(sample):
        result = next(results)
        if result == "fail":
            raise agent.SendError("no se pudo conectar con el servidor")
        return result

    assert live.run_session({"sampleSeconds": 2, "maxSeconds": 600}, sampler, send, sleep=fake.sleep,
                            clock=fake.clock) == 2


def test_a_key_the_server_no_longer_knows_ends_the_session_at_once():
    fake, calls = FakeTime(), []
    sampler = fake_sampler(endless_counters(), fake.clock)

    def send(sample):
        calls.append(sample)
        raise live.LiveStopped("401")

    assert live.run_session({"sampleSeconds": 2, "maxSeconds": 600}, sampler, send, sleep=fake.sleep,
                            clock=fake.clock) == 0
    assert len(calls) == 1


def test_a_stop_request_ends_the_session():
    fake, stop = FakeTime(), threading.Event()
    sampler = fake_sampler(endless_counters(), fake.clock)

    def send(sample):
        stop.set()
        return True

    assert live.run_session({"sampleSeconds": 2, "maxSeconds": 600}, sampler, send, sleep=fake.sleep,
                            clock=fake.clock, stop=stop) == 1


def test_describe_sample_is_readable():
    text = live.describe_sample({"downloadBps": 12_500_000, "uploadBps": 1_000_000, "internetLost": True,
                                 "gatewayMs": 4.2, "signalPercent": 64})
    assert text == "bajada 12.50 Mbps · subida 1.00 Mbps · router 4 ms · internet sin respuesta · señal 64 %"


# ------------------------------------------------------------------------------------------------- con el servidor

def test_while_waiting_the_agent_starts_live_when_someone_opens_the_page_and_does_not_ask_again_meanwhile(
        monkeypatch):
    clock, asked, started = [0.0], [], []
    running = {"value": False}

    def opener(request, timeout):
        path = request.full_url.rsplit("/api/agent/", 1)[1]
        asked.append(path)
        if path == "live/next":
            return Response(b'{"live": true, "sampleSeconds": 2, "maxSeconds": 600}')
        return NoContent(b"")

    def start(task, server, key, opener):
        started.append(task)
        running["value"] = True

    monkeypatch.setattr(agent, "start_live", start)
    monkeypatch.setattr(agent, "live_running", lambda: running["value"])
    agent.wait_watching_tasks(120, SERVER, KEY, "sal", {}, sleep=lambda s: clock.__setitem__(0, clock[0] + s),
                              clock=lambda: clock[0], opener=opener)

    assert started == [{"sampleSeconds": 2, "maxSeconds": 600}]
    assert asked.count("live/next") == 1  # mientras mide no vuelve a preguntar
    assert asked.count("scans/next") == 3  # y lo demás sigue igual


def test_a_server_without_live_is_not_asked_again_until_the_next_report(monkeypatch):
    clock, asked = [0.0], []

    def opener(request, timeout):
        path = request.full_url.rsplit("/api/agent/", 1)[1]
        asked.append(path)
        if path == "live/next":
            raise urllib.error.HTTPError(request.full_url, 404, "no", {}, None)
        return NoContent(b"")

    monkeypatch.setattr(agent, "live_running", lambda: False)
    agent.wait_watching_tasks(120, SERVER, KEY, "sal", {}, sleep=lambda s: clock.__setitem__(0, clock[0] + s),
                              clock=lambda: clock[0], opener=opener)

    assert asked.count("live/next") == 1


def test_a_sample_goes_to_the_server_with_the_key_and_the_answer_says_whether_to_go_on():
    requests = []

    def opener(request, timeout):
        requests.append(request)
        return Response(b'{"keepGoing": false}')

    assert agent.send_live({"downloadBps": 5, "internetMs": 30.0}, SERVER, KEY, opener=opener) is False
    request = requests[0]
    assert request.full_url == SERVER + "/api/agent/live/samples" and request.get_method() == "POST"
    assert request.headers["X-agent-key"] == KEY
    assert json.loads(request.data) == {"downloadBps": 5, "internetMs": 30.0}


def test_a_revoked_key_stops_the_live_session():
    def opener(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 401, "no", {}, None)

    try:
        agent.send_live({}, SERVER, KEY, opener=opener)
    except live.LiveStopped:
        pass
    else:
        raise AssertionError("debía detenerse")


def test_start_live_measures_in_another_thread_and_ends_when_nobody_watches():
    fake, posted = FakeTime(), []
    sampler = fake_sampler(endless_counters(), fake.clock)

    def opener(request, timeout):
        posted.append(json.loads(request.data))
        return Response(b'{"keepGoing": false}')

    # el hilo usa el reloj real: con 1 segundo de muestra termina enseguida porque el servidor dice que pare
    thread = agent.start_live({"sampleSeconds": 1, "maxSeconds": 10}, SERVER, KEY, opener=opener, sampler=sampler)
    thread.join(timeout=5)

    assert not thread.is_alive() and len(posted) == 1
    assert not agent.live_running()


def test_the_live_command_measures_here_and_saves_the_samples(tmp_path, monkeypatch, capsys):
    fake = FakeTime()
    monkeypatch.setattr(agent, "live_sampler", lambda: fake_sampler(endless_counters(), fake.clock))
    monkeypatch.setattr(live.time, "sleep", fake.sleep)
    monkeypatch.setattr(live.time, "monotonic", fake.clock)
    output = tmp_path / "vivo.json"

    assert agent.main(["live", "--seconds", "6", "--output", str(output)]) == 0

    saved = json.loads(output.read_text(encoding="utf-8"))
    assert saved["agentVersion"] == "2.1.0" and len(saved["samples"]) == 3
    assert "internet 42 ms" in capsys.readouterr().out
