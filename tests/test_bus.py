import asyncio
import logging

import fakeredis
import pytest
from redis.exceptions import ResponseError

from kube_tower import bus as bus_module
from kube_tower.bus import Bus, connect
from kube_tower.config import Settings


@pytest.fixture
async def bus():
    bus = Bus(fakeredis.FakeAsyncRedis(), "kt-test:")
    yield bus
    await bus.close()


async def test_keys_start_with_the_prefix(bus):
    assert bus.key("tasks", "worker") == "kt-test:tasks:worker"


async def test_a_message_goes_to_one_consumer_and_is_deleted_once_done(bus):
    await bus.ensure_group("tasks:worker", "workers")
    await bus.ensure_group("tasks:worker", "workers")  # kept when it exists
    sent = await bus.send("tasks:worker", b"collect c1", kind="collect")
    first = await bus.receive("tasks:worker", "workers", "pod-a", block=0.05)
    assert [(m.id, m.data, m.fields) for m in first] == [(sent, b"collect c1", {"kind": "collect"})]
    assert await bus.receive("tasks:worker", "workers", "pod-b", block=0.05) == []  # nothing left for another pod
    [pending] = await bus.pending("tasks:worker", "workers")
    assert (pending.id, pending.consumer, pending.deliveries) == (sent, "pod-a", 1)
    await bus.done("tasks:worker", "workers", sent)
    await bus.done("tasks:worker", "workers")  # nothing to acknowledge
    assert await bus.pending("tasks:worker", "workers") == []
    assert await bus.length("tasks:worker") == 0


async def test_the_group_is_created_again_when_valkey_lost_it(bus, caplog):
    caplog.set_level(logging.INFO)
    await bus.ensure_group("results", "controller")
    await bus.send("results", b"lost")
    await bus.redis.xgroup_destroy(bus.key("results"), "controller")  # e.g. Valkey restarted, the group lost
    assert await bus.pending("results", "controller") == []
    # The messages still in the stream are read by the new group
    assert [m.data for m in await bus.receive("results", "controller", "ctl", block=0.05)] == [b"lost"]
    assert "created again" in caplog.text


async def test_other_errors_are_raised(bus, monkeypatch):
    await bus.redis.set(bus.key("results"), "not a stream")
    with pytest.raises(ResponseError, match="WRONGTYPE"):
        await bus.ensure_group("results", "controller")

    async def fail(*args, **kwargs):
        raise ResponseError("ERR out of memory")

    monkeypatch.setattr(bus.redis, "xreadgroup", fail)
    monkeypatch.setattr(bus.redis, "xpending_range", fail)
    with pytest.raises(ResponseError, match="out of memory"):
        await bus.receive("results", "controller", "ctl", block=0.05)
    with pytest.raises(ResponseError, match="out of memory"):
        await bus.pending("results", "controller")


async def test_a_pending_message_is_given_to_another_consumer(bus):
    await bus.ensure_group("tasks:trivy", "trivy")
    sent = await bus.send("tasks:trivy", b"scan", kind="scan-vulnerabilities", attempt="1")
    await bus.receive("tasks:trivy", "trivy", "pod-dead", block=0.05)
    new_id = await bus.requeue("tasks:trivy", "trivy", sent, attempt="2")
    assert new_id and new_id != sent
    assert await bus.pending("tasks:trivy", "trivy") == []
    [again] = await bus.receive("tasks:trivy", "trivy", "pod-alive", block=0.05)
    assert (again.id, again.data, again.fields) == (new_id, b"scan", {"kind": "scan-vulnerabilities", "attempt": "2"})


async def test_requeue_of_a_message_gone_meanwhile(bus):
    await bus.ensure_group("tasks:worker", "workers")
    sent = await bus.send("tasks:worker", b"t")
    await bus.receive("tasks:worker", "workers", "pod-a", block=0.05)
    await bus.redis.xdel(bus.key("tasks:worker"), sent)
    assert await bus.requeue("tasks:worker", "workers", sent) is None
    assert await bus.pending("tasks:worker", "workers") == []


async def test_reset_empties_a_stream_and_keeps_its_group(bus):
    await bus.ensure_group("tasks:worker", "workers")
    await bus.send("tasks:worker", b"old")
    await bus.reset("tasks:worker", "workers")
    assert await bus.length("tasks:worker") == 0
    await bus.send("tasks:worker", b"new")
    assert [m.data for m in await bus.receive("tasks:worker", "workers", "pod-a", block=0.05)] == [b"new"]


async def test_capped_streams_read_by_everyone(bus):
    ids = [await bus.send("logs", f"line {i}".encode(), maxlen=1000, source="pod-a") for i in range(5)]
    assert [m.data for m in await bus.read("logs")] == [b"line 0", b"line 1", b"line 2", b"line 3", b"line 4"]
    assert [m.data for m in await bus.read("logs", after=ids[2])] == [b"line 3", b"line 4"]
    assert [m.data for m in await bus.read("logs", count=2)] == [b"line 0", b"line 1"]
    last = await bus.last("logs", 2)
    assert [(m.data, m.fields) for m in last] == [(b"line 3", {"source": "pod-a"}), (b"line 4", {"source": "pod-a"})]


async def test_the_state_and_its_revision(bus):
    assert await bus.state_revision() == 0
    assert await bus.state() == (0, None)
    assert await bus.publish_state(b"state 1") == 1
    assert await bus.publish_state(b"state 2") == 2
    assert await bus.state_revision() == 2
    assert await bus.state() == (2, b"state 2")


async def test_a_request_gets_its_reply(bus):
    await bus.ensure_group("actions", "controller")

    async def controller():
        while not (messages := await bus.receive("actions", "controller", "ctl", block=0.05)):
            pass
        [message] = messages
        assert (message.data, message.fields["name"]) == (b"{}", "trigger")
        await bus.reply(message, b"started")
        await bus.done("actions", "controller", message.id)

    task = asyncio.create_task(controller())
    assert await bus.request("actions", b"{}", timeout=2, name="trigger") == b"started"
    await task
    assert await bus.redis.ttl((await bus.redis.keys(bus.key("reply", "*")) or [b""])[0]) in (-2, *range(1, 61))


async def test_a_request_without_reply_in_time(bus):
    assert await bus.request("actions", b"{}", timeout=0.1, name="trigger") is None


async def test_reply_to_a_message_that_expects_none(bus):
    await bus.ensure_group("actions", "controller")
    await bus.send("actions", b"{}")
    [message] = await bus.receive("actions", "controller", "ctl", block=0.05)
    await bus.reply(message, b"ignored")
    assert await bus.redis.keys(bus.key("reply", "*")) == []


async def test_the_processes_expire_unless_written_again(bus):
    assert await bus.processes() == {}
    await bus.set_process("kube-tower-ui-1", b"ui", ttl=60)
    await bus.set_process("kube-tower-worker-1", b"worker", ttl=0.05)
    await asyncio.sleep(0.1)
    assert await bus.processes() == {"kube-tower-ui-1": b"ui"}
    await bus.remove_process("kube-tower-ui-1")
    assert await bus.processes() == {}


def test_connect_uses_the_url_the_password_and_the_prefix(monkeypatch):
    settings = Settings()
    settings.redis.url = "redis://valkey:6379/0"
    settings.redis.key_prefix = "my-release"
    monkeypatch.setenv(settings.redis.password_env, "s3cret")
    bus = connect(settings)
    kwargs = bus.redis.connection_pool.connection_kwargs
    assert (kwargs["host"], kwargs["password"], kwargs["socket_timeout"]) == ("valkey", "s3cret", bus_module.SOCKET_TIMEOUT)
    assert bus.key("state") == "my-release:state"


def test_connect_without_password(monkeypatch):
    settings = Settings()
    settings.redis.url = "redis://valkey:6379/0"
    monkeypatch.delenv(settings.redis.password_env, raising=False)
    assert connect(settings).redis.connection_pool.connection_kwargs.get("password") is None
