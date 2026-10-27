"""The Valkey (or Redis) keys through which the processes of the distributed mode talk (ADR 0003).

Every exchange between roles goes through Valkey, and only the active controller orchestrates: it
queues the tasks, gives a task lost with its process to another one, reads the results and the actions
of the UIs, and publishes the state that the UIs show. The other processes only know the address of
Valkey, never the one of the controller.

- Streams read by a consumer group (`tasks:worker`, `tasks:trivy`, `results`, `actions`): each message
  goes to one consumer of the group, which acknowledges it once handled (the message is then deleted).
  A message read and never acknowledged (its process died) stays pending: see `pending` and `requeue`.
- The state of the controller: `state`, with its revision `state:rev`, so that a UI reads it again only
  when it changed.
- Replies to the actions of the UIs: a short-lived list per request (`reply:<id>`).
- The processes: one key per pod (`pods:<name>`) that expires unless the pod writes it again.
- Capped streams (the log lines of every process).

Every key starts with the prefix of the installation (`redis.keyPrefix`), so that several installations
can share one Valkey. The payloads are bytes: the callers encode them (JSON, often compressed).
"""

from __future__ import annotations

import json
import logging
import os
import uuid
import zlib
from dataclasses import dataclass
from typing import Any

import redis.asyncio as aioredis
from redis.exceptions import ResponseError

from kube_tower.config import Settings

log = logging.getLogger(__name__)

DATA = b"data"  # the field of a stream message holding its payload
REPLY_TTL = 60  # seconds a reply waits for the UI that asked
SOCKET_TIMEOUT = 60.0  # seconds: longer than any blocking read (BLOCK / BLPOP) of the processes


@dataclass(frozen=True)
class Message:
    id: str
    data: bytes
    fields: dict[str, str]  # the other fields of the message (e.g. the task kind, the reply key)
    stream: str = ""  # the stream it was read from, without the prefix


@dataclass(frozen=True)
class Pending:
    """A message read by a consumer and not acknowledged yet."""

    id: str
    consumer: str
    idle: float  # seconds since it was read
    deliveries: int  # times it was read


def _text(value: Any) -> str:
    return value.decode() if isinstance(value, bytes) else str(value)


def _message(entry_id: Any, raw: dict, stream: str = "") -> Message:
    fields = {_text(k): v for k, v in raw.items()}
    data = fields.pop(DATA.decode(), b"")
    data = data if isinstance(data, bytes) else str(data).encode()
    return Message(_text(entry_id), data, {k: _text(v) for k, v in fields.items()}, stream)


def pack(value: Any) -> bytes:
    """A JSON-ready value as a payload: compressed JSON (a result can weigh megabytes). Slow for large values:
    call it in a thread."""
    return zlib.compress(json.dumps(value).encode())


def unpack(data: bytes) -> Any:
    return json.loads(zlib.decompress(data))


class Bus:
    def __init__(self, client: aioredis.Redis, prefix: str = "kube-tower"):
        self.redis = client
        self.prefix = prefix.rstrip(":")

    def key(self, *parts: str) -> str:
        return ":".join((self.prefix, *parts))

    async def close(self) -> None:
        await self.redis.aclose()

    # Streams read by a consumer group

    async def ensure_group(self, stream: str, group: str) -> None:
        """Create the stream and its group, both kept when they exist."""
        try:
            await self.redis.xgroup_create(self.key(stream), group, id="0", mkstream=True)
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    async def send(self, stream: str, data: bytes, maxlen: int | None = None, **fields: str) -> str:
        """Add a message to a stream: its id. `maxlen` keeps about that many messages (the oldest go)."""
        entry = {DATA: data, **fields}
        sent = await self.redis.xadd(self.key(stream), entry, maxlen=maxlen, approximate=True)
        return _text(sent)

    async def receive(self, streams: str | list[str], group: str, consumer: str, block: float, count: int = 1) -> list[Message]:
        """The next messages of the group (same name in each stream) for this consumer, waiting up to `block`
        seconds for one. The groups are created again when Valkey lost them (e.g. restarted without persistence)."""
        names = [streams] if isinstance(streams, str) else streams
        wanted = {self.key(name): ">" for name in names}
        read = lambda: self.redis.xreadgroup(group, consumer, wanted, count=count, block=int(block * 1000))  # noqa: E731
        try:
            answer = await read()
        except ResponseError as exc:
            if "NOGROUP" not in str(exc):
                raise
            log.info("stream %s or its group %s missing in Valkey: created again", ", ".join(wanted), group)
            for name in names:
                await self.ensure_group(name, group)
            answer = await read()
        start = len(self.key(""))
        return [_message(entry_id, raw, _text(key)[start:]) for key, entries in answer or [] for entry_id, raw in entries if raw]

    async def done(self, stream: str, group: str, *ids: str) -> None:
        """Acknowledge messages and delete them: nobody reads them again."""
        if not ids:
            return
        async with self.redis.pipeline(transaction=True) as pipe:
            pipe.xack(self.key(stream), group, *ids)
            pipe.xdel(self.key(stream), *ids)
            await pipe.execute()

    async def pending(self, stream: str, group: str, count: int = 1000) -> list[Pending]:
        """The messages read by the consumers of the group and not acknowledged yet, oldest first."""
        try:
            entries = await self.redis.xpending_range(self.key(stream), group, min="-", max="+", count=count)
        except ResponseError as exc:
            if "NOGROUP" in str(exc):
                return []
            raise
        return [
            Pending(_text(e["message_id"]), _text(e["consumer"]), e["time_since_delivered"] / 1000, e["times_delivered"])
            for e in entries
        ]

    async def requeue(self, stream: str, group: str, entry_id: str, **fields: str) -> str | None:
        """Give a pending message to the next consumer: added again at the end of the stream (with these fields
        changed), the old one acknowledged and deleted. Its new id, None when it is gone meanwhile."""
        found = await self.redis.xrange(self.key(stream), min=entry_id, max=entry_id, count=1)
        if not found:
            await self.done(stream, group, entry_id)
            return None
        message = _message(*found[0])
        new_id = await self.send(stream, message.data, **{**message.fields, **fields})
        await self.done(stream, group, entry_id)
        return new_id

    async def reset(self, stream: str, group: str) -> None:
        """Delete a stream with its messages, and create it again empty with its group."""
        await self.redis.delete(self.key(stream))
        await self.ensure_group(stream, group)

    async def length(self, stream: str) -> int:
        return await self.redis.xlen(self.key(stream))

    # Capped streams read by everyone (e.g. the log lines)

    async def read(self, stream: str, after: str = "0", count: int = 1000) -> list[Message]:
        """The messages after this id, oldest first."""
        entries = await self.redis.xrange(self.key(stream), min=f"({after}" if after != "0" else "-", count=count)
        return [_message(entry_id, raw) for entry_id, raw in entries]

    async def last(self, stream: str, count: int) -> list[Message]:
        """The last `count` messages, oldest first."""
        entries = await self.redis.xrevrange(self.key(stream), count=count)
        return [_message(entry_id, raw) for entry_id, raw in reversed(entries)]

    # The state of the controller

    async def publish_state(self, data: bytes) -> int:
        """Write the state and give it a new revision: the revision."""
        async with self.redis.pipeline(transaction=True) as pipe:
            pipe.set(self.key("state"), data)
            pipe.incr(self.key("state", "rev"))
            _, revision = await pipe.execute()
        return int(revision)

    async def state_revision(self) -> int:
        """The revision of the published state, 0 when none was published."""
        return int(await self.redis.get(self.key("state", "rev")) or 0)

    async def state(self) -> tuple[int, bytes | None]:
        """The published state and its revision."""
        async with self.redis.pipeline(transaction=True) as pipe:
            pipe.get(self.key("state", "rev"))
            pipe.get(self.key("state"))
            revision, data = await pipe.execute()
        return int(revision or 0), data

    # Requests that wait for a reply (the actions of the UIs)

    async def request(self, stream: str, data: bytes, timeout: float, **fields: str) -> bytes | None:
        """Send a message and wait up to `timeout` seconds for its reply: None when none came."""
        reply = self.key("reply", uuid.uuid4().hex)
        await self.send(stream, data, reply=reply, **fields)
        answer = await self.redis.blpop([reply], timeout=timeout)
        return answer[1] if answer else None

    async def reply(self, message: Message, data: bytes) -> None:
        """Answer a request (nothing when the message expects no reply)."""
        if not (reply := message.fields.get("reply")):
            return
        async with self.redis.pipeline(transaction=True) as pipe:
            pipe.rpush(reply, data)
            pipe.expire(reply, REPLY_TTL)
            await pipe.execute()

    # The processes, each with a key that expires unless it is written again

    async def set_process(self, name: str, data: bytes, ttl: float) -> None:
        await self.redis.set(self.key("pods", name), data, px=int(ttl * 1000))

    async def remove_process(self, name: str) -> None:
        await self.redis.delete(self.key("pods", name))

    async def processes(self) -> dict[str, bytes]:
        """The processes whose key has not expired: their data, by name."""
        keys = [k async for k in self.redis.scan_iter(match=self.key("pods", "*"), count=500)]
        if not keys:
            return {}
        start = len(self.key("pods", ""))
        values = await self.redis.mget(keys)
        return {_text(k)[start:]: v for k, v in zip(keys, values, strict=True) if v is not None}


def connect(settings: Settings) -> Bus:
    """The bus of settings.redis (redis.url set). Connects at the first command."""
    options: dict[str, Any] = {
        "socket_timeout": SOCKET_TIMEOUT,
        "socket_connect_timeout": 10,
        "socket_keepalive": True,
        "health_check_interval": 30,
    }
    if password := os.environ.get(settings.redis.password_env):
        options["password"] = password  # a password in the URL wins
    return Bus(aioredis.Redis.from_url(settings.redis.url, **options), settings.redis.key_prefix)
