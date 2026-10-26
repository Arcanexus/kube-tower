"""Controller election (ADR 0002): one active controller, the other replicas wait as standbys.

The replicas share a Kubernetes Lease. The holder renews it every few seconds; another replica takes it once
it expired (the holder stopped or lost the API server). A controller that cannot renew its Lease in time
stops: Kubernetes restarts it as a standby, so two controllers never scan, nor hand out tasks, together.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import socket
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

from kubernetes import client
from kubernetes.client.rest import ApiException

log = logging.getLogger(__name__)

DURATION = 15  # seconds a Lease stays valid without being renewed
RENEW = 5  # seconds between two renewals (or two tries of a standby)


def _now() -> datetime:
    return datetime.now(UTC)


class LeaderElection:
    def __init__(
        self,
        name: str,
        namespace: str,
        api: client.CoordinationV1Api,
        identity: str | None = None,
        duration: int = DURATION,
        renew: float = RENEW,
    ):
        self.name, self.namespace, self.api = name, namespace, api
        self.identity = identity or socket.gethostname()
        self.duration, self.renew = duration, renew
        self.leader = False
        self._renewed: datetime | None = None  # last successful renewal, while leader
        self.holder: str | None = None  # of the Lease, as last read

    def try_acquire(self) -> bool:
        """Take or renew the Lease. Whether this process holds it (blocking: run in a thread)."""
        now = _now()
        try:
            lease = self.api.read_namespaced_lease(self.name, self.namespace)
        except ApiException as exc:
            if exc.status != 404:
                raise
            body = client.V1Lease(
                metadata=client.V1ObjectMeta(name=self.name, namespace=self.namespace),
                spec=self._spec(now, acquired=now, transitions=0),
            )
            try:
                self.api.create_namespaced_lease(self.namespace, body)
            except ApiException as exc:
                if exc.status == 409:  # created by another replica meanwhile
                    return False
                raise
            self.holder = self.identity
            return True
        spec = lease.spec or client.V1LeaseSpec()
        holder = self.holder = spec.holder_identity
        if holder and holder != self.identity and not self._expired(spec, now):
            return False
        transitions = spec.lease_transitions or 0
        if holder == self.identity:
            lease.spec = self._spec(now, acquired=spec.acquire_time or now, transitions=transitions)
        else:
            lease.spec = self._spec(now, acquired=now, transitions=transitions + 1)
        try:
            # The resourceVersion read above makes it fail if another replica changed the Lease meanwhile.
            self.api.replace_namespaced_lease(self.name, self.namespace, lease)
        except ApiException as exc:
            if exc.status == 409:
                return False
            raise
        self.holder = self.identity
        return True

    def _spec(self, now: datetime, acquired: datetime, transitions: int) -> client.V1LeaseSpec:
        return client.V1LeaseSpec(
            holder_identity=self.identity,
            lease_duration_seconds=self.duration,
            acquire_time=acquired,
            renew_time=now,
            lease_transitions=transitions,
        )

    def _expired(self, spec: client.V1LeaseSpec, now: datetime) -> bool:
        renewed = spec.renew_time or spec.acquire_time
        if renewed is None:
            return True
        if renewed.tzinfo is None:
            renewed = renewed.replace(tzinfo=UTC)
        return now > renewed + timedelta(seconds=spec.lease_duration_seconds or self.duration)

    async def run(self, on_leader: Callable[[], Awaitable[None]]) -> None:
        """Wait for the Lease, then run `on_leader` while renewing it. Stops the process when it is lost."""
        log.info("waiting for the controller Lease %s/%s (standby until then)", self.namespace, self.name)
        while not await self._attempt():
            await asyncio.sleep(self.renew)
        self.leader = True
        log.info("this process is now the active controller (Lease %s/%s)", self.namespace, self.name)
        work = asyncio.create_task(on_leader())
        try:
            while True:
                await asyncio.sleep(self.renew)
                if await self._attempt():
                    continue
                # The API server did not answer: still ours for a while (stopped before another replica may take it).
                taken = self.holder not in (None, self.identity)
                margin = timedelta(seconds=self.duration - self.renew)
                if not taken and self._renewed is not None and _now() - self._renewed < margin:
                    continue
                self.leader = False
                log.critical("the controller Lease %s/%s is lost: stopping (restarted as a standby)", self.namespace, self.name)
                os.kill(os.getpid(), signal.SIGTERM)
                return
        finally:
            work.cancel()

    async def _attempt(self) -> bool:
        try:
            held = await asyncio.to_thread(self.try_acquire)
        except Exception as exc:  # noqa: BLE001 - the API server may be unreachable for a while
            log.warning("cannot read or renew the controller Lease %s/%s: %s", self.namespace, self.name, exc)
            return False
        if held:
            self._renewed = _now()
        return held
