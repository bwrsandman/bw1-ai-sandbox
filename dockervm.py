"""Docker SDK client that talks to the VM's daemon over an existing paramiko connection.

docker-py's own ssh:// support builds its own paramiko client from ~/.ssh/config and the system
known_hosts, so it can't use the sandbox's dedicated key and known_hosts file. Its SSH adapter does
the right thing once connected (each HTTP connection is a channel running `docker system dial-stdio`),
so we reuse the adapter and only replace how it obtains the connection.
"""

from typing import Any

import docker
import paramiko
from docker.constants import DEFAULT_DOCKER_API_VERSION
from docker.transport.sshconn import SSHHTTPAdapter

BASE_URL = "http+docker://ssh"


# HTTP connections (= ssh channels) to the docker daemon. sshd allows 10 channels per connection (MaxSessions) and
# sandbox.Sandbox needs some for exec and sftp, so docker gets a few and waits for a free one beyond that.
POOL_SIZE = 3


class _VMAdapter(SSHHTTPAdapter):
    def __init__(self, client: paramiko.SSHClient):
        self._vm_client = client
        super().__init__("ssh://vm", timeout=60, max_pool_size=POOL_SIZE)

    def get_connection(self, url: str, proxies: Any = None) -> Any:
        # docker-py keys its pools by the full request URL, and each pool keeps its connection (an open ssh channel)
        # idle: one channel per container ever inspected, until sshd refuses new ones and a create succeeds but its
        # start fails. One pool for everything, blocking when all its connections are busy.
        pool = super().get_connection(BASE_URL, proxies)
        pool.block = True
        return pool

    def _create_paramiko_client(self, base_url: str) -> None:
        self.ssh_client = self._vm_client
        self.ssh_params = {}

    def _connect(self) -> None:
        pass  # sandbox.Sandbox owns the connection (and reconnects it)


def docker_over_paramiko(client: paramiko.SSHClient) -> Any:
    """A docker.DockerClient whose requests travel over `client` (the decomp user is in the docker group)."""
    api = docker.APIClient(base_url="tcp://127.0.0.1:1", version=DEFAULT_DOCKER_API_VERSION, timeout=60)
    adapter = _VMAdapter(client)
    api.mount(BASE_URL, adapter)
    api._custom_adapter = adapter
    api.base_url = BASE_URL
    dc = docker.DockerClient.__new__(docker.DockerClient)
    dc.api = api
    return dc
