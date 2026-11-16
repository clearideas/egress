import socket
import threading
import time
import unittest

from clearideas_egress.nonces import NonceStoreError, RedisNonceStore


class FakeRedis:
    """Minimal RESP server: AUTH, SELECT, PING, SET key value NX PX ms."""

    def __init__(self, password=None):
        self.password = password
        self.data = {}
        self.commands = []
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.clients = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.clients.append(conn)
            threading.Thread(target=self._client, args=(conn,), daemon=True).start()

    def _client(self, conn):
        stream = conn.makefile("rb")
        authed = self.password is None
        try:
            while True:
                header = stream.readline()
                if not header:
                    return
                parts = []
                for _ in range(int(header[1:])):
                    length = int(stream.readline()[1:])
                    parts.append(stream.read(length + 2)[:-2].decode())
                self.commands.append(parts)
                cmd = parts[0].upper()
                if cmd == "AUTH":
                    authed = parts[-1] == self.password
                    conn.sendall(b"+OK\r\n" if authed else b"-WRONGPASS invalid password\r\n")
                elif not authed:
                    conn.sendall(b"-NOAUTH Authentication required.\r\n")
                elif cmd == "PING":
                    conn.sendall(b"+PONG\r\n")
                elif cmd == "SELECT":
                    conn.sendall(b"+OK\r\n")
                elif cmd == "SET":
                    key = parts[1]
                    expires = self.data.get(key)
                    if expires and expires > time.monotonic():
                        conn.sendall(b"$-1\r\n")
                    else:
                        self.data[key] = time.monotonic() + int(parts[5]) / 1000
                        conn.sendall(b"+OK\r\n")
        except OSError:
            return

    def drop_connections(self):
        for conn in self.clients:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def close(self):
        self.drop_connections()
        self.sock.close()


class NonceStoreTests(unittest.TestCase):
    def make(self, url, **kwargs):
        store = RedisNonceStore(url, **kwargs)
        self.addCleanup(store.close)
        return store

    def test_claim_and_replay(self):
        server = FakeRedis()
        try:
            store = self.make(f"redis://127.0.0.1:{server.port}/2")
            self.assertTrue(store.claim("run-a", "nonce-1", 60000))
            self.assertFalse(store.claim("run-a", "nonce-1", 60000))
            self.assertTrue(store.claim("run-b", "nonce-1", 60000))  # scoped per run
            set_commands = [c for c in server.commands if c[0] == "SET"]
            self.assertEqual(set_commands[0][2:], ["1", "NX", "PX", "60000"])
            self.assertIn(["SELECT", "2"], server.commands)
            self.assertTrue(store.ping())
        finally:
            server.close()

    def test_expiry(self):
        server = FakeRedis()
        try:
            store = self.make(f"redis://127.0.0.1:{server.port}")
            self.assertTrue(store.claim("s", "n", 50))
            time.sleep(0.1)
            self.assertTrue(store.claim("s", "n", 50))
        finally:
            server.close()

    def test_authentication(self):
        server = FakeRedis(password="p@ss word")
        try:
            self.assertTrue(self.make(f"redis://:p%40ss%20word@127.0.0.1:{server.port}").claim("s", "n", 1000))
            self.assertTrue(self.make(f"redis://egress:p%40ss%20word@127.0.0.1:{server.port}").claim("s", "m", 1000))
            self.assertIn(["AUTH", "egress", "p@ss word"], server.commands)
            with self.assertRaises(NonceStoreError):
                self.make(f"redis://:wrong@127.0.0.1:{server.port}").claim("s", "x", 1000)
        finally:
            server.close()

    def test_reconnects_after_connection_loss(self):
        server = FakeRedis()
        try:
            store = self.make(f"redis://127.0.0.1:{server.port}")
            self.assertTrue(store.claim("s", "1", 1000))
            server.drop_connections()
            time.sleep(0.05)
            self.assertTrue(store.claim("s", "2", 1000))
        finally:
            server.close()

    def test_unavailable_raises(self):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        with self.assertRaises(NonceStoreError):
            self.make(f"redis://127.0.0.1:{port}", timeout_seconds=0.2).claim("s", "n", 1000)

    def test_url_validation(self):
        for url in ["http://127.0.0.1:6379", "redis://", "redis://h/x"]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                RedisNonceStore(url)


if __name__ == "__main__":
    unittest.main()
