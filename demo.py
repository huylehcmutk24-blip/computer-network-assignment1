"""Run with: python demo.py. Twenty clients use real sockets in one Python process."""

import asyncio
import json
import secrets
import tempfile
from pathlib import Path
from time import perf_counter

from client import ClientApp, UICommand
from config import Settings
from files import compute_sha256
from protocol import MessageType
from security import generate_key, hash_password
from server import ServerApp

CLIENT_COUNT = 20
WAIT_SECONDS = 15


class DropOneChunkClient(ClientApp):
    """Simulate a lost file chunk on the first sender only."""

    dropped_id = None
    retry_sent = False

    async def send_datagram(self, packet, peer):
        """Bỏ qua lần gửi đầu của FILE_DATA đầu tiên để buộc transport gửi lại."""
        if packet.kind == MessageType.FILE_DATA and self.dropped_id is None:
            self.dropped_id = packet.message_id
            print(f"DROP: client01 skipped FILE_DATA seq={packet.sequence}", flush=True)
            return
        await super().send_datagram(packet, peer)
        if packet.message_id == self.dropped_id and not self.retry_sent:
            self.retry_sent = True
            print(f"RETRY: client01 sent FILE_DATA seq={packet.sequence}", flush=True)


def create_accounts(folder, password):
    """Tạo tài khoản và khóa riêng cho demo trong thư mục tạm."""
    users = []
    keys = {}
    for number in range(1, CLIENT_COUNT + 1):
        username = f"client{number:02}"
        salt = secrets.token_bytes(16)
        key = generate_key().decode("ascii")
        keys[str(number)] = key
        users.append(
            {
                "username": username,
                "key_id": number,
                "password_salt": salt.hex(),
                "password_hash": hash_password(password, salt),
            }
        )
        (folder / f"{username}.keys.json").write_text(
            json.dumps({str(number): key}), encoding="utf-8"
        )
    (folder / "users.json").write_text(json.dumps(users), encoding="utf-8")
    (folder / "server.keys.json").write_text(json.dumps(keys), encoding="utf-8")


async def wait_event(client, event_name):
    """Đọc sự kiện đến khi gặp kết quả cần chờ; lỗi hoặc quá 15 giây thì dừng."""
    async with asyncio.timeout(WAIT_SECONDS):
        while True:
            event = await client.events.get()
            if event.name == "error":
                raise RuntimeError("Client reported an error")
            if event.name == event_name:
                return event.data
            if event.name == "message":
                raise RuntimeError("Unexpected chat message")


async def wait_users(client, count):
    """Chờ danh sách online có đúng số người cần kiểm tra."""
    async with asyncio.timeout(WAIT_SECONDS):
        while len(client.snapshot()["users"]) != count:
            await wait_event(client, "users")


async def demo_chat(clients):
    """Gửi và kiểm tra chat chung trước, rồi chat riêng theo vòng tròn."""
    public_ids = {}
    for client in clients:
        public_ids[client.settings.username] = await client.send_chat("Hello everyone")

    # Mỗi client phải nhận đủ tin chung từ những người còn lại, mỗi người đúng một tin.
    for client in clients:
        expected = public_ids.copy()
        del expected[client.settings.username]
        while expected:
            message = await wait_event(client, "message")
            sender = message["sender"]
            if sender not in expected:
                raise RuntimeError("Duplicate or unexpected public message")
            if message["message_id"] != expected[sender] or message["private"]:
                raise RuntimeError("Public message identity mismatch")
            if message["text"] != "Hello everyone":
                raise RuntimeError("Public message content mismatch")
            del expected[sender]
    print("PASS: Public chat reached all other clients.", flush=True)

    # Client 01 gửi riêng cho 02, ...; client cuối gửi cho client đầu.
    private_ids = {}
    for index, sender in enumerate(clients):
        receiver = clients[(index + 1) % len(clients)]
        private_ids[receiver.settings.username] = await sender.send_chat(
            "Hello privately", receiver.settings.username
        )
    for index, receiver in enumerate(clients):
        message = await wait_event(receiver, "message")
        if (
            message["message_id"] != private_ids[receiver.settings.username]
            or message["sender"] != clients[index - 1].settings.username
            or message["text"] != "Hello privately"
            or not message["private"]
        ):
            raise RuntimeError("Private message content or recipient mismatch")
    print("PASS: Private chat reached the correct clients.", flush=True)


async def demo_files(clients, folder):
    """Gửi lần lượt từng cặp, chờ hoàn tất và kiểm tra hash file nhận."""
    source = folder / "demo.bin"
    source.write_bytes(bytes(range(256)) * 16)
    expected_hash = compute_sha256(source)
    for index in range(0, len(clients), 2):
        sender = clients[index]
        receiver = clients[index + 1]
        transfer = await sender.execute(
            UICommand(
                "send_file",
                {
                    "path": source,
                    "recipient": receiver.settings.username,
                },
            )
        )
        for client in (sender, receiver):
            result = await wait_event(client, "file_finished")
            if not result["ok"] or result["transfer_id"] != transfer["transfer_id"]:
                raise RuntimeError("File transfer failed")
        destination = receiver.settings.receive_dir / source.name
        if compute_sha256(destination) != expected_hash:
            raise RuntimeError("Received file SHA-256 mismatch")
        if isinstance(sender, DropOneChunkClient):
            if not sender.retry_sent:
                raise RuntimeError("Expected the dropped file chunk to be retransmitted")
            print("PASS: client02 file matches SHA-256 after one lost chunk.", flush=True)
    print(f"PASS: {len(clients) // 2} received files match SHA-256.", flush=True)


async def connect_clients(server, folder, password, clients, tasks, client_starts):
    """Mở và đăng nhập từng client; client.run() tiếp tục xử lý mạng ở nền."""
    for number in range(1, CLIENT_COUNT + 1):
        username = f"client{number:02}"
        client_type = DropOneChunkClient if number == 1 else ClientApp
        client = client_type(
            Settings(
                username=username,
                key_id=number,
                tcp_port=server.tcp_address[1],
                udp_port=server.udp_address[1],
                keyring_path=folder / f"{username}.keys.json",
                receive_dir=folder / username,
            )
        )
        clients.append(client)
        client_starts[client] = perf_counter()
        await client.connect()
        tasks.append(asyncio.create_task(client.run()))
        await client.login(username, password)
    for client in clients:
        await wait_users(client, CLIENT_COUNT)
    print(f"PASS: {CLIENT_COUNT} clients logged in and see the online list.", flush=True)


async def demo_logout(clients, close_client):
    """Đăng xuất client cuối rồi kiểm tra danh sách online của các client còn lại."""
    await close_client(clients[-1])
    for client in clients[:-1]:
        await wait_users(client, CLIENT_COUNT - 1)
    # Những tin thừa hoặc lỗi đến muộn cũng phải làm demo thất bại.
    for client in clients:
        while not client.events.empty():
            event = client.events.get_nowait()
            if event.name in {"message", "error"}:
                raise RuntimeError("Unexpected late message or client error")
    print("PASS: Logout updated the online list.", flush=True)


async def main():
    """Chạy demo theo thứ tự và luôn đóng tài nguyên khi kết thúc."""
    demo_start = perf_counter()
    client_starts = {}

    async def close_and_print_time(client):
        """Đóng một client và in thời gian phiên của nó."""
        await client.close()
        start = client_starts.pop(client, None)
        if start is not None:
            print(f"{client.settings.username}: {perf_counter() - start:.3f} s", flush=True)

    with tempfile.TemporaryDirectory(prefix="streamcollab-demo-") as directory:
        folder = Path(directory)
        password = secrets.token_urlsafe(24)
        create_accounts(folder, password)
        server = ServerApp(
            Settings(
                tcp_port=0,
                udp_port=0,
                discovery_port=0,
                users_path=folder / "users.json",
                keyring_path=folder / "server.keys.json",
            )
        )
        clients = []
        tasks = []
        try:
            # 1. Mở server trên cổng còn trống; 2. đăng nhập 20 client.
            await server.start()
            print(f"Server ready. Connecting {CLIENT_COUNT} clients in one process...", flush=True)
            await connect_clients(server, folder, password, clients, tasks, client_starts)

            # 3. Chat chung và riêng; 4. Gửi file theo từng cặp; 5. Đăng xuất một client.
            await demo_chat(clients)
            await demo_files(clients, folder)
            await demo_logout(clients, close_and_print_time)
        finally:
            # 6. Đóng client, đợi các tác vụ dừng, đóng server và xóa thư mục tạm.
            results = await asyncio.gather(
                *(close_and_print_time(c) for c in clients), return_exceptions=True
            )
            for task in tasks:
                task.cancel()
            results += await asyncio.gather(*tasks, return_exceptions=True)
            await server.close()
            for result in results:
                if isinstance(result, Exception):
                    raise result
    print("DEMO PASS. Temporary accounts and files cleaned up.", flush=True)
    print(f"Total demo time: {perf_counter() - demo_start:.3f} s", flush=True)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Demo interrupted.")
        raise SystemExit(130) from None
    except Exception as error:
        print(f"DEMO FAIL: {type(error).__name__}: {error}")
        raise SystemExit(1) from None
