"use strict";

// Use same-origin fetch and DOM APIs with the local bridge; no WebSocket.
// Networking, retries, and encryption belong to Python. Render peer content with textContent.
const POLL_INTERVAL_MS = 500;
const MAX_BACKOFF_MS = 8000;
// Wait longer than the bridge default (25 seconds) so it can return a timeout response first.
const REQUEST_TIMEOUT_MS = 30000;
// Allow more time for local uploads up to max_file_bytes (100 MiB).
const UPLOAD_TIMEOUT_MS = 120000;
const MAX_RENDERED_MESSAGES = 300;

const STATE_LABELS = {
  DISCONNECTED: "Not connected to the server",
  CONNECTED: "Connected to the server, not logged in",
  AUTHENTICATED: "Authenticated, establishing UDP connection",
  ONLINE: "Online",
  CLOSING: "Closing connection",
};
const MESSAGE_STATUS_LABELS = {
  pending: "Sending",
  sent: "Server received",
  failed: "Send failed",
};
// Display labels may be translated or reordered without changing the transfer lifecycle.
const TRANSFER_STATUS_LABELS = {
  OFFERED: "Preparing",
  READY: "Preparing",
  TRANSFERRING: "Transferring",
  VERIFYING: "Verifying SHA-256",
  COMPLETED: "Complete, SHA-256 verified",
  FAILED: "Failed",
  CANCELLED: "Cancelled",
};
// Match TransferStatus in files.py. Explicit ranks keep stale events from moving
// an active transfer backwards; terminal results are preserved separately below.
const TRANSFER_STATUS_RANK = {
  OFFERED: 0,
  READY: 1,
  TRANSFERRING: 2,
  VERIFYING: 3,
  COMPLETED: 4,
  FAILED: 5,
  CANCELLED: 6,
};
const TERMINAL_STATUSES = new Set(["COMPLETED", "FAILED", "CANCELLED"]);

const state = {
  csrfToken: "",
  cursor: 0,
  pollingStopped: false,
  pollController: null,
  transfers: new Map(),
  clientState: "DISCONNECTED",
  username: null,
  online: [],
  messages: new Map(),
  failedMessages: new Set(),
  maxChatBytes: 0,
  reconnecting: 0,
  server: null,
};

/** Trả phần tử giao diện có ID được chỉ định. */
const byId = (id) => document.getElementById(id);
/** Chờ khoảng thời gian đã cho mà không chặn trình duyệt. */
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Gửi yêu cầu cùng nguồn, kiểm CSRF và thời hạn, rồi trả JSON hoặc báo lỗi. */
async function requestJson(path, options = {}) {
  const { method = "GET", body, raw, signal, timeoutMs = REQUEST_TIMEOUT_MS } = options;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  if (signal) signal.addEventListener("abort", () => controller.abort(), { once: true });
  const init = { method, headers: {}, signal: controller.signal, cache: "no-store" };
  if (method !== "GET") init.headers["X-CSRF-Token"] = state.csrfToken;
  if (body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  if (raw !== undefined) {
    // The browser supplies the required Content-Length header for Blob/File bodies.
    init.headers["Content-Type"] = "application/octet-stream";
    init.body = raw;
  }
  try {
    const response = await fetch(path, init);
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.error ? `${data.error} (HTTP ${response.status})` : `HTTP ${response.status}`);
    }
    return data;
  } catch (error) {
    if (error.name === "AbortError") throw new Error("The local client did not respond in time");
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

/** Gửi lệnh có tên tới client và trả kết quả JSON. */
function sendCommand(name, args = {}) {
  return requestJson("/api/commands", { method: "POST", body: { name, args } });
}

/** Gắn các thao tác giao diện, khôi phục trạng thái và bắt đầu lấy sự kiện định kỳ. */
async function initialize() {
  byId("login-form").addEventListener("submit", guard(login));
  byId("logout-button").addEventListener("click", guard(logout));
  byId("chat-form").addEventListener("submit", guard(sendChat));
  byId("file-form").addEventListener("submit", guard(sendFile));
  byId("message").addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
      event.preventDefault();
      byId("chat-form").requestSubmit();
    }
  });
  window.addEventListener("pagehide", stopPolling);
  await loadState();
  pollEvents();
}

// Chặn submit mặc định của form và hiển thị lỗi khi thao tác thất bại.
function guard(action) {
  return (event) => {
    if (event) event.preventDefault();
    showError("");
    action().catch((error) => showError(error.message));
  };
}

/** Lấy trạng thái client, mã CSRF và vị trí đọc sự kiện hiện tại. */
async function loadState() {
  const data = await requestJson("/api/state");
  state.csrfToken = data.csrf_token;
  state.cursor = data.cursor;
  applySnapshot(data.snapshot || {});
}

/** Khôi phục kết nối, danh sách người dùng, lịch sử file và giới hạn chat đã thống nhất. */
function applySnapshot(snapshot) {
  applyChatLimit(snapshot.max_chat_bytes);
  applyConnectionDetail(snapshot);
  if (typeof snapshot.username === "string" || snapshot.username === null) {
    state.username = snapshot.username;
  }
  if (typeof snapshot.state === "string") renderState(snapshot.state);
  const users = snapshot.users ?? snapshot.online;
  if (Array.isArray(users)) renderUsers(users);
  if (Array.isArray(snapshot.transfers)) {
    for (const transfer of snapshot.transfers) {
      if (transfer && typeof transfer.transfer_id === "string") renderTransfer(transfer, "snapshot");
    }
  }
}

/** Lưu giới hạn byte hợp lệ từ server và hiển thị cạnh ô nhập tin nhắn. */
function applyChatLimit(limit) {
  if (!Number.isSafeInteger(limit) || limit < 0) return;
  state.maxChatBytes = limit;
  byId("message-limit").textContent = `Up to ${limit} UTF-8 bytes per message.`;
}

/** Kiểm tra thông tin đăng nhập, xóa ô mật khẩu và gửi lệnh đăng nhập. */
async function login() {
  const username = byId("username").value.trim();
  const passwordInput = byId("password");
  const password = passwordInput.value;
  passwordInput.value = "";
  if (!username || !password) throw new Error("Enter your username and password");
  // Set the username before sending: state/users events can precede the login response.
  // This identifies the current user and excludes them from recipient selectors.
  state.username = username;
  try {
    await withBusy(byId("login-button"), () => sendCommand("login", { username, password }));
  } catch (error) {
    if (state.clientState !== "ONLINE") state.username = null;
    throw error;
  }
}

/** Đóng phiên mạng hiện tại và xóa danh sách người dùng online trên giao diện. */
async function logout() {
  await withBusy(byId("logout-button"), () => sendCommand("logout"));
  renderUsers([]);
}

/** Kiểm tra số byte, hiển thị tin đang gửi và cập nhật kết quả gửi cuối cùng. */
async function sendChat() {
  const input = byId("message");
  const text = input.value.trim();
  const recipient = byId("recipient").value;
  if (!text) throw new Error("Message is empty");
  if (new TextEncoder().encode(text).length > state.maxChatBytes) {
    throw new Error(`Message exceeds ${state.maxChatBytes} UTF-8 bytes; split it into smaller messages`);
  }
  const item = renderMessage(
    { message_id: null, sender: state.username, recipient: recipient || null, text },
    "pending",
  );
  try {
    const result = recipient
      ? await sendCommand("private", { recipient, text })
      : await sendCommand("public", { text });
    input.value = "";
    markMessage(item, result.message_id, "sent");
  } catch (error) {
    markMessage(item, null, "failed");
    throw error;
  }
}

/** Tải file đã chọn lên client, gửi mã upload và hiển thị ngay lượt truyền file. */
async function sendFile() {
  const input = byId("file-input");
  const file = input.files[0];
  const recipient = byId("file-recipient").value;
  if (!recipient) throw new Error("No recipients are currently online");
  if (!file) throw new Error("Choose a file to send");
  const result = await withBusy(byId("send-file-button"), async () => {
    // The bridge stages bytes and returns an upload ID; browsers never send local file paths.
    const upload = await requestJson(`/api/uploads?name=${encodeURIComponent(file.name)}`, {
      method: "POST",
      raw: file,
      timeoutMs: UPLOAD_TIMEOUT_MS,
    });
    return sendCommand("send_file", { recipient, upload_id: upload.upload_id });
  });
  input.value = "";
  if (typeof result.transfer_id === "string") {
    // Display outgoing offers immediately; core events merge by transfer_id.
    const offer = { transfer_id: result.transfer_id, filename: file.name, size_bytes: file.size };
    renderTransfer({ ...offer, sender: state.username, recipient }, "file_offer");
  }
}

/** Yêu cầu hủy file và chờ lõi client xác nhận trạng thái cuối cùng. */
async function cancelFile(transferId) {
  await onTransfer(transferId, () => sendCommand("cancel_file", { transfer_id: transferId }));
  // Show CANCELLED only when the core emits file_finished.
  markClosing(transferId);
}

/** Khóa thao tác trên lượt file khi đang xử lý và luôn mở lại các nút sau đó. */
async function onTransfer(transferId, action) {
  const entry = state.transfers.get(transferId);
  if (!entry) throw new Error("This file transfer was not found in the list");
  entry.busy = true;
  drawTransfer(entry);
  try {
    return await action();
  } finally {
    entry.busy = false;
    drawTransfer(entry);
  }
}

/** Đánh dấu lượt file đang chờ xác nhận hủy và vẽ lại các nút điều khiển. */
function markClosing(transferId) {
  const entry = state.transfers.get(transferId);
  if (!entry) return;
  entry.closing = true;
  drawTransfer(entry);
}

/** Lấy sự kiện đúng thứ tự, khôi phục lịch sử hết hạn và tăng thời gian chờ khi mất kết nối. */
async function pollEvents() {
  let delay = POLL_INTERVAL_MS;
  while (!state.pollingStopped) {
    try {
      state.pollController = new AbortController();
      const data = await requestJson(`/api/events?after=${state.cursor}`, {
        signal: state.pollController.signal,
      });
      if (data.reset) {
        // Recover a fresh snapshot when the cursor expires or the bridge restarts.
        await loadState();
        // Only chat history is absent from a snapshot; replaying state would regress it.
        for (const event of data.events) {
          if (event.name === "message") renderEventSafely(event);
        }
      } else {
        for (const event of data.events) {
          if (event.id > state.cursor) renderEventSafely(event);
        }
        state.cursor = data.next_cursor;
      }
      delay = POLL_INTERVAL_MS;
      setLinkProblem("");
    } catch (error) {
      if (state.pollingStopped) break;
      setLinkProblem(`Connection to the local client was lost; retrying in ${Math.ceil(delay / 1000)} seconds`);
      await sleep(delay);
      delay = Math.min(delay * 2, MAX_BACKOFF_MS);
      continue;
    }
    await sleep(delay);
  }
}

/** Dừng vòng lấy sự kiện và hủy yêu cầu đang chờ khi trang đóng. */
function stopPolling() {
  state.pollingStopped = true;
  if (state.pollController) state.pollController.abort();
}

/** Hiển thị một sự kiện và báo lỗi dựng giao diện mà không chặn sự kiện sau. */
function renderEventSafely(event) {
  try {
    renderEvent(event);
  } catch (error) {
    showError(`Could not display event ${event.name}: ${error.message}`);
  }
}

/** Chuyển sự kiện tới hàm hiển thị trạng thái, tin nhắn, người dùng, lỗi hoặc file. */
function renderEvent(event) {
  const data = event.data || {};
  switch (event.name) {
    case "state":
      applyChatLimit(data.max_chat_bytes);
      applyConnectionDetail(data);
      renderState(data.state);
      break;
    case "users":
      renderUsers(data.users || data.online || []);
      break;
    case "message":
      renderMessage(data, null);
      break;
    case "error":
      renderMessageError(data);
      showError(data.message || data.error || "The client reported an unknown error");
      break;
    case "file_offer":
    case "file_progress":
    case "file_finished":
      renderTransfer(data, event.name);
      break;
    default:
      break;
  }
}

/** Ghi nhận số lần đang thử kết nối lại và địa chỉ server mà phiên hiện tại dùng. */
function applyConnectionDetail(data) {
  if (Number.isSafeInteger(data.reconnecting) && data.reconnecting >= 0) {
    state.reconnecting = data.reconnecting;
  }
  if (typeof data.server === "string" || data.server === null) state.server = data.server;
}

/** Cập nhật nhãn kết nối và bật các thao tác phù hợp với trạng thái client. */
function renderState(clientState) {
  if (!(clientState in STATE_LABELS)) return;
  state.clientState = clientState;
  const online = clientState === "ONLINE";
  const reconnecting = !online && state.reconnecting > 0;
  const status = byId("connection-status");
  let label = STATE_LABELS[clientState];
  if (online && state.server) label = `Online, server ${state.server}`;
  if (reconnecting) label = `Connection lost, reconnecting (attempt ${state.reconnecting})`;
  status.textContent = label;
  status.dataset.state = reconnecting ? "RECONNECTING" : clientState;
  byId("current-user").textContent = online && state.username ? state.username : "";
  // Show the login view until ONLINE, then reveal the main application.
  byId("login-view").hidden = online;
  byId("app-view").hidden = !online;
  const signedIn = online || clientState === "AUTHENTICATED";
  byId("login-button").disabled = signedIn;
  byId("username").disabled = signedIn;
  byId("password").disabled = signedIn;
  byId("logout-button").hidden = !signedIn;
  byId("logout-button").disabled = !signedIn;
  byId("send-message-button").disabled = !online;
  byId("file-recipient").disabled = !online;
  byId("file-input").disabled = !online;
  byId("send-file-button").disabled = !online;
}

/** Hiển thị người dùng online không trùng và cập nhật lựa chọn người nhận chat/file. */
function renderUsers(users) {
  const names = [...new Set(
    users.map((user) => (typeof user === "string" ? user : user && user.username)).filter(Boolean),
  )].sort((a, b) => a.localeCompare(b));
  state.online = names;
  const list = byId("user-list");
  list.replaceChildren(...names.map((name) => {
    const item = document.createElement("li");
    item.textContent = name === state.username ? `${name} (you)` : name;
    return item;
  }));
  byId("user-count").textContent = String(names.length);
  const peers = names.filter((name) => name !== state.username);
  fillRecipients(byId("recipient"), peers, "Public chat (everyone)");
  fillRecipients(byId("file-recipient"), peers, null);
}

// Giữ người nhận đã chọn nếu còn online; nếu không, chọn mục đầu tiên.
function fillRecipients(select, peers, publicLabel) {
  const previous = select.value;
  const options = [];
  if (publicLabel) options.push(new Option(publicLabel, ""));
  for (const peer of peers) options.push(new Option(peer, peer));
  select.replaceChildren(...options);
  if (options.some((option) => option.value === previous)) select.value = previous;
}

/** Hiển thị tin nhắn an toàn và loại trùng theo mã tin nhận được. */
function renderMessage(message, status) {
  const id = message.message_id;
  if (id && state.messages.has(id)) return state.messages.get(id);
  const item = document.createElement("li");
  const own = Boolean(state.username) && message.sender === state.username;
  item.className = own ? "message own" : "message";
  const meta = document.createElement("p");
  meta.className = "message-meta";
  const who = document.createElement("span");
  who.className = "message-who";
  who.textContent = describeRoute(message, own);
  const time = document.createElement("time");
  const now = new Date();
  time.dateTime = now.toISOString();
  time.textContent = now.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" });
  meta.append(who, time);
  const text = document.createElement("p");
  text.className = "message-text";
  text.textContent = String(message.text ?? "");
  item.append(meta, text);
  if (status) setMessageStatus(item, status);
  const list = byId("message-list");
  list.append(item);
  if (id) state.messages.set(id, item);
  trimMessages(list);
  item.scrollIntoView({ block: "nearest" });
  return item;
}

/** Trả mô tả người gửi và đích nhận chung hoặc riêng của tin nhắn. */
function describeRoute(message, own) {
  const sender = own ? "You" : message.sender || "Unknown";
  if (message.private === false || !message.recipient || message.recipient === "*") {
    return `${sender} → Public chat`;
  }
  const recipient = message.recipient === state.username ? "you" : message.recipient;
  return `${sender} → ${recipient} (private)`;
}

/** Gắn mã tin cho dòng đang gửi và áp dụng lỗi có thể đến trước phản hồi lệnh. */
function markMessage(item, messageId, status) {
  if (messageId) {
    state.messages.set(messageId, item);
    if (state.failedMessages.delete(messageId)) status = "failed";
  }
  setMessageStatus(item, status);
}

/** Đánh dấu tin lỗi; chỉ lưu mã lỗi khi phản hồi gửi chưa gắn mã vào dòng tin. */
function renderMessageError(error) {
  if (error.scope === "file" || typeof error.message_id !== "string") return;
  const item = state.messages.get(error.message_id);
  if (item) {
    setMessageStatus(item, "failed");
    return;
  }
  state.failedMessages.add(error.message_id);
  while (state.failedMessages.size > MAX_RENDERED_MESSAGES) {
    state.failedMessages.delete(state.failedMessages.values().next().value);
  }
}

/** Cập nhật nhãn trạng thái gửi; không đổi lỗi đã có thành thành công. */
function setMessageStatus(item, status) {
  if (item.dataset.status === "failed") status = "failed";
  item.dataset.status = status;
  let badge = item.querySelector(".message-status");
  if (!badge) {
    badge = textElement("span", "message-status");
    item.append(badge);
  }
  badge.textContent = MESSAGE_STATUS_LABELS[status] || status;
}

/** Xóa các dòng cũ nhất cùng mã tin khi lịch sử chat vượt giới hạn. */
function trimMessages(list) {
  while (list.children.length > MAX_RENDERED_MESSAGES) {
    const oldest = list.firstElementChild;
    for (const [id, item] of state.messages) {
      if (item === oldest) state.messages.delete(id);
    }
    oldest.remove();
  }
}

// Gộp dữ liệu sự kiện vào thẻ file, cập nhật tiến độ và giữ kết quả cuối cùng.
// Ghép theo transfer_id; tiến độ dùng số byte, kết quả dùng status/ok/error.
function renderTransfer(update, eventName) {
  const id = update.transfer_id;
  if (typeof id !== "string" || !id) throw new Error("File event is missing transfer_id");
  let entry = state.transfers.get(id);
  if (!entry) {
    entry = createTransferEntry();
    state.transfers.set(id, entry);
    byId("transfer-list").prepend(entry.item);
  }
  const previous = entry.data;
  entry.data = {
    ...previous,
    ...update,
    transfer_id: id,
    status: nextTransferStatus(previous.status, update, eventName),
    // Retained progress must not move backwards when older updates arrive.
    bytes_transferred: Math.max(Number(previous.bytes_transferred) || 0, Number(update.bytes_transferred) || 0),
  };
  drawTransfer(entry);
}

/** Chỉ cho trạng thái file tiến lên và không để sự kiện cũ thay kết quả cuối. */
function nextTransferStatus(current, update, eventName) {
  let candidate = current || "OFFERED";
  if (Object.hasOwn(TRANSFER_STATUS_RANK, update.status)) {
    candidate = update.status;
  } else if (eventName === "file_finished") {
    candidate = update.ok === false ? "FAILED" : "COMPLETED";
  } else if (eventName === "file_progress") {
    candidate = "TRANSFERRING";
  }
  // Preserve terminal results; active states may only advance through TransferStatus.
  if (TERMINAL_STATUSES.has(current)) return current;
  /** Trả thứ tự của trạng thái trong vòng đời file; trạng thái lạ trả về -1. */
  const rank = (status) => Object.hasOwn(TRANSFER_STATUS_RANK, status) ? TRANSFER_STATUS_RANK[status] : -1;
  return rank(candidate) >= rank(current) ? candidate : current;
}

/** Tạo thẻ file có tiến độ, người gửi/nhận, trạng thái và nút hủy. */
function createTransferEntry() {
  const item = document.createElement("li");
  item.className = "transfer";
  const entry = {
    data: {},
    busy: false,
    closing: false,
    item,
    name: textElement("p", "transfer-name"),
    route: textElement("p", "transfer-route"),
    bar: document.createElement("progress"),
    status: textElement("p", "transfer-status"),
  };
  entry.bar.max = 100;
  entry.cancelButton = actionButton("Cancel", "btn-secondary", () => cancelFile(entry.data.transfer_id));
  const actions = textElement("div", "transfer-actions");
  actions.append(entry.cancelButton);
  item.append(entry.name, entry.route, entry.bar, entry.status, actions);
  return entry;
}

/** Tạo phần tử HTML với tên thẻ và lớp CSS được yêu cầu. */
function textElement(tag, className) {
  const element = document.createElement(tag);
  element.className = className;
  return element;
}

/** Tạo nút chạy thao tác bất đồng bộ, báo lỗi qua hàm guard dùng chung. */
function actionButton(label, className, action) {
  const button = textElement("button", className);
  button.type = "button";
  button.textContent = label;
  button.addEventListener("click", guard(action));
  return button;
}

/** Cập nhật thẻ file và ẩn thao tác khi lượt truyền đã hủy hoặc kết thúc. */
function drawTransfer(entry) {
  const transfer = entry.data;
  const direction = transferDirection(transfer);
  const percent = transferPercent(transfer);
  entry.item.dataset.status = transfer.status;
  entry.name.textContent = [transfer.filename || "Unnamed file", formatBytes(transfer.size_bytes)]
    .filter(Boolean)
    .join(" · ");
  entry.route.textContent = describeTransferRoute(transfer, direction);
  entry.bar.value = percent;
  entry.bar.setAttribute("aria-label", `Progress for ${transfer.filename || "file"}`);
  entry.status.textContent = describeTransferStatus(transfer, direction, percent, entry.closing);
  const finished = TERMINAL_STATUSES.has(transfer.status);
  entry.cancelButton.hidden = finished || entry.closing;
  entry.cancelButton.disabled = entry.busy;
}

/** Xác định chiều gửi hoặc nhận file so với người đang đăng nhập. */
function transferDirection(transfer) {
  if (state.username && transfer.recipient === state.username) return "receive";
  if (state.username && transfer.sender === state.username) return "send";
  return null;
}

/** Tính phần trăm từ số byte; file rỗng chỉ đạt 100% khi đã hoàn tất. */
function transferPercent(transfer) {
  if (transfer.status === "COMPLETED") return 100;
  const size = Number(transfer.size_bytes);
  const bytes = Number(transfer.bytes_transferred);
  return size > 0 && Number.isFinite(bytes) ? Math.min(100, Math.floor(100 * bytes / size)) : 0;
}

/** Trả mô tả người gửi hoặc người nhận theo chiều truyền file. */
function describeTransferRoute(transfer, direction) {
  if (direction === "send") return `Sending to ${transfer.recipient || "unknown recipient"}`;
  if (direction === "receive") return `Receiving from ${transfer.sender || "unknown sender"}`;
  return `${transfer.sender || "?"} → ${transfer.recipient || "?"}`;
}

/** Trả mô tả tiến độ file, lỗi cuối cùng hoặc trạng thái đang chờ hủy. */
function describeTransferStatus(transfer, direction, percent, closing) {
  const status = transfer.status;
  if (closing && !TERMINAL_STATUSES.has(status)) return "Request sent, waiting for client confirmation";
  if (status === "TRANSFERRING") {
    return `${TRANSFER_STATUS_LABELS.TRANSFERRING} ${percent}% (${formatBytes(transfer.bytes_transferred)}/${formatBytes(transfer.size_bytes)})`;
  }
  if (status === "VERIFYING" && direction === "send") return "Waiting for receiver verification";
  const label = TRANSFER_STATUS_LABELS[status] || String(status);
  const reason = transfer.error || transfer.reason;
  return (status === "FAILED" || status === "CANCELLED") && reason ? `${label}: ${reason}` : label;
}

/** Định dạng số byte hợp lệ thành đơn vị dễ đọc theo bội số của 1024. */
function formatBytes(value) {
  const bytes = Number(value);
  if (value === undefined || value === null || !Number.isFinite(bytes) || bytes < 0) return "";
  const units = ["B", "KB", "MB", "GB"];
  let size = bytes;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toLocaleString("en-US", { maximumFractionDigits: unit ? 1 : 0 })} ${units[unit]}`;
}

/** Khóa nút khi chạy thao tác bất đồng bộ rồi khôi phục điều khiển theo trạng thái kết nối. */
async function withBusy(button, action) {
  button.disabled = true;
  try {
    return await action();
  } finally {
    renderState(state.clientState);
  }
}

/** Hiển thị hoặc xóa cảnh báo kết nối tới client cục bộ. */
function setLinkProblem(message) {
  const banner = byId("link-problem");
  banner.textContent = message;
  banner.hidden = !message;
}

/** Hiển thị hoặc xóa thông báo lỗi thao tác bằng nội dung văn bản an toàn. */
function showError(message) {
  const alert = byId("error-message");
  alert.textContent = message;
  alert.hidden = !message;
}

document.addEventListener("DOMContentLoaded", () => {
  initialize().catch((error) => {
    setLinkProblem(`Could not open the interface: ${error.message}. Check that the client is running.`);
  });
});
