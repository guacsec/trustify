# Notification Module

WebSocket endpoint that streams `change_log` events (advisory/SBOM additions and deletions) in real time.

## Protocol

- **Endpoint**: `GET /api/v3/notifications?after=<cursor>`
- **Auth**: Bearer token via `Authorization` header or `?token=<jwt>` query parameter. Requires at least one of `read.sbom` or `read.advisory` — events are filtered per-entity by the caller's permissions
- **`after`**: last known cursor; omit on first connect (the server sends a `connection` message with the current cursor), provide on reconnect to replay missed events
- **Heartbeat**: server sends a WebSocket ping every 30 s; clients should respond with pong (most WebSocket libraries do this automatically)

### Connection message

On first connect (no `after` parameter), the server sends a control message:

```json
{"type":"connection","cursor":"019577ab-..."}
```

Save this `cursor` value. If you disconnect before any change events arrive, pass it as `?after=` on reconnect for gap-free delivery.

### Change events

Server → client, JSON text frames:

```json
{"cursor":"019577ab-...","type":"sbom","id":"550e8400-...","operation":"added"}
```

| Field       | Type                        | Description                                              |
|-------------|-----------------------------|----------------------------------------------------------|
| `cursor`    | `string`                    | Monotonically increasing event cursor (pass as `after` on reconnect) |
| `type`      | `"sbom"` \| `"advisory"`    | What kind of entity changed                              |
| `id`        | `string` \| `null`          | The entity that changed (null for bulk operations)       |
| `operation` | `"added"` \| `"deleted"`    | What happened                                            |

Track the `cursor` field from each message and pass it as `?after=` on reconnect for gap-free delivery.

## Example: websocat

```sh
websocat -H "Authorization: Bearer $TOKEN" \
  ws://localhost:8080/api/v3/notifications
```

To resume from a known cursor:

```sh
websocat -H "Authorization: Bearer $TOKEN" \
  "ws://localhost:8080/api/v3/notifications?after=019577ab-0000-7000-8000-000000000000"
```

## Example: HTML

Streams events with reconnect. Enter your access token before connecting.

```html
<!DOCTYPE html>
<html>
<body>
  <input id="token" placeholder="Access token" style="width:300px">
  <button onclick="connect()">Connect</button>
  <pre id="log"></pre>
  <script>
    let lastCursor;

    function connect() {
      const log = document.getElementById('log');
      const token = document.getElementById('token').value;
      let url = 'ws://localhost:8080/api/v3/notifications';
      const params = [];
      if (lastCursor) params.push('after=' + lastCursor);
      if (token) params.push('token=' + encodeURIComponent(token));
      if (params.length) url += '?' + params.join('&');

      const ws = new WebSocket(url);
      ws.onopen = () => log.textContent += '--- connected ---\n';
      ws.onmessage = (e) => {
        const msg = JSON.parse(e.data);
        lastCursor = msg.cursor;
        if (msg.type === 'connection') {
          log.textContent += '--- cursor: ' + msg.cursor + ' ---\n';
          return;
        }
        log.textContent += JSON.stringify(msg) + '\n';
      };
      ws.onclose = () => {
        log.textContent += '--- disconnected, reconnecting in 3s ---\n';
        setTimeout(connect, 3000);
      };
    }
  </script>
</body>
</html>
```
