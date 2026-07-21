# Notification Module

WebSocket endpoint that streams `change_log` events (advisory/SBOM ingestion and deletion) in real time.

## Protocol

- **Endpoint**: `GET /api/v3/notifications?after=<uuid>`
- **Auth**: Bearer token via `Authorization` header or `?token=<jwt>` query parameter (requires `read.sbom` and/or `read.advisory` — events are filtered by permission)
- **`after`**: last known event ID; omit for live-only, provide to replay missed events first
- **Messages** (server to client, JSON text frames):

```json
{"id":"019577ab-...","entity_type":"sbom","entity_id":"550e8400-...","operation":"ingested"}
```

Track the `id` field and pass it as `?after=` on reconnect for gap-free delivery.

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
    let lastId;

    function connect() {
      const log = document.getElementById('log');
      const token = document.getElementById('token').value;
      let url = 'ws://localhost:8080/api/v3/notifications';
      const params = [];
      if (lastId) params.push('after=' + lastId);
      if (token) params.push('token=' + encodeURIComponent(token));
      if (params.length) url += '?' + params.join('&');

      const ws = new WebSocket(url);
      ws.onopen = () => log.textContent += '--- connected ---\n';
      ws.onmessage = (e) => {
        const event = JSON.parse(e.data);
        lastId = event.id;
        log.textContent += JSON.stringify(event) + '\n';
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
