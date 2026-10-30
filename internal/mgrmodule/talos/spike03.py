# Spike for plan 03, step 0 (temporary, removed in step 1): a listener on the
# bridge port that runs mon commands through send_command with a deadline, from
# a request thread. Plain TCP, one JSON request per connection:
#   {"op": "health" | "mgrdump" | "late", "timeout": seconds}
# "late" waits far less than the command needs, reports the timeout, and keeps
# the completion so a later {"op": "late_result"} returns it.
import json
import socket
import threading
import time
from typing import Any, Dict, List

from mgr_module import CommandResult

PORT = 4722


class Spike:
    def __init__(self, module: Any) -> None:
        self.module = module
        self.stop = threading.Event()
        self.late: List[CommandResult] = []
        self.sock = socket.create_server(('0.0.0.0', PORT), reuse_port=True)
        self.sock.settimeout(1.0)
        threading.Thread(target=self.accept, name='spike03-accept', daemon=True).start()

    def accept(self) -> None:
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            threading.Thread(target=self.handle, args=(conn,), name='spike03-req', daemon=True).start()
        self.sock.close()

    def command(self, cmd: Dict[str, Any], timeout: float) -> Dict[str, Any]:
        res = CommandResult('spike03')
        start = time.monotonic()
        self.module.send_command(res, 'mon', '', json.dumps(cmd), 'spike03')
        done = res.ev.wait(timeout)
        took = time.monotonic() - start
        if not done:
            self.late.append(res)
            return {'outcome': 'unknown', 'waited': round(took, 3)}
        return {'outcome': 'done', 'r': res.r, 'out': res.outb, 'outs': res.outs[:500], 'took': round(took, 3),
                'thread': threading.current_thread().name}

    def handle(self, conn: socket.socket) -> None:
        with conn:
            req = json.loads(conn.makefile().readline())
            op, timeout = req['op'], float(req.get('timeout', 10))
            if op == 'health':
                reply = self.command({'prefix': 'health', 'format': 'json'}, timeout)
                reply['out'] = reply.get('out', '')[:300]
            elif op == 'mgrdump':
                reply = self.command({'prefix': 'mgr dump', 'format': 'json'}, timeout)
                if reply['outcome'] == 'done':
                    fresh = json.loads(reply.pop('out'))
                    reply['fresh_active_gid'] = fresh.get('active_gid')
                    reply['fresh_epoch'] = fresh.get('epoch')
                reply['cached_active_gid'] = self.module.get('mgr_map').get('active_gid')
                reply['my_name'] = self.module.get_mgr_id()
            elif op == 'late':
                reply = self.command({'prefix': 'osd tree', 'format': 'json'}, timeout)
            elif op == 'late_result':
                reply = {'late': [{'done': r.ev.is_set(), 'r': r.r, 'bytes': len(r.outb)} for r in self.late]}
            else:
                reply = {'error': 'unknown op'}
            conn.sendall((json.dumps(reply) + '\n').encode())

    def shutdown(self) -> None:
        self.stop.set()
