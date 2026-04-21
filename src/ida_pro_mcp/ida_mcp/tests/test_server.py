"""Tests for the top-level stdio proxy server (server.py) and unsafe tool gating."""

import argparse
import contextlib
import os
import sys

from ..framework import test
from ..rpc import MCP_SERVER, MCP_UNSAFE

try:
    from ida_pro_mcp import server
except ImportError:
    _parent = os.path.join(os.path.dirname(__file__), "..", "..")
    sys.path.insert(0, _parent)
    try:
        import server  # type: ignore
    finally:
        sys.path.remove(_parent)


class _FakeHttpResponse:
    status = 200
    reason = "OK"

    def __init__(self, body=b'{"jsonrpc":"2.0","result":{}}'):
        self._body = body

    def read(self):
        return self._body


class _RecordingConnection:
    calls = []

    def __init__(self, host, port, timeout=None):
        self.host = host
        self.port = port
        self.timeout = timeout

    def request(self, method, path, body=None, headers=None):
        self.__class__.calls.append(
            {
                "host": self.host,
                "port": self.port,
                "timeout": self.timeout,
                "method": method,
                "path": path,
                "body": body,
                "headers": headers or {},
            }
        )

    def getresponse(self):
        return _FakeHttpResponse()

    def close(self):
        pass


@contextlib.contextmanager
def _saved_target():
    """Preserve the currently selected IDA target across assertions."""
    old_host = server.IDA_HOST
    old_port = server.IDA_PORT
    old_fallback = server._FALLBACK_SELECTED_TARGET
    old_selected = server._SESSION_SELECTED_TARGETS.copy()
    old_session = getattr(server.mcp._transport_session_id, "data", None)
    old_exts = getattr(server.mcp._enabled_extensions, "data", set())
    try:
        yield
    finally:
        server.IDA_HOST = old_host
        server.IDA_PORT = old_port
        server._FALLBACK_SELECTED_TARGET = old_fallback
        server._SESSION_SELECTED_TARGETS.clear()
        server._SESSION_SELECTED_TARGETS.update(old_selected)
        server.mcp._transport_session_id.data = old_session
        server.mcp._enabled_extensions.data = old_exts


@test()
def test_tools_list_keeps_discovery_and_launch_tools_when_ida_unreachable():
    """tools/list should still expose local discovery/recovery tools when IDA is down."""
    with _saved_target():
        server.IDA_HOST = "127.0.0.1"
        server.IDA_PORT = 1  # unreachable
        req = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        result = server.dispatch_proxy(req)
        assert "result" in result, f"Expected successful tools/list response, got: {result}"
        tool_names = {tool["name"] for tool in result["result"].get("tools", [])}
        assert "select_instance" in tool_names
        assert "select_instance_by_binary" in tool_names
        assert "select_instance_by_idb" in tool_names
        assert "list_instances" in tool_names
        assert "current_instance" in tool_names
        assert "open_file" in tool_names


@test()
def test_server_proxy_to_instance_forwards_session_and_extensions():
    """Top-level proxy requests should preserve MCP session and enabled extensions."""
    with _saved_target():
        original_conn = server.http.client.HTTPConnection
        _RecordingConnection.calls = []
        server.http.client.HTTPConnection = _RecordingConnection
        server.mcp._transport_session_id.data = "http:session-456"
        server.mcp._enabled_extensions.data = {"dbg"}
        try:
            server._proxy_to_instance("127.0.0.1", 13337, b"{}")
            assert len(_RecordingConnection.calls) == 1
            call = _RecordingConnection.calls[0]
            assert call["path"] == "/mcp?ext=dbg"
            assert call["headers"].get("Mcp-Session-Id") == "session-456"
        finally:
            server.http.client.HTTPConnection = original_conn


@test()
def test_resolve_ida_rpc_preserves_ext_query_param():
    """--ida-rpc http://host:port/mcp?ext=dbg should seed enabled extensions."""
    with _saved_target():
        args = argparse.Namespace(ida_rpc="http://10.0.0.1:9999/mcp?ext=dbg")
        server._resolve_ida_rpc(args)
        assert server.IDA_HOST == "10.0.0.1"
        assert server.IDA_PORT == 9999
        exts = getattr(server.mcp._enabled_extensions, "data", set())
        assert "dbg" in exts, f"Expected 'dbg' in enabled extensions, got: {exts}"


@test()
def test_resolve_ida_rpc_preserves_multiple_ext_query_params():
    """--ida-rpc with ext=dbg,extra should seed both extensions."""
    with _saved_target():
        args = argparse.Namespace(ida_rpc="http://10.0.0.1:9999/mcp?ext=dbg,extra")
        server._resolve_ida_rpc(args)
        exts = getattr(server.mcp._enabled_extensions, "data", set())
        assert "dbg" in exts, f"Expected 'dbg' in extensions, got: {exts}"
        assert "extra" in exts, f"Expected 'extra' in extensions, got: {exts}"


@test()
def test_resolve_ida_rpc_no_ext_leaves_extensions_empty():
    """--ida-rpc without ext param should not add spurious extensions."""
    with _saved_target():
        server.mcp._enabled_extensions.data = set()
        args = argparse.Namespace(ida_rpc="http://10.0.0.1:9999")
        server._resolve_ida_rpc(args)
        exts = getattr(server.mcp._enabled_extensions, "data", set())
        assert len(exts) == 0, f"Expected no extensions, got: {exts}"


@test()
def test_ida_rpc_ext_flows_through_to_proxy_path():
    """Extensions from --ida-rpc should appear in proxied request path."""
    with _saved_target():
        original_conn = server.http.client.HTTPConnection
        _RecordingConnection.calls = []
        server.http.client.HTTPConnection = _RecordingConnection
        try:
            args = argparse.Namespace(ida_rpc="http://10.0.0.1:9999/mcp?ext=dbg")
            server._resolve_ida_rpc(args)
            server._proxy_to_instance("10.0.0.1", 9999, b"{}")
            assert len(_RecordingConnection.calls) == 1
            assert _RecordingConnection.calls[0]["path"] == "/mcp?ext=dbg"
        finally:
            server.http.client.HTTPConnection = original_conn


@test()
def test_select_instance_isolated_per_transport_session():
    """Selecting an instance in one transport session must not affect another."""
    with _saved_target():
        original_probe = server.probe_instance
        server.probe_instance = lambda host, port: True
        try:
            server.IDA_HOST = "127.0.0.1"
            server.IDA_PORT = 13337

            server.mcp._transport_session_id.data = "http:session-A"
            result_a = server.select_instance(20001)
            assert result_a.get("success"), f"session A selection failed: {result_a}"
            assert server._get_selected_target() == ("127.0.0.1", 20001)

            server.mcp._transport_session_id.data = "http:session-B"
            result_b = server.select_instance(20002)
            assert result_b.get("success"), f"session B selection failed: {result_b}"
            assert server._get_selected_target() == ("127.0.0.1", 20002)

            server.mcp._transport_session_id.data = "http:session-A"
            assert server._get_selected_target() == ("127.0.0.1", 20001)

            server.mcp._transport_session_id.data = "http:session-B"
            assert server._get_selected_target() == ("127.0.0.1", 20002)
        finally:
            server.probe_instance = original_probe


@test()
def test_select_instance_reset_only_current_transport_session():
    """Resetting one session should not clear another session's target selection."""
    with _saved_target():
        original_probe = server.probe_instance
        server.probe_instance = lambda host, port: True
        try:
            server.IDA_HOST = "127.0.0.1"
            server.IDA_PORT = 13337

            server.mcp._transport_session_id.data = "http:session-A"
            server.select_instance(20001)

            server.mcp._transport_session_id.data = "http:session-B"
            server.select_instance(20002)

            server.mcp._transport_session_id.data = "http:session-A"
            reset = server.select_instance(0)
            assert reset.get("success"), f"session A reset failed: {reset}"
            assert server._get_selected_target() == ("127.0.0.1", 13337)

            server.mcp._transport_session_id.data = "http:session-B"
            assert server._get_selected_target() == ("127.0.0.1", 20002)
        finally:
            server.probe_instance = original_probe


@test()
def test_select_instance_by_binary_isolated_per_transport_session():
    """Binary-based selection should bind independently for each HTTP session."""
    with _saved_target():
        original_discover = server.discover_instances
        server.discover_instances = lambda: [
            {
                "host": "127.0.0.1",
                "port": 20001,
                "pid": 101,
                "binary": "chall-A.exe",
                "idb_path": "D:/ctf/chall-A.i64",
                "started_at": "2026-04-20T00:00:00+00:00",
            },
            {
                "host": "127.0.0.1",
                "port": 20002,
                "pid": 102,
                "binary": "chall-B.exe",
                "idb_path": "D:/ctf/chall-B.i64",
                "started_at": "2026-04-20T00:01:00+00:00",
            },
        ]
        try:
            server.IDA_HOST = "127.0.0.1"
            server.IDA_PORT = 13337

            server.mcp._transport_session_id.data = "http:session-A"
            result_a = server.select_instance_by_binary("chall-A.exe")
            assert result_a.get("success"), f"session A selection failed: {result_a}"
            assert server._get_selected_target() == ("127.0.0.1", 20001)

            server.mcp._transport_session_id.data = "http:session-B"
            result_b = server.select_instance_by_binary("chall-B.exe")
            assert result_b.get("success"), f"session B selection failed: {result_b}"
            assert server._get_selected_target() == ("127.0.0.1", 20002)

            server.mcp._transport_session_id.data = "http:session-A"
            assert server._get_selected_target() == ("127.0.0.1", 20001)
        finally:
            server.discover_instances = original_discover


@test()
def test_select_instance_by_binary_reports_ambiguity():
    """Binary-based selection should not guess when multiple instances share a name."""
    with _saved_target():
        original_discover = server.discover_instances
        server.discover_instances = lambda: [
            {
                "host": "127.0.0.1",
                "port": 20001,
                "pid": 101,
                "binary": "chall.exe",
                "idb_path": "D:/ctf/set1/chall.i64",
                "started_at": "2026-04-20T00:00:00+00:00",
            },
            {
                "host": "127.0.0.1",
                "port": 20002,
                "pid": 102,
                "binary": "chall.exe",
                "idb_path": "D:/ctf/set2/chall.i64",
                "started_at": "2026-04-20T00:01:00+00:00",
            },
        ]
        try:
            result = server.select_instance_by_binary("chall.exe")
            assert result["success"] is False
            assert "Multiple running IDA instances match binary" in result["error"]
            assert len(result.get("candidates", [])) == 2
        finally:
            server.discover_instances = original_discover


@test()
def test_select_instance_by_idb_normalizes_windows_path():
    """IDB-based selection should tolerate slash and case differences on Windows paths."""
    with _saved_target():
        original_discover = server.discover_instances
        server.discover_instances = lambda: [
            {
                "host": "127.0.0.1",
                "port": 20077,
                "pid": 177,
                "binary": "vm.exe",
                "idb_path": "D:\\CTF\\RE\\VM\\vm.i64",
                "started_at": "2026-04-20T00:00:00+00:00",
            }
        ]
        try:
            result = server.select_instance_by_idb("d:/ctf/re/vm/vm.i64")
            assert result.get("success"), f"IDB selection failed: {result}"
            assert result["port"] == 20077
            assert server._get_selected_target() == ("127.0.0.1", 20077)
        finally:
            server.discover_instances = original_discover


@test()
def test_proxy_to_ida_uses_transport_specific_target():
    """Proxy routing should use the current transport session's selected target."""
    with _saved_target():
        original_conn = server.http.client.HTTPConnection
        _RecordingConnection.calls = []
        server.http.client.HTTPConnection = _RecordingConnection
        try:
            server.IDA_HOST = "127.0.0.1"
            server.IDA_PORT = 13337

            server.mcp._transport_session_id.data = "http:session-A"
            server._set_selected_target("127.0.0.1", 20001)
            server._proxy_to_ida(b"{}")

            server.mcp._transport_session_id.data = "http:session-B"
            server._set_selected_target("127.0.0.1", 20002)
            server._proxy_to_ida(b"{}")

            assert len(_RecordingConnection.calls) == 2
            assert _RecordingConnection.calls[0]["host"] == "127.0.0.1"
            assert _RecordingConnection.calls[0]["port"] == 20001
            assert _RecordingConnection.calls[1]["host"] == "127.0.0.1"
            assert _RecordingConnection.calls[1]["port"] == 20002
        finally:
            server.http.client.HTTPConnection = original_conn


@test()
def test_current_instance_reports_session_selection_source():
    """current_instance should expose the selected target and whether it came from session binding."""
    with _saved_target():
        original_probe = server.probe_instance
        original_discover = server.discover_instances
        server.probe_instance = lambda host, port: True
        server.discover_instances = lambda: [
            {
                "host": "127.0.0.1",
                "port": 20001,
                "pid": 123,
                "binary": "chall-A",
                "idb_path": "D:/ctf/chall-A.i64",
                "started_at": "2026-04-20T00:00:00+00:00",
            }
        ]
        try:
            server.IDA_HOST = "127.0.0.1"
            server.IDA_PORT = 13337
            server.mcp._transport_session_id.data = "http:session-A"
            server._set_selected_target("127.0.0.1", 20001)

            result = server.current_instance()
            assert result["source"] == "session"
            assert result["host"] == "127.0.0.1"
            assert result["port"] == 20001
            assert result["binary"] == "chall-A"
            assert result["reachable"] is True
        finally:
            server.probe_instance = original_probe
            server.discover_instances = original_discover


@test()
def test_dead_default_target_refreshes_from_discovery():
    """Unbound sessions should automatically move to a live discovered default target."""
    with _saved_target():
        original_probe = server.probe_instance
        original_discover = server.discover_instances

        def fake_probe(host, port):
            return port == 20088

        server.probe_instance = fake_probe
        server.discover_instances = lambda: [
            {
                "host": "127.0.0.1",
                "port": 20088,
                "pid": 888,
                "binary": "chall-live",
                "idb_path": "D:/ctf/chall-live.i64",
                "started_at": "2026-04-20T00:00:00+00:00",
            }
        ]
        try:
            server.IDA_HOST = "127.0.0.1"
            server.IDA_PORT = 13337
            server.mcp._transport_session_id.data = "http:session-A"

            assert server._get_selected_target() == ("127.0.0.1", 20088)
            assert server.IDA_PORT == 20088
        finally:
            server.probe_instance = original_probe
            server.discover_instances = original_discover


@test()
def test_dispatch_proxy_clears_dead_session_binding_on_error():
    """Failed requests to a dead session-bound instance should clear that binding."""
    with _saved_target():
        original_probe = server.probe_instance
        original_proxy = server._proxy_to_instance

        def fake_probe(host, port):
            return port == 13337

        def fake_proxy(host, port, payload):
            raise RuntimeError("connection failed")

        server.probe_instance = fake_probe
        server._proxy_to_instance = fake_proxy
        try:
            server.IDA_HOST = "127.0.0.1"
            server.IDA_PORT = 13337
            server.mcp._transport_session_id.data = "http:session-A"
            server._set_selected_target("127.0.0.1", 20001)

            req = {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "decompile", "arguments": {}}}
            result = server.dispatch_proxy(req)

            assert "error" in result, f"Expected error result, got: {result}"
            assert server._get_selected_target() == ("127.0.0.1", 13337)
            assert "was cleared because that IDA instance is no longer reachable" in result["error"]["message"]
        finally:
            server.probe_instance = original_probe
            server._proxy_to_instance = original_proxy


@test()
def test_open_file_switches_only_at_proxy_layer():
    """Top-level open_file should keep switch routing local to the proxy session."""
    with _saved_target():
        original_probe = server.probe_instance
        original_call = server._call_ida_tool
        recorded = {}
        server.probe_instance = lambda host, port: True

        def fake_call(host, port, name, arguments):
            recorded["host"] = host
            recorded["port"] = port
            recorded["name"] = name
            recorded["arguments"] = dict(arguments)
            return {
                "success": True,
                "host": "127.0.0.1",
                "port": 20099,
                "binary": "new.bin",
                "pid": 4242,
            }

        server._call_ida_tool = fake_call
        try:
            server.IDA_HOST = "127.0.0.1"
            server.IDA_PORT = 13337
            server.mcp._transport_session_id.data = "http:session-A"
            server._set_selected_target("127.0.0.1", 20001)

            result = server.open_file("D:/ctf/new.bin", switch=True, timeout=5)
            assert result.get("success"), f"open_file failed: {result}"
            assert recorded["name"] == "open_file"
            assert recorded["arguments"]["switch"] is False
            assert server._get_selected_target() == ("127.0.0.1", 20099)
        finally:
            server.probe_instance = original_probe
            server._call_ida_tool = original_call


# ---------------------------------------------------------------------------
# Unsafe tool gating (idalib registry-removal approach, mirrors idalib_server)
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _saved_tools():
    """Save and restore the tools registry so removal tests are non-destructive."""
    original = MCP_SERVER.tools.methods.copy()
    try:
        yield
    finally:
        MCP_SERVER.tools.methods = original


@test()
def test_unsafe_tools_registered():
    """@unsafe decorator should populate MCP_UNSAFE with known tool names."""
    assert len(MCP_UNSAFE) > 0, "MCP_UNSAFE is empty — no tools marked @unsafe"
    assert "py_eval" in MCP_UNSAFE, "py_eval should be marked @unsafe"
    assert "py_exec_file" in MCP_UNSAFE, "py_exec_file should be marked @unsafe"


@test()
def test_unsafe_tools_present_by_default():
    """Unsafe tools should be in the registry by default (plugin behavior)."""
    tool_names = set(MCP_SERVER.tools.methods)
    for name in ("py_eval", "py_exec_file"):
        assert name in tool_names, f"{name} should be present by default"


@test()
def test_unsafe_tools_hidden_after_removal():
    """tools/list should exclude tools removed from the registry (idalib --unsafe behavior)."""
    with _saved_tools():
        for name in MCP_UNSAFE:
            MCP_SERVER.tools.methods.pop(name, None)
        result = MCP_SERVER._mcp_tools_list()
        tool_names = {t["name"] for t in result.get("tools", [])}
        leaked = MCP_UNSAFE & tool_names
        assert not leaked, f"Removed unsafe tools still listed: {leaked}"


@test()
def test_unsafe_tool_call_rejected_after_removal():
    """tools/call for a removed tool should return an error."""
    with _saved_tools():
        for name in MCP_UNSAFE:
            MCP_SERVER.tools.methods.pop(name, None)
        result = MCP_SERVER._mcp_tools_call("py_eval", {"code": "pass"})
        assert result.get("isError"), f"Expected error for removed tool, got: {result}"


@test()
def test_safe_tools_unaffected_by_unsafe_removal():
    """Non-unsafe tools should remain callable after unsafe removal."""
    with _saved_tools():
        for name in MCP_UNSAFE:
            MCP_SERVER.tools.methods.pop(name, None)
        assert "decompile" not in MCP_UNSAFE, "decompile should not be unsafe"
        assert "decompile" in MCP_SERVER.tools.methods, "decompile should survive removal"
