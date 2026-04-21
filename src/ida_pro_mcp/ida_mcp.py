"""IDA Pro MCP Plugin Loader

This file serves as the entry point for IDA Pro's plugin system.
It loads the actual implementation from the ida_mcp package.
"""

import os
import json
import shutil
import socket
import subprocess
import sys
import time
import idaapi
import ida_kernwin
import ida_netnode
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import ida_mcp


NETNODE_AUTOSTART = "$ ida_mcp.autostart"


def _get_autostart() -> bool:
    """Read the autostart preference from the IDB. Defaults to True."""
    node = ida_netnode.netnode(NETNODE_AUTOSTART)
    val = node.altval(0)  # 0 = not set, 1 = off, 2 = on
    return val != 1


def _set_autostart(enabled: bool):
    """Persist the autostart preference into the IDB."""
    node = ida_netnode.netnode(NETNODE_AUTOSTART, 0, True)
    node.altset(0, 1 if not enabled else 2)


def _get_ida_user_dir() -> str:
    """Return the current user's IDA directory."""
    if sys.platform == "win32":
        return os.path.join(os.environ["APPDATA"], "Hex-Rays", "IDA Pro")
    return os.path.join(os.path.expanduser("~"), ".idapro")


def unload_package(package_name: str):
    """Remove every module that belongs to the package from sys.modules."""
    to_remove = [
        mod_name
        for mod_name in sys.modules
        if mod_name == package_name or mod_name.startswith(package_name + ".")
    ]
    for mod_name in to_remove:
        del sys.modules[mod_name]


CONFIG_ACTION_ID = "mcp:configure"
CONFIG_ACTION_LABEL = "MCP Configuration"


class _SafePromptFormatDict(dict):
    def __missing__(self, key):
        return "{" + key + "}"


class MCPConfigForm(idaapi.Form):
    """Form to configure MCP server host and port."""

    def __init__(self, host: str, port: int, autostart: bool):
        form_str = r"""STARTITEM 0
MCP Server Configuration

<Host:{host}>
<Port:{port}>
<Autostart server when IDA opens:{autostart}>{checks}>
"""
        super().__init__(
            form_str,
            {
                "host": idaapi.Form.StringInput(value=host),
                "port": idaapi.Form.NumericInput(value=port, tp=idaapi.Form.FT_DEC),
                "checks": idaapi.Form.ChkGroupControl(("autostart",), value=1 if autostart else 0),
            },
        )


class MCPConfigHandler(idaapi.action_handler_t):
    def __init__(self, plugin: "MCP"):
        idaapi.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        old_host = self.plugin.host
        old_port = self.plugin.port
        old_autostart = self.plugin.autostart

        form = MCPConfigForm(self.plugin.host, self.plugin.port, self.plugin.autostart)
        form.Compile()
        ok = form.Execute()
        if ok != 1:
            form.Free()
            return 0

        host = form.host.value
        port = form.port.value
        autostart = bool(form.checks.value & 1)
        form.Free()

        if port < 1 or port > 65535:
            print(f"[MCP] Invalid port: {port}")
            return 0

        if autostart != old_autostart:
            self.plugin.autostart = autostart
            _set_autostart(autostart)
            print(f"[MCP] Autostart {'enabled' if autostart else 'disabled'}")

        if host == old_host and port == old_port:
            if autostart == old_autostart:
                print(f"[MCP] Configuration unchanged: {host}:{port}")
            return 1

        self.plugin.host = host
        self.plugin.port = port
        print(f"[MCP] Configuration updated: {host}:{port}")

        # Apply new endpoint immediately if the server is running.
        if self.plugin.mcp is not None:
            print("[MCP] Applying configuration change without manual restart...")
            self.plugin.restart_local_server()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class MCPUIHooks(ida_kernwin.UI_Hooks):
    """Defers menu attachment and autostart until the UI is fully ready."""

    def __init__(self, plugin: "MCP"):
        super().__init__()
        self.plugin = plugin

    def ready_to_run(self):
        ida_kernwin.attach_action_to_menu(
            "Edit/Plugins/", CONFIG_ACTION_ID, idaapi.SETMENU_APP
        )
        # Skip autostart when running under idalib – the idalib_server manages
        # the MCP server lifecycle itself and would otherwise hit a port conflict
        # because unload_package creates a separate MCP_SERVER instance.
        if self.plugin.autostart and ida_kernwin.is_idaq():
            print("[MCP] Autostarting server...")
            self.plugin.run(0)
        self.unhook()


class MCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "MCP Plugin"
    help = "MCP"
    wanted_name = "MCP"
    wanted_hotkey = "Ctrl-Alt-M"

    PROXY_HOST = os.environ.get("IDA_MCP_PROXY_HOST", "127.0.0.1")
    PROXY_PORT = int(os.environ.get("IDA_MCP_PROXY_PORT", "8744"))
    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = int(os.environ.get("IDA_MCP_LOCAL_PORT", "13777"))
    LOCAL_PORT_SPAN = 100
    PROXY_START_TIMEOUT = 8.0
    PROXY_POLL_INTERVAL = 0.25
    PROMPT_TEMPLATE_ENV = "IDA_MCP_PROMPT_TEMPLATE"
    PROMPT_TEMPLATE_NAME = "prompt_template.txt"
    DEFAULT_PROMPT_TEMPLATE = (
        "# 自定义 MCP 提示词模板\n"
        "# 支持占位符: {idb_path} {binary} {binding_steps} {local_instance_url} {shared_proxy_url}\n"
        "# 也支持: {select_instance_by_idb} {select_instance_by_binary} {current_instance_call} {list_instances_call}\n"
        "\n"
        "你现在是 CTF 二进制分析与解题助手。\n"
        "\n"
        "请调用 IDA MCP 分析当前题目。\n"
        "\n"
        "请只分析这个题目，不要切换到其他 IDA 实例。\n"
        "\n"
        "IDB: {idb_path}\n"
        "Binary: {binary}\n"
        "\n"
        "先绑定并确认当前实例：\n"
        "{binding_steps}\n"
        "\n"
        "题目类型:\n"
        "题目描述:\n"
        "目标:\n"
    )

    def init(self):
        hotkey = MCP.wanted_hotkey.replace("-", "+")
        if __import__("sys").platform == "darwin":
            hotkey = hotkey.replace("Alt", "Option")

        self.mcp: "ida_mcp.rpc.McpServer | None" = None
        self.host = self.DEFAULT_HOST
        self.port = self.DEFAULT_PORT
        self.autostart = _get_autostart()
        self._ensure_prompt_template_file()

        if self.autostart and ida_kernwin.is_idaq():
            print("[MCP] Plugin loaded, server will start automatically")
        elif not ida_kernwin.is_idaq():
            print("[MCP] Plugin loaded (idalib mode, server managed externally)")
        else:
            print(
                f"[MCP] Plugin loaded, use Edit -> Plugins -> MCP ({hotkey}) to start the server"
            )
        print(f"[MCP] Prompt template: {self._get_prompt_template_path()}")

        # Register a separate menu item for host/port configuration
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                CONFIG_ACTION_ID,
                CONFIG_ACTION_LABEL,
                MCPConfigHandler(self),
            )
        )
        # Defer menu attachment and autostart until the UI is fully initialized
        self._ui_hooks = MCPUIHooks(self)
        self._ui_hooks.hook()

        return idaapi.PLUGIN_KEEP

    def _unregister_instance(self):
        port = getattr(self, "_registered_port", None)
        if port is not None:
            try:
                if TYPE_CHECKING:
                    from .ida_mcp.discovery import unregister_instance
                else:
                    from ida_mcp.discovery import unregister_instance
                unregister_instance(port)
            except Exception as e:
                print(f"[MCP] Instance unregistration failed: {e}")
            self._registered_port = None

    @staticmethod
    def _probe_port(host: str, port: int, timeout: float = 0.5) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    @classmethod
    def _get_python_executable(cls) -> str | None:
        override = os.environ.get("IDA_MCP_PROXY_PYTHON")
        if override:
            return override

        venv = os.environ.get("VIRTUAL_ENV")
        if venv:
            candidate = (
                os.path.join(venv, "Scripts", "python.exe")
                if sys.platform == "win32"
                else os.path.join(venv, "bin", "python3")
            )
            if os.path.exists(candidate):
                return candidate

        for path in sys.path:
            normalized = path.replace("/", "\\") if sys.platform == "win32" else path
            split = normalized.split(os.sep)
            if split and split[-1].endswith(".zip"):
                base = os.path.dirname(normalized)
                candidate = (
                    os.path.join(base, "python.exe")
                    if sys.platform == "win32"
                    else os.path.join(base, "..", "bin", "python3")
                )
                candidate = os.path.abspath(candidate)
                if os.path.exists(candidate):
                    return candidate

        for attr in ("_base_executable", "executable"):
            candidate = getattr(sys, attr, None)
            if candidate and os.path.basename(candidate).lower().startswith("python"):
                return candidate

        for name in ("python", "python3"):
            candidate = shutil.which(name)
            if candidate:
                return candidate

        return None

    @classmethod
    def _build_proxy_command(cls) -> list[str] | None:
        python_exe = cls._get_python_executable()
        if not python_exe:
            return None

        command = [python_exe]
        basename = os.path.basename(python_exe).lower()
        if basename in ("py", "py.exe"):
            command.append("-3")
        command.extend(
            [
                "-m",
                "ida_pro_mcp.server",
                "--transport",
                f"http://{cls.PROXY_HOST}:{cls.PROXY_PORT}/mcp",
                "--background",
            ]
        )
        return command

    def _wait_for_port(self, host: str, port: int, timeout: float) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._probe_port(host, port, timeout=0.5):
                return True
            time.sleep(self.PROXY_POLL_INTERVAL)
        return False

    @staticmethod
    def _quote_prompt_value(value: str) -> str:
        return json.dumps(value or "", ensure_ascii=False)

    @classmethod
    def _get_prompt_template_path(cls) -> str:
        override = os.environ.get(cls.PROMPT_TEMPLATE_ENV)
        if override:
            return override
        return os.path.join(_get_ida_user_dir(), "mcp", cls.PROMPT_TEMPLATE_NAME)

    def _ensure_prompt_template_file(self) -> str:
        path = self._get_prompt_template_path()
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write(self.DEFAULT_PROMPT_TEMPLATE)
            print(f"[MCP] Created prompt template: {path}")
        return path

    def _load_prompt_template(self) -> str:
        path = self._ensure_prompt_template_file()
        try:
            with open(path, "r", encoding="utf-8-sig") as f:
                return f.read()
        except Exception as e:
            print(f"[MCP] Failed to read prompt template {path}: {e}")
            print("[MCP] Falling back to built-in prompt template.")
            return self.DEFAULT_PROMPT_TEMPLATE

    def _build_binding_steps(self, idb_path: str, binary: str) -> str:
        if idb_path:
            lines = [f"1. select_instance_by_idb({self._quote_prompt_value(idb_path)})"]
            if binary:
                lines.append(
                    f"2. 失败再用 select_instance_by_binary({self._quote_prompt_value(binary)})"
                )
                lines.append("3. current_instance()")
            else:
                lines.append("2. current_instance()")
            return "\n".join(lines)

        if binary:
            return "\n".join(
                [
                    f"1. select_instance_by_binary({self._quote_prompt_value(binary)})",
                    "2. current_instance()",
                ]
            )

        return "\n".join(
            [
                "1. list_instances()",
                "2. 选中目标实例后再继续",
            ]
        )

    def _render_prompt_template(self, template: str, context: dict[str, str]) -> str:
        filtered = "\n".join(
            line for line in template.splitlines() if not line.lstrip().startswith("#")
        ).strip()
        try:
            return filtered.format_map(_SafePromptFormatDict(context)).strip()
        except Exception as e:
            print(f"[MCP] Failed to render prompt template: {e}")
            if template != self.DEFAULT_PROMPT_TEMPLATE:
                print("[MCP] Falling back to built-in prompt template.")
                return self._render_prompt_template(self.DEFAULT_PROMPT_TEMPLATE, context)
            return filtered

    def _build_analysis_prompt(self, active_port: int | None = None) -> str:
        binary = ""
        idb_path = ""
        try:
            import ida_nalt
            import idc

            binary = ida_nalt.get_root_filename() or ""
            idb_path = idc.get_idb_path() or ""
        except Exception:
            pass

        local_port = active_port or getattr(self, "_registered_port", self.port)
        binding_steps = self._build_binding_steps(idb_path, binary)
        context = {
            "idb_path": idb_path or "(unknown)",
            "binary": binary or "(unknown)",
            "binding_steps": binding_steps,
            "local_instance_url": f"http://{self.host}:{local_port}/mcp",
            "shared_proxy_url": f"http://{self.PROXY_HOST}:{self.PROXY_PORT}/mcp",
            "select_instance_by_idb": (
                f"select_instance_by_idb({self._quote_prompt_value(idb_path)})"
                if idb_path
                else "list_instances()"
            ),
            "select_instance_by_binary": (
                f"select_instance_by_binary({self._quote_prompt_value(binary)})"
                if binary
                else "list_instances()"
            ),
            "current_instance_call": "current_instance()",
            "list_instances_call": "list_instances()",
        }
        template = self._load_prompt_template()
        return self._render_prompt_template(template, context)

    def _emit_analysis_prompt(self, active_port: int | None = None):
        prompt = self._build_analysis_prompt(active_port=active_port)
        print("[MCP] Analysis prompt generated.")
        print(f"[MCP] Prompt template: {self._get_prompt_template_path()}")
        print("[MCP] ----- Suggested Prompt Begin -----")
        print(prompt)
        print("[MCP] ----- Suggested Prompt End -----")

    def ensure_proxy_running(self) -> bool:
        if self._probe_port(self.PROXY_HOST, self.PROXY_PORT, timeout=0.5):
            print(
                f"[MCP] Shared proxy already running at http://{self.PROXY_HOST}:{self.PROXY_PORT}/mcp"
            )
            return True

        command = self._build_proxy_command()
        if not command:
            print(
                "[MCP] Failed to locate a Python interpreter for the shared proxy. "
                "Set IDA_MCP_PROXY_PYTHON to override."
            )
            return False

        print(
            f"[MCP] Starting shared proxy at http://{self.PROXY_HOST}:{self.PROXY_PORT}/mcp ..."
        )
        creationflags = 0
        if sys.platform == "win32":
            creationflags = (
                getattr(subprocess, "DETACHED_PROCESS", 0)
                | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                | getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )

        try:
            subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                creationflags=creationflags,
                close_fds=(sys.platform != "win32"),
            )
        except Exception as e:
            print(f"[MCP] Failed to launch shared proxy: {e}")
            print(f"[MCP] Command: {' '.join(command)}")
            return False

        if self._wait_for_port(self.PROXY_HOST, self.PROXY_PORT, self.PROXY_START_TIMEOUT):
            print(
                f"[MCP] Shared proxy ready at http://{self.PROXY_HOST}:{self.PROXY_PORT}/mcp"
            )
            return True

        print(
            "[MCP] Shared proxy did not become ready in time. "
            "Ensure ida-pro-mcp is installed in the selected Python environment."
        )
        print(f"[MCP] Command: {' '.join(command)}")
        return False

    def _stop_local_server(self):
        if self.mcp:
            self._unregister_instance()
            self.mcp.stop()
            self.mcp = None

    def _start_local_server(self):
        self._stop_local_server()

        # HACK: ensure fresh load of ida_mcp package
        unload_package("ida_mcp")
        if TYPE_CHECKING:
            from .ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, set_local_instance
        else:
            from ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, set_local_instance

        port = self.port
        max_port = port + self.LOCAL_PORT_SPAN
        while port < max_port:
            try:
                MCP_SERVER.serve(
                    self.host, port, request_handler=IdaMcpHttpRequestHandler
                )
                print(
                    f"[MCP] Local instance ready at http://{self.host}:{port}/mcp "
                    f"(proxy: http://{self.PROXY_HOST}:{self.PROXY_PORT}/mcp)"
                )
                print(f"  Config: http://{self.host}:{port}/config.html")
                self.mcp = MCP_SERVER
                set_local_instance(self.host, port)
                self._register_instance(port)
                return True
            except OSError as e:
                if e.errno in (48, 98, 10048):  # Address already in use
                    port += 1
                else:
                    raise
        print(f"[MCP] Error: No available local port in range {self.port}-{max_port - 1}")
        return False

    def restart_local_server(self):
        if not self.ensure_proxy_running():
            print("[MCP] Aborting local restart because the shared proxy is unavailable")
            return
        if self._start_local_server():
            self._emit_analysis_prompt()

    def run(self, arg):
        if self.mcp:
            self.ensure_proxy_running()
            active_port = getattr(self, "_registered_port", self.port)
            print(
                f"[MCP] Local instance already running at http://{self.host}:{active_port}/mcp"
            )
            print(f"  Config: http://{self.host}:{active_port}/config.html")
            self._emit_analysis_prompt(active_port=active_port)
            return

        if not self.ensure_proxy_running():
            print("[MCP] Aborting local startup because the shared proxy could not be started")
            return

        if self._start_local_server():
            self._emit_analysis_prompt()

    def _register_instance(self, port: int):
        try:
            if TYPE_CHECKING:
                from .ida_mcp.discovery import register_instance
            else:
                from ida_mcp.discovery import register_instance
            import os
            import idc
            import ida_nalt
            binary = ida_nalt.get_root_filename() or ""
            idb_path = idc.get_idb_path() or ""
            file_path = register_instance(
                host=self.host,
                port=port,
                pid=os.getpid(),
                binary=binary,
                idb_path=idb_path,
            )
            self._registered_port = port
            print(f"[MCP] Registered instance: {binary} (pid={os.getpid()}, port={port})")
            print(f"  Discovery file: {file_path}")
        except Exception as e:
            import traceback
            print(f"[MCP] Instance registration failed: {e}")
            traceback.print_exc()

    def term(self):
        if hasattr(self, "_ui_hooks"):
            self._ui_hooks.unhook()
        ida_kernwin.unregister_action(CONFIG_ACTION_ID)
        self._stop_local_server()


def PLUGIN_ENTRY():
    return MCP()


