from binaryninja import (
    RepositoryManager,
    Settings,
    BackgroundTaskThread,
    execute_on_main_thread
)
from PySide6.QtCore import Qt, QRectF
from PySide6.QtGui import QImage, QPainter, QFont, QColor
from PySide6.QtWidgets import QTextEdit, QVBoxLayout
from binaryninjaui import (
    SidebarWidget, SidebarWidgetType, UIActionHandler,
    SidebarWidgetLocation, SidebarContextSensitivity
)
from pygments import highlight
from pygments.lexers import RustLexer
from pygments.formatters import HtmlFormatter
import asyncio, json, os
import asyncio, json
from typing import Any, Dict
from anthropic import Anthropic, AuthenticationError, RateLimitError, APIStatusError
from fastmcp import exceptions as mcp_exc
from tenacity import retry, stop_after_attempt, wait_random_exponential

import sys, os, importlib

from .idl_utils import fetch_idl_anchorpy

# binja screws up stdout and stderr, fastmcp doesnt like that
def _safe_fd():
    return getattr(_safe_fd, "fd", os.open(os.devnull, os.O_RDWR))

for stream_name in ("stdout", "stderr"):
    stream = getattr(sys, stream_name, None)
    if stream is not None and not hasattr(stream, "fileno"):
        stream.fileno = _safe_fd  


from fastmcp.client import Client
from fastmcp.client.transports import PythonStdioTransport

from .mcp_utils import *

DEFAULT_RPC = "https://api.mainnet-beta.solana.com"

manager = RepositoryManager()
mcp_plugin = next(
    (plugin
    for plugin in manager.plugins['community']
    if plugin.path == "fosdickio_binary_ninja_mcp"),
    None
)

mcp_module_name = None
if mcp_plugin:
    if not mcp_plugin.installed:
        # TODO: user pop-up?
        # mcp_plugin.install()
        pass
    else:
        mcp_module_name = mcp_plugin.path

if mcp_module_name is None and importlib.util.find_spec("binary_ninja_mcp") is not None:
    mcp_module_name = "binary_ninja_mcp"

if mcp_module_name is None:
    raise FileNotFoundError("Did you install binary_ninja_mcp via Git or the plugin manager?")

# TODO: use ModuleSpec instead here instead of the name?
bridge_spec = importlib.util.find_spec(".bridge.binja_mcp_bridge", mcp_module_name)
SERVER_PATH = bridge_spec.origin
if SERVER_PATH is None:
    raise FileNotFoundError("Unable to find MCP bridge module")

SYSTEM_CONTEXT = (importlib.resources.files() / "system.txt").read_text()

#settings

settings = Settings()
settings.register_group("bn-ebpf-solana", "MCP settings")
settings.register_setting(
    "bn-ebpf-solana.anthropic_api_key",
    '{"title": "Anthropic API Key", "description": "Your Anthropic API key for LLM requests", "type": "string", "default": ""}'
)
settings.register_setting(
    "bn-ebpf-solana.model",
    '{"title": "Model", "description": "Anthropic model ID to use", "type": "string", "default": "claude-sonnet-4-5"}'
)
settings.register_setting(
    "bn-ebpf-solana.context",
    '{"title": "Context for Solana MCP", "description": "Absolute path to extra context to be provided, like an IDL", "type": "string", "default": ""}'
)


class ClaudeRunner(BackgroundTaskThread):
    def __init__(self, bar):
        super().__init__("Prompting Claude for Rust (running)…", can_cancel=True)
        self.bar = bar
        self.func        = bar.f
        self.idl = bar.idl

    def run(self):
        """
        BackgroundTaskThread entry-point.
        • Talks to fast-mcp / Claude in a private event loop.
        • If anything LLM-related fails, it prints a short notice instead of
          killing the sidebar or Binary Ninja.
        """
        pretty_text = ""

        try:
            # actual async work
            pretty_text = asyncio.run(self._extract_rust())

        # ───── expected user-side failures ───────────────────────────────────
        except AuthenticationError as exc:
            pretty_text = f"LLM disabled: bad Anthropic API key ({exc})"

        except mcp_exc.McpError as exc:
            pretty_text = f"LLM disabled: MCP bridge error ({exc})"

        except RuntimeError as exc:          # client not connected, etc.
            pretty_text = f"LLM disabled: {exc}"

        # ───── any other unexpected crash ───────────────────────────────────
        except Exception as exc:
            pretty_text = f"LLM disabled: {type(exc).__name__}: {exc}"

        # ───── always update the sidebar on UI thread ───────────────────────
        finally:
            execute_on_main_thread(
                lambda: self.bar.update_ui_func(self.func, pretty_text)
            )

    # ui stuff


    #llm pipeline
    async def _extract_rust(self) -> str:
        if not self.func:
            return ""

        api_key = settings.get_string("bn-ebpf-solana.anthropic_api_key")

        if not api_key.startswith("sk-"):
            return "Please set your Anthropic API key in the plugin settings"

        # we rely on a forked version of the existing plugin to implement an mcp server
        # how do we reliably get its location?
        async with Client(PythonStdioTransport(SERVER_PATH, python_cmd="python3")) as cli:
            tools = await cli.list_tools()
            specs = [mcp_to_anthropic(t) for t in tools]

            msgs: list[Dict[str, Any]] = [{
                "role":    "user",
                "content": f"Improve the quality of decompilation inside binary ninja of {self.func.name} using all tools at your disposal"
            },
            {
              "role": "user",
              "content": "Here is the IDL interface file : " + self.idl if self.idl else ""
            }
            ]

            for _ in range(50):                        # safety cap
                reply = await self._call_claude(specs, msgs, api_key)
                tool_calls = [b for b in reply.content if b.type == "tool_use"]

                # llm doesnt wanna call any tools anymore
                if not tool_calls:
                    final = "".join(b.text for b in reply.content if b.type == "text")
                    # claude is dumb and sometimes still inserts comments before code
                    if "```" in final:
                        return final[final.index("```"):]
                    if "pub fn" in final:
                        return final[final.index("pub fn"):]
                    return final

                # tool calls
                results: list[Dict[str, Any]] = []
                for call in tool_calls:
                    try:
                        res = await cli.call_tool(call.name, call.input)
                        payload = json.dumps(blocks_to_str(res.content), ensure_ascii=False)
                    except mcp_exc.McpError as e:      # bad args, runtime error, etc.
                        payload = json.dumps({"error": str(e)}, ensure_ascii=False)

                    results.append({
                        "type":        "tool_result",
                        "tool_use_id": call.id,
                        "content":     payload,
                    })

                # ---------- feed results back to Claude ----------
                msgs.append({"role": "assistant", "content": reply.content})
                msgs.append({"role": "user",      "content": results})

        raise RuntimeError("LLM never produced final text")

    #wrap to circumvent rate limiting
    @retry(
        wait=wait_random_exponential(multiplier=1, min=10, max=60),  # 1 s → 30 s
        stop=stop_after_attempt(5),
        retry=(
            lambda exc: isinstance(exc, (RateLimitError, APIStatusError))
        ),
        reraise=False,
    )
    async def _call_claude(self, specs, msgs, api_key):
        """Single API call - automatically retried on 429 / 5xx."""
        claude = Anthropic(api_key=api_key)

        extra_context_path = settings.get_string("bn-ebpf-solana.context")
        extra_context = ""

        if extra_context_path != "":
            with open(extra_context_path) as f:
                extra_context = f.read()

        return claude.messages.create(
            model   = settings.get_string("bn-ebpf-solana.model"),
            system  = SYSTEM_CONTEXT + extra_context,
            messages     = msgs,
            tools        = specs,
            max_tokens   = 1_200,
            temperature  = 0.3,
        )

class LLMDecompSidebarWidget(SidebarWidget):
    def detect_id(self):
        # analyze the entry func
        for function in self.bv.functions:
            if function.name.endswith("::entry") and "DebugList" not in function.name:
                self.idl = fetch_idl_anchorpy(self.bv, function)


    def __init__(self, name, frame, data):
        super().__init__(name)
        self._formatter = HtmlFormatter(
            style="native",      
            noclasses=True,
            cssstyles="""
              background: transparent;
              font-family: monospace;
              /* override any default pre/span backgrounds: */
              pre { background: transparent !important; }
              span { background: transparent !important; }
            """
        )
        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)

        # Keep references for updates
        self.frame = frame
        self.bv = data 
        self.idl = None

        #current cursor
        self.here = 0
        #current function
        self.f = None

        #cache of llm responses
        self.cache = {}

        # The editor will render HTML
        self.editor = QTextEdit()
        self.editor.setReadOnly(False)

        self.editor.setStyleSheet("""
            background:transparent;
            color:inherit;
            font-family: monospace;
        """)
        self.editor.setFrameStyle(0)

        layout = QVBoxLayout()
        layout.addWidget(self.editor)
        self.setLayout(layout)

        # If we already have a BinaryView, render immediately
        if self.bv:
            self._update()

    def notifyViewChanged(self, view_frame):
        # Called when the user opens or switches tabs
        self.frame = view_frame
        if view_frame is None:
            self.bv = None
            self.editor.setHtml("")
        else:
            iface = view_frame.getCurrentViewInterface()
            self.bv = iface.getData()
            if self.idl is None:
                self.detect_id()
            self._update()

    # if the user moves around in the binary view, update UI
    def notifyOffsetChanged(self, offset):
        # Called as the cursor moves
        self._update()

    def update_ui_func(self, func, source):
        if func.name not in self.cache:
            self.cache[func.name] = source

        highlighted = highlight(source, RustLexer(), self._formatter)
        self.editor.setHtml(highlighted)

    def _update(self):
        """
        Refresh sidebar whenever the cursor moves or the view changes.

        Fixes:
        ▸ Guard against cases where the current address is NOT inside any
          discovered function (bn.get_functions_containing returns []).
        ▸ Avoid repeated work if we’re still in the same function.
        """
        # ── Early-outs ────────────────────────────────────────────────────────────
        if not self.frame or not self.bv:
            return

        view = self.frame.getCurrentViewInterface()
        addr = view.getCurrentOffset()

        if addr == self.here:               # cursor hasn’t moved
            return
        self.here = addr

        # ── Robust lookup ────────────────────────────────────────────────────────
        funcs = self.bv.get_functions_containing(addr)
        if not funcs:
            # Cursor is in padding / header / data region → just clear pane.
            self.editor.setHtml("")
            self.f = None
            return

        func = funcs[0]
        if self.f == func:                  # already displaying this function
            return
        self.f = func

        # ── Cached? ──────────────────────────────────────────────────────────────
        if func.name in self.cache:
            self.update_ui_func(func, self.cache[func.name])
            return

        # ── Kick off background Claude job ───────────────────────────────────────
        task = ClaudeRunner(self)
        task.start()

    def contextMenuEvent(self, event):
        # if you want a right-click menu later
        self.m_contextMenuManager.show(self.m_menu, event.globalPos())


class LLMDecompSidebarWidgetType(SidebarWidgetType):
    def __init__(self):
        # Icons are 28×28 points; use 56×56px for HiDPI
        icon = QImage(56, 56, QImage.Format_RGB32)
        icon.fill(0)

        painter = QPainter(icon)
        painter.setFont(QFont("Open Sans", 56))
        painter.setPen(QColor(255, 255, 255, 255))
        # R for Rust!
        painter.drawText(QRectF(0, 0, 56, 56), Qt.AlignCenter, "R")
        painter.end()

        super().__init__(icon, "LLM reconstructed Rust")

    def createWidget(self, frame, data):
        # frame: a ViewFrameRef, data: BinaryViewRef or None
        return LLMDecompSidebarWidget("LLM reconstructed Rust", frame, data)

    def defaultLocation(self):
        return SidebarWidgetLocation.RightContent

    def contextSensitivity(self):
        return SidebarContextSensitivity.SelfManagedSidebarContext
