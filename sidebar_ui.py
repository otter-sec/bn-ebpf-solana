import os
from binaryninja import BackgroundTaskThread, execute_on_main_thread
from PySide6.QtCore import Qt, QRectF
from PySide6.QtGui import QImage, QPainter, QFont, QColor
from PySide6.QtWidgets import QTextEdit, QVBoxLayout
from binaryninjaui import (
    SidebarWidget, SidebarWidgetType, Sidebar, UIActionHandler,
    SidebarWidgetLocation, SidebarContextSensitivity
)
from pygments import highlight
from pygments.lexers import RustLexer
from pygments.formatters import HtmlFormatter
import asyncio, json, os
import asyncio, json
from typing import Any, Dict
from anthropic import Anthropic, RateLimitError, APIStatusError
from fastmcp import exceptions as mcp_exc
from tenacity import retry, stop_after_attempt, wait_random_exponential

import sys, os

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
from pathlib import Path

import zlib, sys
from solders.pubkey import Pubkey
from solana.rpc.async_api import AsyncClient

from .mcp_utils import *

DEFAULT_RPC = "https://api.mainnet-beta.solana.com"
SERVER_PATH = Path(__file__).parent.parent / "binary_ninja_mcp" / "bridge" / "binja_mcp_bridge.py"
#needs to be set
CLAUDE      = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

class ClaudeRunner(BackgroundTaskThread):
    def __init__(self, bar):
        super().__init__("Prompting Claude for Rust (running)…", can_cancel=True)
        self.bar = bar
        self.func        = bar.f
        self.idl = bar.idl

    def run(self):
        """BackgroundTaskThread expects a *sync* function.
        We spin up an event-loop just for this thread."""

        pretty_text = ""

        try:
            pretty_text = asyncio.run(self._extract_rust())
        except* Exception as exc:                       # irrecoverable
            print(exc.exceptions)
            pretty_text = f"❌ Error while extracting Rust:\n"
            for e in exc.exceptions:
                pretty_text += f"{e}\n"
            
        finally:
            execute_on_main_thread(lambda: self.bar.update_ui_func(self.func, pretty_text))

    # ui stuff
    


    #llm pipeline
    async def _extract_rust(self) -> str:
        if not self.func:
            return ""

        # we rely on a forked version of the existing plugin to implement an mcp server
        # how do we reliably get its location?
        async with Client(PythonStdioTransport(SERVER_PATH)) as cli:
            tools = await cli.list_tools()
            specs = [mcp_to_anthropic(t) for t in tools]

            print("CLAUDE IDL: ", self.idl)

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
                reply = await self._call_claude(specs, msgs)
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
                        payload = json.dumps(blocks_to_str(res), ensure_ascii=False)
                    except mcp_exc.MCPError as e:      # bad args, runtime error, etc.
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
    async def _call_claude(self, specs, msgs):
        """Single API call - automatically retried on 429 / 5xx."""

        return CLAUDE.messages.create(
            model   = "claude-3-5-sonnet-20241022",
            system  = open(Path(__file__).parent / "system.txt").read(), 
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
                print("AAAAAAA")
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
        if not self.frame or not self.bv:
            return
        view = self.frame.getCurrentViewInterface()
        addr = view.getCurrentOffset()
        if addr == self.here:
            return
        self.here = addr
        func = self.bv.get_functions_containing(addr)[0]

        if self.f == func:
            return

        self.f = func

        if func.name in self.cache:
            print("Cache hit for ", func.name)
            self.update_ui_func(func, self.cache[func.name])
            return

        print(__file__)
        print(os.environ)
        print(f"starting Claude for {func.name}...")

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

# Register the sidebar widget type
Sidebar.addSidebarWidgetType(LLMDecompSidebarWidgetType())
