# Copyright (c) 2015-2023 Vector 35 Inc
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
import abc
import functools
from pathlib import Path
from typing import List, Any, Optional

from PySide6.QtCore import Qt, QRectF, QTimer
from PySide6.QtGui import QImage, QPainter, QFont, QColor, QShowEvent, QHideEvent
from PySide6.QtWidgets import QVBoxLayout, QListWidget, QAbstractItemView
from binaryninja import BinaryView, AnalysisState
from binaryninjaui import SidebarWidget, SidebarWidgetType, Sidebar, ViewFrame


class AnalysisProgressSidebarWidget(SidebarWidget):
    def __init__(self, name, frame: ViewFrame, data: BinaryView):
        SidebarWidget.__init__(self, name)
        self.m_actionHandler.setupActionHandler(self)
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)

        self.frame = frame
        self.data = data

        self.list = QListWidget(self)
        self.list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.list.setSelectionBehavior(QAbstractItemView.SelectRows)

        self.layout.addWidget(self.list)
        self.update_model()

        self.timer = QTimer()
        self.timer.setInterval(100)
        self.timer.timeout.connect(lambda: self.update_model())

    def notifyOffsetChanged(self, offset):
        pass

    def notifyViewChanged(self, view_frame):
        pass

    def contextMenuEvent(self, event):
        self.m_contextMenuManager.show(self.m_menu, self.m_actionHandler)

    def showEvent(self, event: QShowEvent) -> None:
        self.timer.start()

    def hideEvent(self, event: QHideEvent) -> None:
        self.timer.stop()

    def update_model(self):
        state = self.data.analysis_info

        self.list.clear()
        self.list.addItem(f"Analysis State: {AnalysisState(state.state).name}")
        self.list.addItem(f"Time: {state.analysis_time / 1000}")

        for info in state.active_info:
            self.list.addItem(f"{info.func.start:#x} {info.analysis_time / 1000} {info.update_count} {info.submit_count}")


class AnalysisProgressSidebarWidgetType(SidebarWidgetType):
    def __init__(self):
        # Sidebar icons are 28x28 points. Should be at least 56x56 pixels for
        # HiDPI display compatibility. They will be automatically made theme
        # aware, so you need only provide a grayscale image, where white is
        # the color of the shape.
        icon = QImage(56, 56, QImage.Format_RGB32)
        icon.fill(0)

        # Render an "H" as the example icon
        p = QPainter()
        p.begin(icon)
        p.setFont(QFont("Open Sans", 42))
        p.setPen(QColor(255, 255, 255, 255))
        p.drawText(QRectF(0, 0, 56, 56), Qt.AlignCenter, "AP")
        p.end()

        SidebarWidgetType.__init__(self, icon, "Analysis State")

    def createWidget(self, frame: ViewFrame, data: BinaryView):
        return AnalysisProgressSidebarWidget("Analysis State", frame, data)


Sidebar.addSidebarWidgetType(AnalysisProgressSidebarWidgetType())
