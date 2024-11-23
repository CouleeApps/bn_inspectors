# Copyright (c) 2015-2024 Vector 35 Inc
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
from typing import Optional, List

from PySide6.QtCore import Qt, QRectF
from PySide6.QtGui import QImage, QPainter, QFont, QColor, QShowEvent, QHideEvent, \
    QStandardItemModel
from PySide6.QtGui import QStandardItem
from PySide6.QtWidgets import QVBoxLayout, QTreeView
from binaryninja import BinaryView, LowLevelILOperandType, LowLevelILReg, \
    LowLevelILSetReg, LowLevelILRegSplit, LowLevelILRegSsaPartial, LowLevelILSetRegSsa, \
    SSARegister, LowLevelILRegSplitSsa, LowLevelILSetRegSplit, LowLevelILSetRegSsaPartial, \
    ILRegister, ThemeColor, Architecture, Function, FunctionViewType, DisassemblySettings
from binaryninja import FunctionGraphType, \
    LowLevelILFunction, _binaryninjacore, \
    LowLevelILInstruction, LowLevelILOperation, MediumLevelILFunction, HighLevelILFunction
from binaryninjaui import SidebarWidget, SidebarWidgetType, Sidebar, ViewFrame, \
    UIContextNotification, UIContext, ViewLocation, View, getThemeColor
from binaryninjaui import getMonospaceFont


class RegisterSidebarWidget(SidebarWidget, UIContextNotification):
    def __init__(self, name, frame: ViewFrame, data: BinaryView):
        SidebarWidget.__init__(self, name)
        UIContextNotification.__init__(self)
        self.m_actionHandler.setupActionHandler(self)
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)

        self.frame = frame
        self.data = data

        self.model = QStandardItemModel(self)
        self.tree = QTreeView(self)
        self.tree.setModel(self.model)
        self.tree.setIndentation(10)
        self.tree.setAutoScroll(False)
        self.tree.setModel(self.model)

        self.graph_type: Optional[FunctionViewType] = None
        self.current_address: int = 0
        self.current_arch: Optional[Architecture] = None
        self.current_function: Optional[Function] = None
        self.disassembly_settings: Optional[DisassemblySettings] = None

        self.func_regs: List[ILRegister] = []

        self.layout.addWidget(self.tree)
        self.update_tree()
        UIContext.registerNotification(self)

    def __del__(self):
        UIContext.unregisterNotification(self)

    def notifyOffsetChanged(self, offset):
        pass

    def notifyViewChanged(self, view_frame):
        pass

    def contextMenuEvent(self, event):
        self.m_contextMenuManager.show(self.m_menu, self.m_actionHandler)

    def showEvent(self, event: QShowEvent) -> None:
        self.update_tree()

    def hideEvent(self, event: QHideEvent) -> None:
        self.update_tree()

    def OnViewChange(self, context: UIContext, frame: ViewFrame, type: str):
        self.update_tree()

    def OnAddressChange(self, context: UIContext, frame: ViewFrame, view: View, location: ViewLocation):
        self.update_tree()

    def update_tree(self):
        view = self.frame.getCurrentViewInterface()

        new_func = False
        if view is not None:
            new_func = (self.current_function != view.getCurrentFunction())
            self.graph_type = view.getILViewType()
            self.current_address = view.getCurrentOffset()
            self.current_arch = view.getCurrentArchitecture()
            self.current_function = view.getCurrentFunction()
            self.disassembly_settings = view.getDisassemblySettings()

        if self.current_function is None:
            return

        if new_func:
            self.func_regs = set()

            def collect_regs(insn: LowLevelILInstruction):
                match insn:
                    case LowLevelILReg(src=reg):
                        return [reg]
                    case LowLevelILRegSplit(hi=hi, lo=lo):
                        return [hi, lo]
                    case LowLevelILRegSsaPartial(full_reg=SSARegister(reg=full), src=reg):
                        return [full, reg]
                    case LowLevelILRegSplitSsa(hi=SSARegister(reg=hi), lo=SSARegister(reg=lo)):
                        return [hi, lo]
                    case LowLevelILSetReg(dest=reg):
                        return [reg]
                    case LowLevelILSetRegSplit(hi=hi, lo=lo):
                        return [hi, lo]
                    case LowLevelILSetRegSsa(dest=SSARegister(reg=reg)):
                        return [reg]
                    case LowLevelILSetRegSsaPartial(full_reg=SSARegister(reg=full), dest=reg):
                        return [full, reg]

            for regs in self.current_function.llil.traverse(collect_regs):
                self.func_regs.update(reg.info.full_width_reg for reg in regs if not reg.temp)

            self.func_regs = sorted(list(self.func_regs), key=lambda reg: self.current_arch.get_reg_index(reg))

        self.model.clear()
        self.model.setRowCount(0)

        self.model.setColumnCount(3)
        self.model.setHeaderData(0, Qt.Orientation.Horizontal, "reg")
        self.model.setHeaderData(1, Qt.Orientation.Horizontal, "before")
        self.model.setHeaderData(2, Qt.Orientation.Horizontal, "after")

        monospace_font = getMonospaceFont(self)

        def monospace(item):
            item.setFont(monospace_font)
            return item

        def header(row):
            for item in row:
                item: QStandardItem
                item.setBackground(self.palette().alternateBase())
            return row

        for reg_name in self.func_regs:
            reg_value_before = self.current_function.get_reg_value_at(self.current_address, reg_name, self.current_arch)
            reg_value_after = self.current_function.get_reg_value_after(self.current_address, reg_name, self.current_arch)

            row = [
                QStandardItem(reg_name),
                monospace(QStandardItem(str(reg_value_before))),
                monospace(QStandardItem(str(reg_value_after))),
            ]

            if reg_value_before.type != reg_value_after.type \
                    or reg_value_before.value != reg_value_after.value \
                    or reg_value_before.offset != reg_value_after.offset:
                for item in row:
                    item.setForeground(getThemeColor(ThemeColor.GreenStandardHighlightColor))

            self.model.invisibleRootItem().appendRow(row)

        self.tree.expandToDepth(1)

        self.tree.resizeColumnToContents(0)
        self.tree.resizeColumnToContents(1)
        self.tree.resizeColumnToContents(2)


class RegisterSidebarWidgetType(SidebarWidgetType):
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
        p.setFont(QFont("Open Sans", 56))
        p.setPen(QColor(255, 255, 255, 255))
        p.drawText(QRectF(0, 0, 56, 56), Qt.AlignCenter, "R")
        p.end()

        SidebarWidgetType.__init__(self, icon, "Register Inspector")

    def createWidget(self, frame: ViewFrame, data: BinaryView):
        return RegisterSidebarWidget("Register Inspector", frame, data)


Sidebar.addSidebarWidgetType(RegisterSidebarWidgetType())
