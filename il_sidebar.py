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
from typing import Optional

from PySide6.QtCore import Qt, QRectF
from PySide6.QtGui import QImage, QPainter, QFont, QColor, QShowEvent, QHideEvent, \
    QStandardItemModel
from PySide6.QtGui import QStandardItem
from PySide6.QtWidgets import QVBoxLayout, QTreeView
import binaryninja
from binaryninja import BinaryView, MediumLevelILInstruction, MediumLevelILOperation
from binaryninja import FunctionGraphType, \
    LowLevelILFunction, _binaryninjacore, \
    LowLevelILInstruction, LowLevelILOperation, MediumLevelILFunction, HighLevelILFunction, \
    HighLevelILFunction, HighLevelILOperation, HighLevelILInstruction
from binaryninjaui import SidebarWidget, SidebarWidgetType, Sidebar, ViewFrame, \
    UIContextNotification, UIContext, ViewLocation, View
from binaryninjaui import getMonospaceFont


class ILSidebarWidget(SidebarWidget, UIContextNotification):
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

        self.layout.addWidget(self.tree)
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

        if view is not None:
            self.graph_type = view.getILViewType()
            self.current_address = view.getCurrentOffset()
            self.current_function = view.getCurrentFunction()
            self.disassembly_settings = view.getDisassemblySettings()

            if hasattr(binaryninja, 'FunctionViewType') \
                    and isinstance(self.graph_type, binaryninja.FunctionViewType):
                self.graph_type = self.graph_type.view_type

        if self.current_function is None:
            return

        self.model.clear()
        self.model.setRowCount(0)

        il_function = None
        if self.current_function is not None:
            if self.graph_type == FunctionGraphType.LiftedILFunctionGraph:
                il_function: Optional[LowLevelILFunction] = self.current_function.lifted_il_if_available
            if self.graph_type == FunctionGraphType.LowLevelILFunctionGraph:
                il_function: Optional[LowLevelILFunction] = self.current_function.llil_if_available
            if self.graph_type == FunctionGraphType.LowLevelILSSAFormFunctionGraph:
                il_function: Optional[LowLevelILFunction] = self.current_function.llil_if_available
                if il_function is not None:
                    il_function = il_function.ssa_form
            if self.graph_type == FunctionGraphType.MappedMediumLevelILFunctionGraph:
                il_function: Optional[MediumLevelILFunction] = self.current_function.mmlil_if_available
            if self.graph_type == FunctionGraphType.MappedMediumLevelILSSAFormFunctionGraph:
                il_function: Optional[MediumLevelILFunction] = self.current_function.mmlil_if_available
                if il_function is not None:
                    il_function = il_function.ssa_form
            if self.graph_type == FunctionGraphType.MediumLevelILFunctionGraph:
                il_function: Optional[MediumLevelILFunction] = self.current_function.mlil_if_available
            if self.graph_type == FunctionGraphType.MediumLevelILSSAFormFunctionGraph:
                il_function: Optional[MediumLevelILFunction] = self.current_function.mlil_if_available
                if il_function is not None:
                    il_function = il_function.ssa_form
            if self.graph_type == FunctionGraphType.HighLevelILFunctionGraph:
                il_function: Optional[HighLevelILFunction] = self.current_function.hlil_if_available
            if self.graph_type == FunctionGraphType.HighLevelILSSAFormFunctionGraph:
                il_function: Optional[HighLevelILFunction] = self.current_function.hlil_if_available
                if il_function is not None:
                    il_function = il_function.ssa_form
            if self.graph_type == FunctionGraphType.HighLevelLanguageRepresentationFunctionGraph:
                il_function: Optional[HighLevelILFunction] = self.current_function.hlil_if_available

        if il_function is None:
            self.model.setColumnCount(1)
            self.model.setHeaderData(0, Qt.Orientation.Horizontal, "instr")
            self.model.appendRow([
                QStandardItem("Not Loaded Yet"),
            ])
            self.tree.resizeColumnToContents(0)
            return

        if isinstance(il_function, LowLevelILFunction):
            self.model.setColumnCount(13)
            self.model.setHeaderData(0, Qt.Orientation.Horizontal, "instr")
            self.model.setHeaderData(1, Qt.Orientation.Horizontal, "expr")
            self.model.setHeaderData(2, Qt.Orientation.Horizontal, "addr")
            self.model.setHeaderData(3, Qt.Orientation.Horizontal, "text")
            self.model.setHeaderData(4, Qt.Orientation.Horizontal, "operation")
            self.model.setHeaderData(5, Qt.Orientation.Horizontal, "operand[0]")
            self.model.setHeaderData(6, Qt.Orientation.Horizontal, "operand[1]")
            self.model.setHeaderData(7, Qt.Orientation.Horizontal, "operand[2]")
            self.model.setHeaderData(8, Qt.Orientation.Horizontal, "operand[3]")
            self.model.setHeaderData(9, Qt.Orientation.Horizontal, "attr")
            self.model.setHeaderData(10, Qt.Orientation.Horizontal, "size")
            self.model.setHeaderData(11, Qt.Orientation.Horizontal, "flags")
            self.model.setHeaderData(12, Qt.Orientation.Horizontal, "src op")

            monospace_font = getMonospaceFont(self)

            def monospace(item):
                item.setFont(monospace_font)
                return item

            def header(row):
                for item in row:
                    item: QStandardItem
                    item.setBackground(self.palette().alternateBase())
                return row

            expr_tree = QStandardItem("")
            self.model.invisibleRootItem().appendRow(header([
                expr_tree,
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem("Expressions"),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
            ]))

            expr_indices = {}
            insn_count = len(il_function)
            for i in range(insn_count):
                insn = il_function[i]
                expr_indices[insn.expr_index] = i

            expr_count = _binaryninjacore.BNGetLowLevelILExprCount(il_function.handle)
            for i in range(expr_count):
                expr = LowLevelILInstruction.create(il_function, i)
                if expr.operation < len(LowLevelILOperation):
                    op_name = LowLevelILOperation(expr.operation).name
                else:
                    op_name = f"BAD ({expr.operation})"

                if i in expr_indices:
                    instr_index = expr_indices[i]
                else:
                    instr_index = ""

                expr_tree.appendRow([
                    monospace(QStandardItem(f"{instr_index}")),
                    monospace(QStandardItem(f"{i}")),
                    monospace(QStandardItem(f"{expr.address:#x}")),
                    monospace(QStandardItem(f"{expr}")),
                    monospace(QStandardItem(f"{op_name}")),
                    monospace(QStandardItem(f"{expr.instr.operands[0]:#x}")),
                    monospace(QStandardItem(f"{expr.instr.operands[1]:#x}")),
                    monospace(QStandardItem(f"{expr.instr.operands[2]:#x}")),
                    monospace(QStandardItem(f"{expr.instr.operands[3]:#x}")),
                    monospace(QStandardItem(f"{expr.attributes}")),
                    monospace(QStandardItem(f"{expr.size:#x}")),
                    monospace(QStandardItem(f"{expr.flags}")),
                    monospace(QStandardItem(f"{expr.source_operand:#x}")),
                ])

            insn_tree = QStandardItem("")
            self.model.invisibleRootItem().appendRow(header([
                insn_tree,
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem("Instructions"),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
            ]))

            insn_count = len(il_function)
            for i in range(insn_count):
                insn = il_function[i]
                if insn.operation < len(LowLevelILOperation):
                    op_name = LowLevelILOperation(insn.operation).name
                else:
                    op_name = f"BAD ({insn.operation})"
                insn_tree.appendRow([
                    monospace(QStandardItem(f"{i}")),
                    monospace(QStandardItem(f"{insn.expr_index}")),
                    monospace(QStandardItem(f"{insn.address:#x}")),
                    monospace(QStandardItem(f"{insn}")),
                    monospace(QStandardItem(f"{op_name}")),
                    monospace(QStandardItem(f"{insn.instr.operands[0]:#x}")),
                    monospace(QStandardItem(f"{insn.instr.operands[1]:#x}")),
                    monospace(QStandardItem(f"{insn.instr.operands[2]:#x}")),
                    monospace(QStandardItem(f"{insn.instr.operands[3]:#x}")),
                    monospace(QStandardItem(f"{insn.attributes}")),
                    monospace(QStandardItem(f"{insn.size:#x}")),
                    monospace(QStandardItem(f"{insn.flags}")),
                    monospace(QStandardItem(f"{insn.source_operand:#x}")),
                ])

            bb_tree = QStandardItem("")
            self.model.invisibleRootItem().appendRow(header([
                bb_tree,
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem("Basic Blocks"),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
            ]))
            bb_count = len(list(il_function.basic_blocks))
            for i in range(bb_count):
                bb = list(il_function.basic_blocks)[i]
                tree = QStandardItem("")
                bb_tree.appendRow(header([
                    monospace(tree),
                    monospace(QStandardItem()),
                    monospace(QStandardItem()),
                    monospace(QStandardItem(f"Block {bb.start} -> {bb.end}")),
                    monospace(QStandardItem()),
                    monospace(QStandardItem()),
                    monospace(QStandardItem()),
                    monospace(QStandardItem()),
                    monospace(QStandardItem()),
                    monospace(QStandardItem()),
                    monospace(QStandardItem()),
                    monospace(QStandardItem()),
                    monospace(QStandardItem()),
                ]))

                for j in range(bb.start, bb.end):
                    insn = il_function[j]
                    if insn.operation < len(LowLevelILOperation):
                        op_name = LowLevelILOperation(insn.operation).name
                    else:
                        op_name = f"BAD ({insn.operation})"
                    tree.appendRow([
                        monospace(QStandardItem(f"{j}")),
                        monospace(QStandardItem(f"{insn.expr_index}")),
                        monospace(QStandardItem(f"{insn.address:#x}")),
                        monospace(QStandardItem(f"{insn}")),
                        monospace(QStandardItem(f"{op_name}")),
                        monospace(QStandardItem(f"{insn.instr.operands[0]:#x}")),
                        monospace(QStandardItem(f"{insn.instr.operands[1]:#x}")),
                        monospace(QStandardItem(f"{insn.instr.operands[2]:#x}")),
                        monospace(QStandardItem(f"{insn.instr.operands[3]:#x}")),
                        monospace(QStandardItem(f"{insn.attributes}")),
                        monospace(QStandardItem(f"{insn.size:#x}")),
                        monospace(QStandardItem(f"{insn.flags}")),
                        monospace(QStandardItem(f"{insn.source_operand:#x}")),
                    ])

            self.tree.expandToDepth(1)

            self.tree.resizeColumnToContents(0)
            self.tree.resizeColumnToContents(1)
            self.tree.resizeColumnToContents(2)
            self.tree.resizeColumnToContents(3)
            self.tree.resizeColumnToContents(4)
            self.tree.resizeColumnToContents(5)
            self.tree.resizeColumnToContents(6)
            self.tree.resizeColumnToContents(7)
            self.tree.resizeColumnToContents(8)
            self.tree.resizeColumnToContents(9)
            self.tree.resizeColumnToContents(10)
            self.tree.resizeColumnToContents(11)
            self.tree.resizeColumnToContents(12)

        if isinstance(il_function, MediumLevelILFunction):
            self.model.setColumnCount(14)
            self.model.setHeaderData(0, Qt.Orientation.Horizontal, "instr")
            self.model.setHeaderData(1, Qt.Orientation.Horizontal, "expr")
            self.model.setHeaderData(2, Qt.Orientation.Horizontal, "addr")
            self.model.setHeaderData(3, Qt.Orientation.Horizontal, "text")
            self.model.setHeaderData(4, Qt.Orientation.Horizontal, "type")
            self.model.setHeaderData(5, Qt.Orientation.Horizontal, "operation")
            self.model.setHeaderData(6, Qt.Orientation.Horizontal, "operand[0]")
            self.model.setHeaderData(7, Qt.Orientation.Horizontal, "operand[1]")
            self.model.setHeaderData(8, Qt.Orientation.Horizontal, "operand[2]")
            self.model.setHeaderData(9, Qt.Orientation.Horizontal, "operand[3]")
            self.model.setHeaderData(10, Qt.Orientation.Horizontal, "operand[4]")
            self.model.setHeaderData(11, Qt.Orientation.Horizontal, "attr")
            self.model.setHeaderData(12, Qt.Orientation.Horizontal, "size")
            self.model.setHeaderData(13, Qt.Orientation.Horizontal, "src op")

            monospace_font = getMonospaceFont(self)

            def monospace(item):
                item.setFont(monospace_font)
                return item

            def header(row):
                for item in row:
                    item: QStandardItem
                    item.setBackground(self.palette().alternateBase())
                return row

            expr_tree = QStandardItem("")
            self.model.invisibleRootItem().appendRow(header([
                expr_tree,
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem("Expressions"),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
            ]))

            expr_indices = {}
            insn_count = len(il_function)
            for i in range(insn_count):
                insn = il_function[i]
                expr_indices[insn.expr_index] = i

            expr_count = _binaryninjacore.BNGetMediumLevelILExprCount(il_function.handle)
            for i in range(expr_count):
                expr = MediumLevelILInstruction.create(il_function, i)
                if expr.operation < len(MediumLevelILOperation):
                    op_text = str(expr)
                    op_type = str(il_function.get_expr_type(i))
                    op_name = MediumLevelILOperation(expr.operation).name
                else:
                    op_text = "BAD"
                    op_type = "BAD"
                    op_name = f"BAD ({expr.operation})"

                if i in expr_indices:
                    instr_index = expr_indices[i]
                else:
                    instr_index = ""

                expr_tree.appendRow([
                    monospace(QStandardItem(f"{instr_index}")),
                    monospace(QStandardItem(f"{i}")),
                    monospace(QStandardItem(f"{expr.address:#x}")),
                    monospace(QStandardItem(f"{op_text}")),
                    monospace(QStandardItem(f"{op_type}")),
                    monospace(QStandardItem(f"{op_name}")),
                    monospace(QStandardItem(f"{expr.instr.operands[0]:#x}")),
                    monospace(QStandardItem(f"{expr.instr.operands[1]:#x}")),
                    monospace(QStandardItem(f"{expr.instr.operands[2]:#x}")),
                    monospace(QStandardItem(f"{expr.instr.operands[3]:#x}")),
                    monospace(QStandardItem(f"{expr.instr.operands[4]:#x}")),
                    monospace(QStandardItem(f"{expr.attributes}")),
                    monospace(QStandardItem(f"{expr.size:#x}")),
                    monospace(QStandardItem(f"{expr.source_operand:#x}")),
                ])

            insn_tree = QStandardItem("")
            self.model.invisibleRootItem().appendRow(header([
                insn_tree,
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem("Instructions"),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
            ]))

            insn_count = len(il_function)
            for i in range(insn_count):
                insn = il_function[i]
                if insn.operation < len(MediumLevelILOperation):
                    op_text = str(insn)
                    op_type = str(il_function.get_expr_type(i))
                    op_name = MediumLevelILOperation(insn.operation).name
                else:
                    op_text = "BAD"
                    op_type = "BAD"
                    op_name = f"BAD ({insn.operation})"
                insn_tree.appendRow([
                    monospace(QStandardItem(f"{i}")),
                    monospace(QStandardItem(f"{insn.expr_index}")),
                    monospace(QStandardItem(f"{insn.address:#x}")),
                    monospace(QStandardItem(f"{op_text}")),
                    monospace(QStandardItem(f"{op_type}")),
                    monospace(QStandardItem(f"{op_name}")),
                    monospace(QStandardItem(f"{insn.instr.operands[0]:#x}")),
                    monospace(QStandardItem(f"{insn.instr.operands[1]:#x}")),
                    monospace(QStandardItem(f"{insn.instr.operands[2]:#x}")),
                    monospace(QStandardItem(f"{insn.instr.operands[3]:#x}")),
                    monospace(QStandardItem(f"{insn.instr.operands[4]:#x}")),
                    monospace(QStandardItem(f"{insn.attributes}")),
                    monospace(QStandardItem(f"{insn.size:#x}")),
                    monospace(QStandardItem(f"{insn.source_operand:#x}")),
                ])

            bb_tree = QStandardItem("")
            self.model.invisibleRootItem().appendRow(header([
                bb_tree,
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem("Basic Blocks"),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
            ]))
            bb_count = len(list(il_function.basic_blocks))
            for i in range(bb_count):
                bb = list(il_function.basic_blocks)[i]
                tree = QStandardItem("")
                bb_tree.appendRow(header([
                    monospace(tree),
                    monospace(QStandardItem()),
                    monospace(QStandardItem()),
                    monospace(QStandardItem(f"Block {bb.start} -> {bb.end}")),
                    monospace(QStandardItem()),
                    monospace(QStandardItem()),
                    monospace(QStandardItem()),
                    monospace(QStandardItem()),
                    monospace(QStandardItem()),
                    monospace(QStandardItem()),
                    monospace(QStandardItem()),
                    monospace(QStandardItem()),
                    monospace(QStandardItem()),
                    monospace(QStandardItem()),
                ]))

                for j in range(bb.start, bb.end):
                    insn = il_function[j]
                    if insn.operation < len(MediumLevelILOperation):
                        op_text = str(insn)
                        op_type = str(il_function.get_expr_type(j))
                        op_name = MediumLevelILOperation(insn.operation).name
                    else:
                        op_text = "BAD"
                        op_type = "BAD"
                        op_name = f"BAD ({insn.operation})"
                    tree.appendRow([
                        monospace(QStandardItem(f"{j}")),
                        monospace(QStandardItem(f"{insn.expr_index}")),
                        monospace(QStandardItem(f"{insn.address:#x}")),
                        monospace(QStandardItem(f"{op_text}")),
                        monospace(QStandardItem(f"{op_type}")),
                        monospace(QStandardItem(f"{op_name}")),
                        monospace(QStandardItem(f"{insn.instr.operands[0]:#x}")),
                        monospace(QStandardItem(f"{insn.instr.operands[1]:#x}")),
                        monospace(QStandardItem(f"{insn.instr.operands[2]:#x}")),
                        monospace(QStandardItem(f"{insn.instr.operands[3]:#x}")),
                        monospace(QStandardItem(f"{insn.instr.operands[4]:#x}")),
                        monospace(QStandardItem(f"{insn.attributes}")),
                        monospace(QStandardItem(f"{insn.size:#x}")),
                        monospace(QStandardItem(f"{insn.source_operand:#x}")),
                    ])

            self.tree.expandToDepth(1)

            self.tree.resizeColumnToContents(0)
            self.tree.resizeColumnToContents(1)
            self.tree.resizeColumnToContents(2)
            self.tree.resizeColumnToContents(3)
            self.tree.resizeColumnToContents(4)
            self.tree.resizeColumnToContents(5)
            self.tree.resizeColumnToContents(6)
            self.tree.resizeColumnToContents(7)
            self.tree.resizeColumnToContents(8)
            self.tree.resizeColumnToContents(9)
            self.tree.resizeColumnToContents(10)
            self.tree.resizeColumnToContents(11)
            self.tree.resizeColumnToContents(12)
            self.tree.resizeColumnToContents(13)

        if isinstance(il_function, HighLevelILFunction):
            self.model.setColumnCount(14)
            self.model.setHeaderData(0, Qt.Orientation.Horizontal, "instr")
            self.model.setHeaderData(1, Qt.Orientation.Horizontal, "expr")
            self.model.setHeaderData(2, Qt.Orientation.Horizontal, "addr")
            self.model.setHeaderData(3, Qt.Orientation.Horizontal, "text")
            self.model.setHeaderData(4, Qt.Orientation.Horizontal, "type")
            self.model.setHeaderData(5, Qt.Orientation.Horizontal, "operation")
            self.model.setHeaderData(6, Qt.Orientation.Horizontal, "operand[0]")
            self.model.setHeaderData(7, Qt.Orientation.Horizontal, "operand[1]")
            self.model.setHeaderData(8, Qt.Orientation.Horizontal, "operand[2]")
            self.model.setHeaderData(9, Qt.Orientation.Horizontal, "operand[3]")
            self.model.setHeaderData(10, Qt.Orientation.Horizontal, "operand[4]")
            self.model.setHeaderData(11, Qt.Orientation.Horizontal, "attr")
            self.model.setHeaderData(12, Qt.Orientation.Horizontal, "size")
            self.model.setHeaderData(13, Qt.Orientation.Horizontal, "src op")

            monospace_font = getMonospaceFont(self)

            def monospace(item):
                item.setFont(monospace_font)
                return item

            def header(row):
                for item in row:
                    item: QStandardItem
                    item.setBackground(self.palette().alternateBase())
                return row

            expr_tree = QStandardItem("")
            self.model.invisibleRootItem().appendRow(header([
                expr_tree,
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem("Expressions"),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
            ]))

            expr_indices = {}
            insn_count = len(il_function)
            for i in range(insn_count):
                insn = il_function[i]
                expr_indices[insn.expr_index] = i

            expr_count = _binaryninjacore.BNGetHighLevelILExprCount(il_function.handle)
            for i in range(expr_count):
                expr = HighLevelILInstruction.create(il_function, i)
                if expr.operation < len(HighLevelILOperation):
                    op_text = str(expr)
                    op_type = str(il_function.get_expr_type(i))
                    op_name = HighLevelILOperation(expr.operation).name
                else:
                    op_text = "BAD"
                    op_type = "BAD"
                    op_name = f"BAD ({expr.operation})"

                if i in expr_indices:
                    instr_index = expr_indices[i]
                else:
                    instr_index = ""

                expr_tree.appendRow([
                    monospace(QStandardItem(f"{instr_index}")),
                    monospace(QStandardItem(f"{i}")),
                    monospace(QStandardItem(f"{expr.address:#x}")),
                    monospace(QStandardItem(f"{op_text}")),
                    monospace(QStandardItem(f"{op_type}")),
                    monospace(QStandardItem(f"{op_name}")),
                    monospace(QStandardItem(f"{expr.core_instr.operands[0]:#x}")),
                    monospace(QStandardItem(f"{expr.core_instr.operands[1]:#x}")),
                    monospace(QStandardItem(f"{expr.core_instr.operands[2]:#x}")),
                    monospace(QStandardItem(f"{expr.core_instr.operands[3]:#x}")),
                    monospace(QStandardItem(f"{expr.core_instr.operands[4]:#x}")),
                    monospace(QStandardItem(f"{expr.attributes}")),
                    monospace(QStandardItem(f"{expr.size:#x}")),
                    monospace(QStandardItem(f"{expr.source_operand:#x}")),
                ])

            insn_tree = QStandardItem("")
            self.model.invisibleRootItem().appendRow(header([
                insn_tree,
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem("Instructions"),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
            ]))

            insn_count = len(il_function)
            for i in range(insn_count):
                insn = il_function[i]
                if insn.operation < len(HighLevelILOperation):
                    op_text = str(insn)
                    op_type = str(il_function.get_expr_type(i))
                    op_name = HighLevelILOperation(insn.operation).name
                else:
                    op_text = "BAD"
                    op_type = "BAD"
                    op_name = f"BAD ({insn.operation})"
                insn_tree.appendRow([
                    monospace(QStandardItem(f"{i}")),
                    monospace(QStandardItem(f"{insn.expr_index}")),
                    monospace(QStandardItem(f"{insn.address:#x}")),
                    monospace(QStandardItem(f"{op_text}")),
                    monospace(QStandardItem(f"{op_type}")),
                    monospace(QStandardItem(f"{op_name}")),
                    monospace(QStandardItem(f"{insn.core_instr.operands[0]:#x}")),
                    monospace(QStandardItem(f"{insn.core_instr.operands[1]:#x}")),
                    monospace(QStandardItem(f"{insn.core_instr.operands[2]:#x}")),
                    monospace(QStandardItem(f"{insn.core_instr.operands[3]:#x}")),
                    monospace(QStandardItem(f"{insn.core_instr.operands[4]:#x}")),
                    monospace(QStandardItem(f"{insn.attributes}")),
                    monospace(QStandardItem(f"{insn.size:#x}")),
                    monospace(QStandardItem(f"{insn.source_operand:#x}")),
                ])

            bb_tree = QStandardItem("")
            self.model.invisibleRootItem().appendRow(header([
                bb_tree,
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem("Basic Blocks"),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
            ]))
            bb_count = len(list(il_function.basic_blocks))
            for i in range(bb_count):
                bb = list(il_function.basic_blocks)[i]
                tree = QStandardItem("")
                bb_tree.appendRow(header([
                    monospace(tree),
                    monospace(QStandardItem()),
                    monospace(QStandardItem()),
                    monospace(QStandardItem(f"Block {bb.start} -> {bb.end}")),
                    monospace(QStandardItem()),
                    monospace(QStandardItem()),
                    monospace(QStandardItem()),
                    monospace(QStandardItem()),
                    monospace(QStandardItem()),
                    monospace(QStandardItem()),
                    monospace(QStandardItem()),
                    monospace(QStandardItem()),
                    monospace(QStandardItem()),
                    monospace(QStandardItem()),
                ]))

                for j in range(bb.start, bb.end):
                    insn = il_function[j]
                    if insn.operation < len(HighLevelILOperation):
                        op_text = str(insn)
                        op_type = str(il_function.get_expr_type(j))
                        op_name = HighLevelILOperation(insn.operation).name
                    else:
                        op_text = "BAD"
                        op_type = "BAD"
                        op_name = f"BAD ({insn.operation})"
                    tree.appendRow([
                        monospace(QStandardItem(f"{j}")),
                        monospace(QStandardItem(f"{insn.expr_index}")),
                        monospace(QStandardItem(f"{insn.address:#x}")),
                        monospace(QStandardItem(f"{op_text}")),
                        monospace(QStandardItem(f"{op_type}")),
                        monospace(QStandardItem(f"{op_name}")),
                        monospace(QStandardItem(f"{insn.core_instr.operands[0]:#x}")),
                        monospace(QStandardItem(f"{insn.core_instr.operands[1]:#x}")),
                        monospace(QStandardItem(f"{insn.core_instr.operands[2]:#x}")),
                        monospace(QStandardItem(f"{insn.core_instr.operands[3]:#x}")),
                        monospace(QStandardItem(f"{insn.core_instr.operands[4]:#x}")),
                        monospace(QStandardItem(f"{insn.attributes}")),
                        monospace(QStandardItem(f"{insn.size:#x}")),
                        monospace(QStandardItem(f"{insn.source_operand:#x}")),
                    ])

            self.tree.expandToDepth(1)

            self.tree.resizeColumnToContents(0)
            self.tree.resizeColumnToContents(1)
            self.tree.resizeColumnToContents(2)
            self.tree.resizeColumnToContents(3)
            self.tree.resizeColumnToContents(4)
            self.tree.resizeColumnToContents(5)
            self.tree.resizeColumnToContents(6)
            self.tree.resizeColumnToContents(7)
            self.tree.resizeColumnToContents(8)
            self.tree.resizeColumnToContents(9)
            self.tree.resizeColumnToContents(10)
            self.tree.resizeColumnToContents(11)
            self.tree.resizeColumnToContents(12)
            self.tree.resizeColumnToContents(13)


class ILSidebarWidgetType(SidebarWidgetType):
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
        p.drawText(QRectF(0, 0, 56, 56), Qt.AlignCenter, "IL")
        p.end()

        SidebarWidgetType.__init__(self, icon, "IL Inspector")

    def createWidget(self, frame: ViewFrame, data: BinaryView):
        return ILSidebarWidget("IL Inspector", frame, data)


Sidebar.addSidebarWidgetType(ILSidebarWidgetType())
