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
from typing import List, Any, Optional

import binaryninja
from PySide6.QtCore import Qt, QRectF, QAbstractItemModel, QObject, QModelIndex, QTimer
from PySide6.QtGui import QImage, QPainter, QFont, QColor, QShowEvent, QStandardItemModel, \
    QStandardItem
from PySide6.QtWidgets import QVBoxLayout, QTreeView
from binaryninja import BinaryView, LinearViewObject, FunctionGraphType, \
    LinearDisassemblyLine, InstructionTextToken, Function, DisassemblySettings, \
    LowLevelILFunction, BasicBlock, FlowGraph, FlowGraphNode, execute_on_main_thread, \
    InstructionTextTokenType, InstructionTextTokenContext, FunctionViewType
from binaryninjaui import SidebarWidget, SidebarWidgetType, Sidebar, UIContext, \
    UIContextNotification, ViewFrame, View, ViewLocation, FileContext, getMonospaceFont


# TODO: Linear token inspection too
# TODO: Expand all array properties into subtrees
# TODO: Lazy loading?
# TODO: Create tree off-main and then set on main


class GraphSidebarWidget(SidebarWidget, UIContextNotification):
    def __init__(self, name, frame: ViewFrame, data: BinaryView):
        SidebarWidget.__init__(self, name)
        UIContextNotification.__init__(self)
        self.setParent(frame)
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
        self.tree.clicked.connect(self.item_clicked)

        self.dirty = True
        self.updating = False

        self.graph: Optional[FlowGraph] = None
        self.graph_type = FunctionViewType(FunctionGraphType.NormalFunctionGraph)
        self.current_address = 0
        self.current_function: Optional[Function] = None
        self.disassembly_settings: Optional[DisassemblySettings] = None

        self.layout.addWidget(self.tree)
        view = self.frame.getCurrentViewInterface()

        if view is not None:
            self.graph_type = view.getILViewType()
            self.current_address = view.getCurrentOffset()
            self.current_function = view.getCurrentFunction()
            self.disassembly_settings = view.getDisassemblySettings()

        UIContext.registerNotification(self)

        self.update_tree()

    def __del__(self):
        UIContext.unregisterNotification(self)

    def notifyOffsetChanged(self, offset):
        pass

    def notifyViewChanged(self, view_frame):
        pass

    def contextMenuEvent(self, event):
        self.m_contextMenuManager.show(self.m_menu, self.m_actionHandler)

    def showEvent(self, event: QShowEvent) -> None:
        if self.dirty:
            self.update_tree()

    def OnViewChange(self, context: UIContext, frame: ViewFrame, type: str):
        if frame:
            self.maybe_update(frame.getCurrentViewInterface())
        else:
            self.maybe_update(None)

    def OnAddressChange(self, context: UIContext, frame: ViewFrame, view: View, location: ViewLocation):
        self.maybe_update(view)

    def maybe_update(self, view: View):
        if view is not None:
            old_state = (
                self.graph_type,
                self.current_function.start,
            )

            self.graph_type = view.getILViewType()
            self.disassembly_settings = view.getDisassemblySettings()
            self.current_address = view.getCurrentOffset()
            self.current_function = view.getCurrentFunction()

            new_state = (
                self.graph_type,
                self.current_function.start,
            )

            if old_state != new_state:
                if self.isVisible():
                    self.update_tree()
                else:
                    self.dirty = True

    def item_clicked(self, item: QModelIndex):
        pass

    def update_tree(self):
        if self.updating:
            return

        view_type = 'graph'

        func = None
        graph = None
        item_type = None
        if self.current_function is not None:
            if self.graph_type.view_type == FunctionGraphType.LiftedILFunctionGraph:
                func = self.current_function.lifted_il_if_available
                if func:
                    graph = func.create_graph(self.disassembly_settings)
                    item_type = 'llil'
            elif self.graph_type.view_type == FunctionGraphType.LowLevelILFunctionGraph:
                func = self.current_function.llil_if_available
                if func:
                    graph = func.create_graph(self.disassembly_settings)
                    item_type = 'llil'
            elif self.graph_type.view_type == FunctionGraphType.LowLevelILSSAFormFunctionGraph:
                func = self.current_function.llil_if_available.ssa_form
                if func:
                    graph = func.create_graph(self.disassembly_settings)
                    item_type = 'llil'
            elif self.graph_type.view_type == FunctionGraphType.MediumLevelILFunctionGraph:
                func = self.current_function.mlil_if_available
                if func:
                    graph = func.create_graph(self.disassembly_settings)
                    item_type = 'mlil'
            elif self.graph_type.view_type == FunctionGraphType.MediumLevelILSSAFormFunctionGraph:
                func = self.current_function.mlil_if_available.ssa_form
                if func:
                    graph = func.create_graph(self.disassembly_settings)
                    item_type = 'mlil'
            elif self.graph_type.view_type == FunctionGraphType.MappedMediumLevelILFunctionGraph:
                func = self.current_function.mmlil_if_available
                if func:
                    graph = func.create_graph(self.disassembly_settings)
                    item_type = 'mlil'
            elif self.graph_type.view_type == FunctionGraphType.MappedMediumLevelILSSAFormFunctionGraph:
                func = self.current_function.mmlil_if_available.ssa_form
                if func:
                    graph = func.create_graph(self.disassembly_settings)
                    item_type = 'mlil'
            elif self.graph_type.view_type == FunctionGraphType.HighLevelILFunctionGraph:
                func = self.current_function.hlil_if_available
                if func:
                    graph = func.create_graph(self.disassembly_settings)
                    item_type = 'hlil'
            elif self.graph_type.view_type == FunctionGraphType.HighLevelILSSAFormFunctionGraph:
                func = self.current_function.hlil_if_available.ssa_form
                if func:
                    graph = func.create_graph(self.disassembly_settings)
                    item_type = 'hlil'
            elif self.graph_type.view_type == FunctionGraphType.HighLevelLanguageRepresentationFunctionGraph:
                func = self.current_function.hlil_if_available
                if func:
                    graph = self.current_function.create_graph(self.graph_type, self.disassembly_settings)
                    item_type = 'langrep'
            else:
                func = self.current_function
                if func:
                    graph = self.current_function.create_graph(FunctionGraphType.NormalFunctionGraph, self.disassembly_settings)
                    item_type = 'disasm'

        self.model.clear()
        self.model.setRowCount(1)
        self.model.setColumnCount(2)

        self.graph = graph
        self.tree.resizeColumnToContents(0)

        if self.graph:
            self.updating = True
            self.graph.layout(lambda: execute_on_main_thread(lambda: graph_layout_finished()))
        else:
            self.model.setItem(0, 0, QStandardItem("No Graph"))
            self.model.setItem(0, 1, QStandardItem(""))

        monospace_font = getMonospaceFont(self)

        def monospace(item):
            item.setFont(monospace_font)
            return item

        def graph_layout_finished():
            graph_tree = QStandardItem("Blocks")
            self.model.setItem(0, 0, graph_tree)
            self.model.setItem(0, 1, monospace(QStandardItem("")))

            for i, node in enumerate(self.graph.nodes):
                node: FlowGraphNode
                block = node.basic_block

                if item_type == 'disasm':
                    if block is not None:
                        if block.arch is not None:
                            block_text = f'Block {i}'
                            block_addr_text = f'{block.arch.name} 0x{block.start:x} -> 0x{block.end:x}'
                        else:
                            block_text = f'Block {i}'
                            block_addr_text = f'0x{block.start:x} -> 0x{block.end:x}'
                    else:
                        block_text = f'Node {i}'
                        block_addr_text = ''

                else:
                    if block is not None:
                        if block.arch is not None:
                            block_text = f'Block {i}'
                            block_addr_text = f'{block.arch.name} {block.start} -> {block.end}'
                        else:
                            block_text = f'Block {i}'
                            block_addr_text = f'{block.start} -> {block.end}'
                    else:
                        block_text = f'Node {i}'
                        block_addr_text = ''

                node_tree = QStandardItem(block_text)
                for line in node.lines:
                    line_insn_text = ''.join(token.text for token in line.tokens)
                    if item_type == 'disasm':
                        line_addr_text = f'0x{line.address:x}'
                    else:
                        line_addr_text = f'0x{line.address:x}'
                    line_tree = QStandardItem(line_addr_text)

                    for token in line.tokens:
                        token_tree = QStandardItem(token.type.name)
                        token_tree.appendRow([
                            QStandardItem("type"),
                            monospace(QStandardItem(InstructionTextTokenType(token.type).name))
                        ])
                        token_tree.appendRow([
                            QStandardItem("text"),
                            monospace(QStandardItem(str(token.text)))
                        ])
                        token_tree.appendRow([
                            QStandardItem("value"),
                            monospace(QStandardItem(hex(token.value)))
                        ])
                        token_tree.appendRow([
                            QStandardItem("size"),
                            monospace(QStandardItem(hex(token.size)))
                        ])
                        token_tree.appendRow([
                            QStandardItem("operand"),
                            monospace(QStandardItem(hex(token.operand)))
                        ])
                        token_tree.appendRow([
                            QStandardItem("context"),
                            monospace(QStandardItem(InstructionTextTokenContext(token.context).name))
                        ])
                        token_tree.appendRow([
                            QStandardItem("address"),
                            monospace(QStandardItem(hex(token.address)))
                        ])
                        token_tree.appendRow([
                            QStandardItem("confidence"),
                            monospace(QStandardItem(str(token.confidence)))
                        ])
                        token_tree.appendRow([
                            QStandardItem("typeNames"),
                            monospace(QStandardItem(str(token.typeNames)))
                        ])
                        token_tree.appendRow([
                            QStandardItem("width"),
                            monospace(QStandardItem(hex(token.width)))
                        ])
                        line_tree.appendRow([
                            token_tree,
                            monospace(QStandardItem(token.text))
                        ])

                    line_properties = QStandardItem("Properties...")
                    line_properties.appendRow([
                        QStandardItem("highlight"),
                        monospace(QStandardItem(str(line.highlight)))
                    ])
                    line_properties.appendRow([
                        QStandardItem("address"),
                        monospace(QStandardItem(hex(line.address)))
                    ])
                    line_properties.appendRow([
                        QStandardItem("il_instruction"),
                        monospace(QStandardItem(str(line.il_instruction)))
                    ])
                    line_tree.appendRow([
                        line_properties,
                        monospace(QStandardItem(""))
                    ])
                    node_tree.appendRow([
                        line_tree,
                        monospace(QStandardItem(line_insn_text))
                    ])

                node_properties = QStandardItem("Properties...")
                node_properties.appendRow([
                    QStandardItem("x"),
                    monospace(QStandardItem(str(node.x)))
                ])
                node_properties.appendRow([
                    QStandardItem("y"),
                    monospace(QStandardItem(str(node.y)))
                ])
                node_properties.appendRow([
                    QStandardItem("width"),
                    monospace(QStandardItem(str(node.width)))
                ])
                node_properties.appendRow([
                    QStandardItem("height"),
                    monospace(QStandardItem(str(node.height)))
                ])
                node_properties.appendRow([
                    QStandardItem("outgoing_edges"),
                    monospace(QStandardItem(str(node.outgoing_edges)))
                ])
                node_properties.appendRow([
                    QStandardItem("incoming_edges"),
                    monospace(QStandardItem(str(node.incoming_edges)))
                ])
                node_properties.appendRow([
                    QStandardItem("highlight"),
                    monospace(QStandardItem(str(node.highlight)))
                ])
                if block is not None:
                    node_properties.appendRow([
                        QStandardItem("block.instruction_count"),
                        monospace(QStandardItem(hex(block.instruction_count)))
                    ])
                    node_properties.appendRow([
                        QStandardItem("block.function"),
                        monospace(QStandardItem(str(block.function)))
                    ])
                    node_properties.appendRow([
                        QStandardItem("block.view"),
                        monospace(QStandardItem(str(block.view)))
                    ])
                    node_properties.appendRow([
                        QStandardItem("block.arch"),
                        monospace(QStandardItem(str(block.arch)))
                    ])
                    node_properties.appendRow([
                        QStandardItem("block.start"),
                        monospace(QStandardItem(hex(block.start)))
                    ])
                    node_properties.appendRow([
                        QStandardItem("block.end"),
                        monospace(QStandardItem(hex(block.end)))
                    ])
                    node_properties.appendRow([
                        QStandardItem("block.length"),
                        monospace(QStandardItem(hex(block.length)))
                    ])
                    node_properties.appendRow([
                        QStandardItem("block.index"),
                        monospace(QStandardItem(hex(block.index)))
                    ])
                    node_properties.appendRow([
                        QStandardItem("block.has_undetermined_outgoing_edges"),
                        monospace(QStandardItem(str(block.has_undetermined_outgoing_edges)))
                    ])
                    node_properties.appendRow([
                        QStandardItem("block.can_exit"),
                        monospace(QStandardItem(str(block.can_exit)))
                    ])
                    node_properties.appendRow([
                        QStandardItem("block.has_invalid_instructions"),
                        monospace(QStandardItem(str(block.has_invalid_instructions)))
                    ])
                    node_properties.appendRow([
                        QStandardItem("block.dominators"),
                        monospace(QStandardItem(str(block.dominators)))
                    ])
                    node_properties.appendRow([
                        QStandardItem("block.post_dominators"),
                        monospace(QStandardItem(str(block.post_dominators)))
                    ])
                    node_properties.appendRow([
                        QStandardItem("block.strict_dominators"),
                        monospace(QStandardItem(str(block.strict_dominators)))
                    ])
                    node_properties.appendRow([
                        QStandardItem("block.immediate_dominator"),
                        monospace(QStandardItem(str(block.immediate_dominator)))
                    ])
                    node_properties.appendRow([
                        QStandardItem("block.immediate_post_dominator"),
                        monospace(QStandardItem(str(block.immediate_post_dominator)))
                    ])
                    node_properties.appendRow([
                        QStandardItem("block.dominator_tree_children"),
                        monospace(QStandardItem(str(block.dominator_tree_children)))
                    ])
                    node_properties.appendRow([
                        QStandardItem("block.post_dominator_tree_children"),
                        monospace(QStandardItem(str(block.post_dominator_tree_children)))
                    ])
                    node_properties.appendRow([
                        QStandardItem("block.dominance_frontier"),
                        monospace(QStandardItem(str(block.dominance_frontier)))
                    ])
                    node_properties.appendRow([
                        QStandardItem("block.post_dominance_frontier"),
                        monospace(QStandardItem(str(block.post_dominance_frontier)))
                    ])
                    node_properties.appendRow([
                        QStandardItem("block.annotations"),
                        monospace(QStandardItem(str(block.annotations)))
                    ])
                node_tree.appendRow([
                    node_properties,
                    monospace(QStandardItem(""))
                ])
                graph_tree.appendRow([
                    node_tree,
                    monospace(QStandardItem(block_addr_text))
                ])

            self.tree.expandToDepth(1)

            self.tree.resizeColumnToContents(0)
            self.tree.resizeColumnToContents(1)
            self.dirty = False
            self.updating = False


class GraphSidebarWidgetType(SidebarWidgetType):
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
        p.drawText(QRectF(0, 0, 56, 56), Qt.AlignCenter, "G")
        p.end()

        SidebarWidgetType.__init__(self, icon, "Graph Inspector")

    def createWidget(self, frame: ViewFrame, data: BinaryView):
        return GraphSidebarWidget("Graph Inspector", frame, data)


Sidebar.addSidebarWidgetType(GraphSidebarWidgetType())
