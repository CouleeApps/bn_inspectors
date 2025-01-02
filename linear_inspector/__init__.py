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

from PySide6.QtCore import Qt, QRectF, QAbstractItemModel, QObject, QModelIndex
from PySide6.QtGui import QImage, QPainter, QFont, QColor, QShowEvent
from PySide6.QtWidgets import QVBoxLayout, QTreeView
from binaryninja import BinaryView, LinearViewObject, FunctionGraphType, \
    LinearDisassemblyLine, InstructionTextToken, FunctionViewType, \
    InstructionTextTokenType, LinearDisassemblyLineType, InstructionTextTokenContext
from binaryninjaui import SidebarWidget, SidebarWidgetType, Sidebar, UIContext, \
    UIContextNotification, ViewFrame, View, ViewLocation


class LinearViewTreeItem:
    """
    Python tree model for linear view
    """
    model: 'LinearViewItemModel'
    cursor: Optional[LinearViewObject]
    line: Optional[LinearDisassemblyLine]
    token: Optional[InstructionTextToken]
    id: int = 0
    expanded: bool = True
    parent: Optional['LinearViewTreeItem'] = None
    _children: List['LinearViewTreeItem'] = None

    def __init__(
            self,
            model: 'LinearViewItemModel',
            cursor: LinearViewObject = None,
            line: Optional[LinearDisassemblyLine] = None,
            token: Optional[InstructionTextToken] = None,
            text: Optional[str] = None,
            parent: Optional['LinearViewTreeItem'] = None
    ):
        self.model = model
        self.cursor = cursor
        self.line = line
        self.token = token
        self.text = text
        self.parent = parent
        self.id = self.model.last_id
        self.model.ids[self.model.last_id] = self
        self.model.last_id += 1

    @property
    def has_object_children(self) -> bool:
        if self.cursor is None:
            return False
        return self.cursor.first_child is not None

    @property
    def children(self) -> List['LinearViewTreeItem']:
        if self._children is None:
            self._children = []
            if self.cursor is not None:
                cur = self.cursor.first_child
                while cur is not None:
                    child = LinearViewTreeItem(self.model, cursor=cur, parent=self)
                    self._children.append(child)
                    cur = cur.next
                if len(self._children) == 0:
                    prev = None
                    next = None
                    prev_object = self.prev_object
                    if prev_object is not None:
                        prev = prev_object.cursor
                    next_object = self.next_object
                    if next_object is not None:
                        next = next_object.cursor
                    lines = self.cursor.get_lines(prev, next)
                    for line in lines:
                        child = LinearViewTreeItem(self.model, line=line, parent=self)
                        self._children.append(child)
            if self.line is not None:
                self._children.append(LinearViewTreeItem(self.model, text=f"Type: {LinearDisassemblyLineType(self.line.type).name}", parent=self))
                self._children.append(LinearViewTreeItem(self.model, text=f"Function: {self.line.function}", parent=self))
                self._children.append(LinearViewTreeItem(self.model, text=f"Block: {self.line.block}", parent=self))
                for token in self.line.contents.tokens:
                    child = LinearViewTreeItem(self.model, token=token, parent=self)
                    self._children.append(child)
            if self.token is not None:
                self._children.append(LinearViewTreeItem(self.model, text=f"Type: {InstructionTextTokenType(self.token.type).name}", parent=self))
                self._children.append(LinearViewTreeItem(self.model, text=f"Value: {self.token.value:#x}", parent=self))
                self._children.append(LinearViewTreeItem(self.model, text=f"Size: {self.token.size:#x}", parent=self))
                self._children.append(LinearViewTreeItem(self.model, text=f"Operand: {self.token.operand:#x}", parent=self))
                self._children.append(LinearViewTreeItem(self.model, text=f"Context: {InstructionTextTokenContext(self.token.context).name}", parent=self))
                self._children.append(LinearViewTreeItem(self.model, text=f"Address: {self.token.address:#x}", parent=self))
                self._children.append(LinearViewTreeItem(self.model, text=f"Confidence: {self.token.confidence}", parent=self))
                self._children.append(LinearViewTreeItem(self.model, text=f"Type Names: {self.token.typeNames}", parent=self))
                self._children.append(LinearViewTreeItem(self.model, text=f"Width: {self.token.width:#x}", parent=self))
                self._children.append(LinearViewTreeItem(self.model, text=f"IL Expr Index: {self.token.il_expr_index:#x}", parent=self))

        return self._children

    @property
    def first_object(self) -> Optional['LinearViewTreeItem']:
        if not self.has_object_children:
            return None
        child = self.children[0]
        first_child = child.first_object
        if first_child is None:
            return child
        else:
            return first_child

    @property
    def last_object(self) -> Optional['LinearViewTreeItem']:
        if not self.has_object_children:
            return None
        child = self.children[-1]
        last_child = child.last_object
        if last_child is None:
            return child
        else:
            return last_child

    @property
    def prev_object(self) -> Optional['LinearViewTreeItem']:
        if self.cursor is None:
            return None
        if self.parent is None:
            return None
        # Go one back in our parent, unless we're the first item in our parent,
        # in which case go one back in our parent's parent and pick their last child
        self_parent_index = self.parent.children.index(self)
        while self_parent_index > 0:
            self_parent_index -= 1
            last_prev = self.parent.children[self_parent_index].last_object
            if last_prev is not None:
                return last_prev
        # No previous child of the parent matches, go up a level
        return self.parent.prev_object

    @property
    def next_object(self) -> Optional['LinearViewTreeItem']:
        if self.cursor is None:
            return None
        if self.parent is None:
            return None
        # Go one forward in our parent, unless we're the last item in our parent,
        # in which case go one forward in our parent's parent and pick their first child
        self_parent_index = self.parent.children.index(self)
        while (self_parent_index + 1) < len(self.parent.children):
            self_parent_index += 1
            first_prev = self.parent.children[self_parent_index].first_object
            if first_prev is not None:
                return first_prev
        # No next child of the parent matches, go up a level
        return self.parent.next_object

    @property
    def name(self) -> str:
        if self.cursor is not None:
            return str(self.cursor.identifier)
        if self.line is not None:
            return "".join(t.text for t in self.line.contents.tokens)
        if self.token is not None:
            return self.token.text
        if self.text is not None:
            return self.text
        return ""

    @property
    def start(self) -> int:
        if self.cursor is not None:
            return self.cursor.start
        if self.line is not None:
            return self.line.contents.address
        if self.token is not None or self.text is not None:
            return self.parent.start
        return 0

    @property
    def end(self) -> int:
        if self.cursor is not None:
            return self.cursor.end
        if self.line is not None:
            # Hack: find end of line by using start of next line in parent
            parent_index = self.parent.children.index(self)
            if len(self.parent.children) == parent_index + 1:
                return self.parent.end
            else:
                return self.parent.children[parent_index + 1].start
        if self.token is not None or self.text is not None:
            # Use parent start so we don't expand tokens
            return self.parent.start
        return 0

    @property
    def index(self) -> QModelIndex:
        if self.parent is None:
            return self.model.to_index(0, 0, self)
        else:
            return self.model.to_index(self.parent.children.index(self), 0, self)


class LinearViewItemModel(QAbstractItemModel):
    """
    Qt item model for linear view
    """
    def __init__(self, parent: QObject, root: Optional[LinearViewObject]):
        QAbstractItemModel.__init__(self, parent)
        self.ids = {}
        self.last_id = 0
        self.root = LinearViewTreeItem(self, cursor=root)

    def set_root(self, root: Optional[LinearViewObject]):
        self.beginResetModel()
        self.ids = {}
        self.last_id = 0
        self.root = LinearViewTreeItem(self, cursor=root)
        self.endResetModel()

    def columnCount(self, parent: QModelIndex = None) -> int:
        return 3

    def rowCount(self, parent: QModelIndex = None) -> int:
        if parent is None:
            if self.root is None:
                return 0
            return 1
        if parent.internalId() not in self.ids:
            return -1
        item = self.ids[parent.internalId()]
        return len(item.children)

    def parent(self, index: QModelIndex = None) -> QModelIndex:
        if self.root is None:
            return QModelIndex()
        if index is None:
            return QModelIndex()
        if index.internalId() not in self.ids:
            return QModelIndex()
        item = self.ids[index.internalId()]
        if item.parent is None:
            return QModelIndex()

        row = item.parent.children.index(item)
        return self.createIndex(row, 0, item.parent.id)

    def to_index(self, row: int, column: int, tree: LinearViewTreeItem) -> QModelIndex:
        return self.createIndex(row, column, tree.id)

    def to_tree(self, index: QModelIndex) -> Optional[LinearViewTreeItem]:
        if index is None:
            return QModelIndex()
        if index.internalId() not in self.ids:
            return QModelIndex()
        return self.ids[index.internalId()]

    def index(self, row: int, column: int, parent: QModelIndex = None) -> QModelIndex:
        if self.root is None:
            return QModelIndex()
        if parent is None:
            id = self.root.id
        elif parent.internalId() not in self.ids:
            id = self.root.id
        else:
            item = self.ids[parent.internalId()]
            id = item.children[row].id
        return self.createIndex(row, column, id)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if index is None:
            return None
        if index.internalId() not in self.ids:
            return None
        item = self.ids[index.internalId()]
        if role == Qt.ItemDataRole.DisplayRole:
            if index.column() == 0:
                return item.name
            elif index.column() == 1:
                return f"{item.start:X}"
            elif index.column() == 2:
                return f"{item.end:X}"
        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if section < 0 or section >= 3:
            return None
        if role == Qt.ItemDataRole.DisplayRole:
            return ["Name", "Start", "End"][section]
        return None


class LinearSidebarWidget(SidebarWidget, UIContextNotification):
    def __init__(self, name, frame: ViewFrame, data: BinaryView):
        SidebarWidget.__init__(self, name)
        UIContextNotification.__init__(self)
        self.setParent(frame)
        self.m_actionHandler.setupActionHandler(self)
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)

        self.frame = frame
        self.data = data
        self.model = LinearViewItemModel(self, None)
        self.tree = QTreeView(self)
        self.tree.setModel(self.model)
        self.tree.clicked.connect(self.item_clicked)
        self.graph_type = FunctionViewType(FunctionGraphType.NormalFunctionGraph)
        self.current_address = 0

        self.layout.addWidget(self.tree)
        self.view = self.frame.getCurrentView()

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
        self.update_tree()

    def OnViewChange(self, context: UIContext, frame: ViewFrame, type: str):
        if self.isVisible():
            if frame is not None:
                view = frame.getCurrentWidget()
                self.view = view
            else:
                self.view = None
            self.update_tree()

    def OnAddressChange(self, context: UIContext, frame: ViewFrame, view: View, location: ViewLocation):
        if self.isVisible():
            offset = location.getOffset()

            if location.getILViewType() != self.graph_type:
                self.graph_type = location.getILViewType()
                self.update_tree()

            self.set_address(offset)
            self.current_address = offset

    def set_address(self, offset):
        def recurse(tree: LinearViewTreeItem):
            for child in tree.children:
                if child.start <= offset < child.end:
                    recurse(child)
                    if child.cursor is not None:
                        self.tree.expand(child.index)
                    return
            self.tree.setCurrentIndex(tree.index)
            self.tree.scrollTo(tree.index)

        recurse(self.model.root)

    def item_clicked(self, item: QModelIndex):
        tree = self.model.to_tree(item)
        if tree is not None:
            addr = tree.start
            self.data.navigate(f'Linear:{self.data.view_type}', addr)

    def update_tree(self):
        if self.graph_type.view_type == FunctionGraphType.LiftedILFunctionGraph:
            self.model.set_root(LinearViewObject.lifted_il(self.data))
        elif self.graph_type.view_type == FunctionGraphType.LowLevelILFunctionGraph:
            self.model.set_root(LinearViewObject.llil(self.data))
        elif self.graph_type.view_type == FunctionGraphType.LowLevelILSSAFormFunctionGraph:
            self.model.set_root(LinearViewObject.llil_ssa_form(self.data))
        elif self.graph_type.view_type == FunctionGraphType.MediumLevelILFunctionGraph:
            self.model.set_root(LinearViewObject.mlil(self.data))
        elif self.graph_type.view_type == FunctionGraphType.MediumLevelILSSAFormFunctionGraph:
            self.model.set_root(LinearViewObject.mlil_ssa_form(self.data))
        elif self.graph_type.view_type == FunctionGraphType.MappedMediumLevelILFunctionGraph:
            self.model.set_root(LinearViewObject.mmlil(self.data))
        elif self.graph_type.view_type == FunctionGraphType.MappedMediumLevelILSSAFormFunctionGraph:
            self.model.set_root(LinearViewObject.mmlil_ssa_form(self.data))
        elif self.graph_type.view_type == FunctionGraphType.HighLevelILFunctionGraph:
            self.model.set_root(LinearViewObject.hlil(self.data))
        elif self.graph_type.view_type == FunctionGraphType.HighLevelILSSAFormFunctionGraph:
            self.model.set_root(LinearViewObject.hlil_ssa_form(self.data))
        elif self.graph_type.view_type == FunctionGraphType.HighLevelLanguageRepresentationFunctionGraph:
            self.model.set_root(LinearViewObject.language_representation(self.data, None, self.graph_type.name))
        else:
            self.model.set_root(LinearViewObject.disassembly(self.data))

        self.set_address(self.current_address)
        self.tree.resizeColumnToContents(0)


class LinearSidebarWidgetType(SidebarWidgetType):
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
        p.drawText(QRectF(0, 0, 56, 56), Qt.AlignCenter, "L")
        p.end()

        SidebarWidgetType.__init__(self, icon, "Linear Inspector")

    def createWidget(self, frame: ViewFrame, data: BinaryView):
        return LinearSidebarWidget("Linear Inspector", frame, data)


Sidebar.addSidebarWidgetType(LinearSidebarWidgetType())
