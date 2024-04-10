# Copyright (c) 2015-2022 Vector 35 Inc
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
import shlex
import traceback
from typing import Optional

from binaryninja import Platform, TypeParserResult, Type, TypeClass, ThemeColor, TypeParser, ParsedType, QualifiedNameTypeAndId
from binaryninjaui import SidebarWidget, SidebarWidgetType, Sidebar, UIActionHandler, getMonospaceFont, getThemeColor, \
	UIContext
from PySide6 import QtCore
from PySide6.QtCore import Qt, QRectF, QSettings
from PySide6.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QLabel, QWidget, QPushButton, QMenu, QSplitter, \
	QPlainTextEdit, QTreeWidget, QTreeWidgetItem, QFormLayout, QCheckBox, QLineEdit
from PySide6.QtGui import QImage, QPixmap, QPainter, QFont, QColor, QFontMetrics, QTextCharFormat, QPalette

instance_id = 0


class TypesSidebarWidget(SidebarWidget):
	def __init__(self, name, frame, data):
		global instance_id
		SidebarWidget.__init__(self, name)
		self.actionHandler = UIActionHandler()
		self.actionHandler.setupActionHandler(self)
		self.layout = QVBoxLayout(self)
		self.layout.setContentsMargins(0, 0, 0, 0)

		platformLayout = QVBoxLayout()
		platformLayout.setContentsMargins(0, 0, 0, 0)

		platformLayout.addWidget(QLabel("Platform:"))
		self.platformEntry = QPushButton(self)
		self.platformMenu = QMenu(self)
		platform_name = QSettings().value("plugin.typeInspector.platform", "windows-x86_64")
		self.platform = Platform[platform_name]
		self.platformEntry.setText(platform_name)
		self.platformEntry.setMenu(self.platformMenu)
		platformLayout.addWidget(self.platformEntry)

		typeParserLayout = QVBoxLayout()
		typeParserLayout.setContentsMargins(0, 0, 0, 0)

		typeParserLayout.addWidget(QLabel("Parser:"))
		self.typeParserEntry = QPushButton(self)
		self.typeParserMenu = QMenu(self)
		type_parser_name = QSettings().value("plugin.typeInspector.type_parser", "ClangTypeParser")
		try:
			self.type_parser = TypeParser[type_parser_name]
		except:
			self.type_parser = TypeParser.default
		self.typeParserEntry.setText(type_parser_name)
		self.typeParserEntry.setMenu(self.typeParserMenu)
		typeParserLayout.addWidget(self.typeParserEntry)

		configLayout = QHBoxLayout()
		configLayout.setContentsMargins(0, 0, 0, 0)

		configLayout.addLayout(platformLayout)
		configLayout.addLayout(typeParserLayout)

		self.layout.addLayout(configLayout)

		self.optionsEntry = QLineEdit()
		options = QSettings().value("plugin.typeInspector.options", "")
		self.optionsEntry.setText(options)
		self.optionsEntry.textChanged.connect(self.updateTypes)

		self.layout.addWidget(self.optionsEntry)

		splitter = QSplitter(Qt.Orientation.Vertical)
		self.layout.addWidget(splitter)

		font = getMonospaceFont(self)
		self.typesBox = QPlainTextEdit()
		self.typesBox.setPlainText(QSettings().value("plugin.typeInspector.types", ""))
		self.typesBox.setFont(font)
		self.typesBox.setTabStopDistance(QFontMetrics(font).horizontalAdvance(" ") * 4)
		self.typesBox.textChanged.connect(self.updateTypes)

		self.errorBox = QPlainTextEdit()

		self.typesContainer = QWidget()
		typesLayout = QVBoxLayout()
		typesLayout.setContentsMargins(0, 0, 0, 0)
		self.typesContainer.setLayout(typesLayout)
		typesLayout.addWidget(self.typesBox)
		typesLayout.addWidget(self.errorBox)

		parseOptionsContainer = QWidget()
		parseOptionsLayout = QHBoxLayout()
		parseOptionsContainer.setLayout(parseOptionsLayout)
		parseOptionsLayout.setContentsMargins(0, 0, 0, 0)

		parseSingle = QCheckBox("Single Line?")
		self.parse_single = False
		def update_parse_single():
			self.parse_single = parseSingle.checkState() == Qt.Checked
			QSettings().setValue("plugin.typeInspector.parseSingle", '1' if self.parse_single else '0')
			self.updateTypes()
		parseSingle.stateChanged.connect(update_parse_single)
		parseOptionsLayout.addWidget(parseSingle)

		parseOptionsLayout.addStretch(1)

		preprocessOnly = QCheckBox("Preprocessor Only?")
		self.preprocess_only = False
		def update_preprocess_only():
			self.preprocess_only = preprocessOnly.checkState() == Qt.Checked
			QSettings().setValue("plugin.typeInspector.preprocessOnly", '1' if self.preprocess_only else '0')
			self.updateTypes()
		preprocessOnly.stateChanged.connect(update_preprocess_only)
		parseOptionsLayout.addWidget(preprocessOnly)

		typesLayout.addWidget(parseOptionsContainer)

		splitter.addWidget(self.typesContainer)

		self.preprocessContainer = QWidget()
		preprocessLayout = QVBoxLayout()
		preprocessLayout.setContentsMargins(0, 0, 0, 0)
		self.preprocessContainer.setLayout(preprocessLayout)
		self.preprocessOutput = QPlainTextEdit()
		preprocessLayout.addWidget(self.preprocessOutput)

		self.typesTree = QTreeWidget()
		self.typesTree.setColumnCount(2)
		self.typesTree.setIndentation(10)

		self.treeContainer = QWidget()
		treeLayout = QVBoxLayout()
		treeLayout.setContentsMargins(0, 0, 0, 0)

		treeLayout.addWidget(self.typesTree)

		self.treeContainer.setLayout(treeLayout)
		showWA = QCheckBox("Show width/align")
		self.show_wa = False
		def update_show_wa():
			self.show_wa = showWA.checkState() == Qt.Checked
			QSettings().setValue("plugin.typeInspector.showWA", '1' if self.show_wa else '0')
			self.updateTypes()
		showWA.stateChanged.connect(update_show_wa)
		treeLayout.addWidget(showWA)

		bottomContainer = QWidget()
		bottomLayout = QVBoxLayout()
		bottomLayout.setContentsMargins(0, 0, 0, 0)
		bottomContainer.setLayout(bottomLayout)
		bottomLayout.addWidget(self.preprocessContainer)
		bottomLayout.addWidget(self.treeContainer)

		splitter.addWidget(bottomContainer)

		splitter.setSizes([1000, 1000])

		self.updatePlatforms()
		self.updateTypeParsers()

		showWA.setCheckState(Qt.Checked if QSettings().value("plugin.typeInspector.showWA", '0') == '1' else Qt.Unchecked)
		parseSingle.setCheckState(Qt.Checked if QSettings().value("plugin.typeInspector.parseSingle", '0') == '1' else Qt.Unchecked)
		preprocessOnly.setCheckState(Qt.Checked if QSettings().value("plugin.typeInspector.preprocessOnly", '0') == '1' else Qt.Unchecked)

	def notifyOffsetChanged(self, offset):
		pass

	def notifyViewChanged(self, view_frame):
		pass

	def contextMenuEvent(self, event):
		self.m_contextMenuManager.show(self.m_menu, self.actionHandler)

	def updatePlatforms(self):
		self.platformMenu.clear()
		for platform in Platform:
			def select_platform(platform):
				return lambda: self.selectPlatform(platform)
			self.platformMenu.addAction(platform.name, select_platform(platform))

		self.selectPlatform(self.platform)

	def selectPlatform(self, platform):
		self.platform = platform
		self.platformEntry.setText(platform.name)
		QSettings().setValue("plugin.typeInspector.platform", platform.name)

		self.updateTypes()
		# Load base types
		try:
			self.platform.parse_types_from_source('')
		except SyntaxError:
			pass

	def updateTypeParsers(self):
		self.typeParserMenu.clear()
		for type_parser in TypeParser:
			def select_type_parser(type_parser):
				return lambda: self.selectTypeParser(type_parser)
			self.typeParserMenu.addAction(type_parser.name, select_type_parser(type_parser))

		self.selectTypeParser(self.type_parser)

	def selectTypeParser(self, type_parser):
		self.type_parser = type_parser
		self.typeParserEntry.setText(type_parser.name)
		QSettings().setValue("plugin.typeInspector.type_parser", type_parser.name)
		self.updateTypes()

	def updateTypes(self):
		conts = self.typesBox.toPlainText()
		conts = conts.replace('\x00', '')  # What
		QSettings().setValue("plugin.typeInspector.types", conts)

		options = self.optionsEntry.text()
		QSettings().setValue("plugin.typeInspector.options", options)

		try:
			existing_types = []
			bv = None
			uic = UIContext.activeContext()
			vf = uic.getCurrentViewFrame()
			if vf is not None:
				bv = vf.getCurrentBinaryView()
				if bv is not None:
					for (name, type) in bv.types:
						existing_types.append(QualifiedNameTypeAndId(name, bv.get_type_id(name), type))

			if self.preprocess_only:
				result, errors = self.type_parser.preprocess_source(conts, "input.hpp", self.platform, existing_types, shlex.split(options), [])
				# This is only one type in this case
				if result is not None:
					self.preprocessOutput.setPlainText(result)

				pal = self.typesBox.palette()
				pal.setColor(QPalette.Text, self.palette().text().color())
				self.typesBox.setPalette(pal)

				self.preprocessContainer.show()
				self.treeContainer.hide()
				return
			elif self.parse_single:
				result, errors = self.type_parser.parse_type_string(conts, self.platform, existing_types)
				# This is only one type in this case
				if result is not None:
					result = TypeParserResult([
						ParsedType(result[0], result[1], True)
					], [], [])
			else:
				result, errors = self.type_parser.parse_types_from_source(conts, "input.hpp", self.platform, existing_types, shlex.split(options), [], "")

			self.preprocessContainer.hide()
			self.treeContainer.show()

			if len(errors) > 0:
				self.errorBox.setPlainText('\n'.join(str(e) for e in errors))
				self.errorBox.show()
			else:
				self.errorBox.hide()

			def boolstr(b: bool):
				if b:
					return "True"
				return "False"

			def hexornone(h: Optional[int]) -> str:
				if h is None:
					return "None"
				else:
					return hex(h)

			def create_type_tree(root: QTreeWidgetItem, type: Type):
				if type.type_class == TypeClass.VoidTypeClass:
					tree = QTreeWidgetItem(["void", str(type)])
					root.addChild(tree)
					if self.show_wa:
						tree.addChild(QTreeWidgetItem(["width", hexornone(type.width)]))
						tree.addChild(QTreeWidgetItem(["alignment", hexornone(type.alignment)]))
						tree.addChild(QTreeWidgetItem(["const", boolstr(type.const)]))
						tree.addChild(QTreeWidgetItem(["volatile", boolstr(type.volatile)]))
				elif type.type_class == TypeClass.BoolTypeClass:
					tree = QTreeWidgetItem(["bool", str(type)])
					root.addChild(tree)
					if self.show_wa:
						tree.addChild(QTreeWidgetItem(["width", hexornone(type.width)]))
						tree.addChild(QTreeWidgetItem(["alignment", hexornone(type.alignment)]))
						tree.addChild(QTreeWidgetItem(["const", boolstr(type.const)]))
						tree.addChild(QTreeWidgetItem(["volatile", boolstr(type.volatile)]))
				elif type.type_class == TypeClass.IntegerTypeClass:
					tree = QTreeWidgetItem(["int", str(type)])
					root.addChild(tree)
					if self.show_wa:
						tree.addChild(QTreeWidgetItem(["width", hexornone(type.width)]))
						tree.addChild(QTreeWidgetItem(["alignment", hexornone(type.alignment)]))
						tree.addChild(QTreeWidgetItem(["const", boolstr(type.const)]))
						tree.addChild(QTreeWidgetItem(["volatile", boolstr(type.volatile)]))
					tree.addChild(QTreeWidgetItem(["signed", boolstr(type.signed)]))
				elif type.type_class == TypeClass.FloatTypeClass:
					tree = QTreeWidgetItem(["float", str(type)])
					root.addChild(tree)
					if self.show_wa:
						tree.addChild(QTreeWidgetItem(["width", hexornone(type.width)]))
						tree.addChild(QTreeWidgetItem(["alignment", hexornone(type.alignment)]))
						tree.addChild(QTreeWidgetItem(["const", boolstr(type.const)]))
						tree.addChild(QTreeWidgetItem(["volatile", boolstr(type.volatile)]))
				elif type.type_class == TypeClass.StructureTypeClass:
					tree = QTreeWidgetItem(["struct", str(type)])
					root.addChild(tree)
					if self.show_wa:
						tree.addChild(QTreeWidgetItem(["width", hexornone(type.width)]))
						tree.addChild(QTreeWidgetItem(["alignment", hexornone(type.alignment)]))
						tree.addChild(QTreeWidgetItem(["const", boolstr(type.const)]))
						tree.addChild(QTreeWidgetItem(["volatile", boolstr(type.volatile)]))
					tree.addChild(QTreeWidgetItem(["type", str(type.type)]))
					tree.addChild(QTreeWidgetItem(["packed", boolstr(type.packed)]))
					members = QTreeWidgetItem(["members", f"len: {len(type.members)}"])
					tree.addChild(members)
					for m in type.members:
						member = QTreeWidgetItem([m.name, hexornone(m.offset)])
						create_type_tree(member, m.type)
						members.addChild(member)
					base_structures = QTreeWidgetItem(["base_structures", f"len: {len(type.base_structures)}"])
					tree.addChild(base_structures)
					for i, b in enumerate(type.base_structures):
						base_structure = QTreeWidgetItem([str(b.type.name), f"index: {i}"])
						base_structure.addChild(QTreeWidgetItem(["offset", hexornone(b.offset)]))
						base_structure.addChild(QTreeWidgetItem(["width", hexornone(b.width)]))
						base_structure_type = QTreeWidgetItem(["type"])
						create_type_tree(base_structure_type, b.type)
						base_structure.addChild(base_structure_type)
						base_structures.addChild(base_structure)
				elif type.type_class == TypeClass.EnumerationTypeClass:
					tree = QTreeWidgetItem(["enum", str(type)])
					root.addChild(tree)
					if self.show_wa:
						tree.addChild(QTreeWidgetItem(["width", hexornone(type.width)]))
						tree.addChild(QTreeWidgetItem(["alignment", hexornone(type.alignment)]))
						tree.addChild(QTreeWidgetItem(["const", boolstr(type.const)]))
						tree.addChild(QTreeWidgetItem(["volatile", boolstr(type.volatile)]))
					members = QTreeWidgetItem(["members"])
					tree.addChild(members)
					for m in type.members:
						member = QTreeWidgetItem([m.name, hexornone(m.value)])
						members.addChild(member)
				elif type.type_class == TypeClass.PointerTypeClass:
					tree = QTreeWidgetItem(["pointer", str(type)])
					root.addChild(tree)
					if self.show_wa:
						tree.addChild(QTreeWidgetItem(["width", hexornone(type.width)]))
						tree.addChild(QTreeWidgetItem(["alignment", hexornone(type.alignment)]))
						tree.addChild(QTreeWidgetItem(["const", boolstr(type.const)]))
						tree.addChild(QTreeWidgetItem(["volatile", boolstr(type.volatile)]))
					target = QTreeWidgetItem(["target"])
					tree.addChild(target)
					create_type_tree(target, type.target)
					if type.origin(bv) is not None:
						(origin_type, origin_offset) = type.origin(bv)
						tree.addChild(QTreeWidgetItem(["origin.offset", hexornone(origin_offset)]))
						origin_tree = QTreeWidgetItem(["origin.type", str(origin_type)])
						tree.addChild(origin_tree)
				elif type.type_class == TypeClass.ArrayTypeClass:
					tree = QTreeWidgetItem(["array", str(type)])
					root.addChild(tree)
					if self.show_wa:
						tree.addChild(QTreeWidgetItem(["width", hexornone(type.width)]))
						tree.addChild(QTreeWidgetItem(["alignment", hexornone(type.alignment)]))
						tree.addChild(QTreeWidgetItem(["const", boolstr(type.const)]))
						tree.addChild(QTreeWidgetItem(["volatile", boolstr(type.volatile)]))
					tree.addChild(QTreeWidgetItem(["count", hexornone(type.count)]))
					element_type = QTreeWidgetItem(["element_type"])
					tree.addChild(element_type)
					create_type_tree(element_type, type.element_type)
				elif type.type_class == TypeClass.FunctionTypeClass:
					tree = QTreeWidgetItem(["function", str(type)])
					root.addChild(tree)
					if self.show_wa:
						tree.addChild(QTreeWidgetItem(["width", hexornone(type.width)]))
						tree.addChild(QTreeWidgetItem(["alignment", hexornone(type.alignment)]))
						tree.addChild(QTreeWidgetItem(["const", boolstr(type.const)]))
						tree.addChild(QTreeWidgetItem(["volatile", boolstr(type.volatile)]))
					tree.addChild(QTreeWidgetItem(["stack_adjustment", hexornone(type.stack_adjustment.value)]))
					if type.calling_convention is not None:
						tree.addChild(QTreeWidgetItem(["calling_convention", type.calling_convention.name]))
					else:
						tree.addChild(QTreeWidgetItem(["calling_convention", "None"]))
					tree.addChild(QTreeWidgetItem(["has_variable_arguments", boolstr(type.has_variable_arguments.value)]))
					tree.addChild(QTreeWidgetItem(["can_return", boolstr(type.can_return.value)]))
					tree.addChild(QTreeWidgetItem(["system_call_number", str(type.system_call_number)]))
					return_value = QTreeWidgetItem(["return_value"])
					tree.addChild(return_value)
					create_type_tree(return_value, type.return_value)
					parameters = QTreeWidgetItem(["parameters"])
					tree.addChild(parameters)
					for m in type.parameters:
						parameter = QTreeWidgetItem([m.name])
						create_type_tree(parameter, m.type)
						location_tree = QTreeWidgetItem(["location"])
						parameter.addChild(location_tree)
						if m.location is None:
							location_tree.addChild(QTreeWidgetItem(["is_default", "True"]))
						else:
							location_tree.addChild(QTreeWidgetItem(["is_default", "False"]))
							location_tree.addChild(QTreeWidgetItem(["source_type", m.location.source_type.name]))
							location_tree.addChild(QTreeWidgetItem(["storage", m.location.storage]))
							location_tree.addChild(QTreeWidgetItem(["index", m.location.index]))
						parameters.addChild(parameter)
				elif type.type_class == TypeClass.VarArgsTypeClass:
					tree = QTreeWidgetItem(["varargs", str(type)])
					root.addChild(tree)
					if self.show_wa:
						tree.addChild(QTreeWidgetItem(["width", hexornone(type.width)]))
						tree.addChild(QTreeWidgetItem(["alignment", hexornone(type.alignment)]))
						tree.addChild(QTreeWidgetItem(["const", boolstr(type.const)]))
						tree.addChild(QTreeWidgetItem(["volatile", boolstr(type.volatile)]))
				elif type.type_class == TypeClass.ValueTypeClass:
					tree = QTreeWidgetItem(["ValueTypeClass", str(type)])
					root.addChild(tree)
					if self.show_wa:
						tree.addChild(QTreeWidgetItem(["width", hexornone(type.width)]))
						tree.addChild(QTreeWidgetItem(["alignment", hexornone(type.alignment)]))
						tree.addChild(QTreeWidgetItem(["const", boolstr(type.const)]))
						tree.addChild(QTreeWidgetItem(["volatile", boolstr(type.volatile)]))
				elif type.type_class == TypeClass.NamedTypeReferenceClass:
					tree = QTreeWidgetItem(["named_type", str(type)])
					root.addChild(tree)
					if self.show_wa:
						tree.addChild(QTreeWidgetItem(["width", hexornone(type.width)]))
						tree.addChild(QTreeWidgetItem(["alignment", hexornone(type.alignment)]))
						tree.addChild(QTreeWidgetItem(["const", boolstr(type.const)]))
						tree.addChild(QTreeWidgetItem(["volatile", boolstr(type.volatile)]))
					tree.addChild(QTreeWidgetItem(["named_type_class", str(type.named_type_class)]))
					tree.addChild(QTreeWidgetItem(["type_id", type.type_id]))
					tree.addChild(QTreeWidgetItem(["name", str(type.name)]))
				elif type.type_class == TypeClass.WideCharTypeClass:
					tree = QTreeWidgetItem(["wchar", str(type)])
					root.addChild(tree)
					if self.show_wa:
						tree.addChild(QTreeWidgetItem(["width", hexornone(type.width)]))
						tree.addChild(QTreeWidgetItem(["alignment", hexornone(type.alignment)]))
						tree.addChild(QTreeWidgetItem(["const", boolstr(type.const)]))
						tree.addChild(QTreeWidgetItem(["volatile", boolstr(type.volatile)]))
				else:
					tree = QTreeWidgetItem(["???", str(type)])
					root.addChild(tree)
					if self.show_wa:
						tree.addChild(QTreeWidgetItem(["width", hexornone(type.width)]))
						tree.addChild(QTreeWidgetItem(["alignment", hexornone(type.alignment)]))
						tree.addChild(QTreeWidgetItem(["const", boolstr(type.const)]))
						tree.addChild(QTreeWidgetItem(["volatile", boolstr(type.volatile)]))

			if result is not None:
				scroll_x = self.typesTree.horizontalScrollBar().value()
				scroll_y = self.typesTree.verticalScrollBar().value()
				self.typesTree.clear()
				pal = self.typesBox.palette()
				pal.setColor(QPalette.Text, self.palette().text().color())
				self.typesBox.setPalette(pal)

				types_tree = QTreeWidgetItem(self.typesTree, ["Types"])
				types_tree.setBackground(0, self.palette().alternateBase())
				types_tree.setBackground(1, self.palette().alternateBase())
				self.typesTree.addTopLevelItem(types_tree)

				for ptype in result.types:
					if ptype.is_user:
						source = "User Type"
					else:
						source = "Auto Type"

					child = QTreeWidgetItem(types_tree, [str(ptype.name), source])
					child.addChild(create_type_tree(child, ptype.type))
					types_tree.addChild(child)

				vars_tree = QTreeWidgetItem(self.typesTree, ["Variables"])
				vars_tree.setBackground(0, self.palette().alternateBase())
				vars_tree.setBackground(1, self.palette().alternateBase())
				self.typesTree.addTopLevelItem(vars_tree)

				for ptype in result.variables:
					if ptype.is_user:
						source = "User Type"
					else:
						source = "Auto Type"

					child = QTreeWidgetItem(vars_tree, [str(ptype.name), source])
					child.addChild(create_type_tree(child, ptype.type))
					vars_tree.addChild(child)

				funcs_tree = QTreeWidgetItem(self.typesTree, ["Functions"])
				funcs_tree.setBackground(0, self.palette().alternateBase())
				funcs_tree.setBackground(1, self.palette().alternateBase())
				self.typesTree.addTopLevelItem(funcs_tree)

				for ptype in result.functions:
					if ptype.is_user:
						source = "User Type"
					else:
						source = "Auto Type"

					child = QTreeWidgetItem(funcs_tree, [str(ptype.name), source])
					child.addChild(create_type_tree(child, ptype.type))
					funcs_tree.addChild(child)

				self.typesTree.expandAll()
				self.typesTree.resizeColumnToContents(0)
				self.typesTree.resizeColumnToContents(1)
				self.typesTree.horizontalScrollBar().setValue(scroll_x)
				self.typesTree.verticalScrollBar().setValue(scroll_y)
			else:
				pal = self.typesBox.palette()
				pal.setColor(QPalette.Text, getThemeColor(ThemeColor.RedStandardHighlightColor))
				self.typesBox.setPalette(pal)
		except SyntaxError as e:
			pal = self.typesBox.palette()
			pal.setColor(QPalette.Text, getThemeColor(ThemeColor.RedStandardHighlightColor))
			self.typesBox.setPalette(pal)
			self.errorBox.setPlainText(e.msg)
			self.errorBox.show()
		except:
			self.errorBox.setPlainText(traceback.format_exc())
			self.errorBox.show()


class TypesSidebarWidgetType(SidebarWidgetType):
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
		p.drawText(QRectF(0, 0, 56, 56), Qt.AlignCenter, "TI")
		p.end()

		SidebarWidgetType.__init__(self, icon, "Type Inspector")

	def createWidget(self, frame, data):
		return TypesSidebarWidget("Type Inspector", frame, data)

	def viewSensitive(self, *args, **kwargs):
		return False


Sidebar.addSidebarWidgetType(TypesSidebarWidgetType())
