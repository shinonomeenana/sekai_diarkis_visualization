import sys
import ast
import traceback
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, 
    QTableWidget, QHeaderView, QTableWidgetItem, QCheckBox,
    QMenu, QWidgetAction, QPushButton, QSplitter,
    QLabel, QHBoxLayout, QListWidget, QListWidgetItem, QTreeWidget, 
    QTreeWidgetItem, QFileDialog, QMessageBox, QDialog, QTextEdit
)
from PyQt6.QtGui import QAction
from PyQt6.QtCore import Qt

from DiarkisUtils import Packet, SyncProperty
import har_helper
import pcap_helper

class TextViewerDialog(QDialog):
    """自定义的弹出窗口类 (复用之前的代码)"""
    def __init__(self, content, title="详细信息", parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(700, 400)

        layout = QVBoxLayout()
        self.text_edit = QTextEdit()
        self.text_edit.setPlainText(content)
        self.text_edit.setReadOnly(True) 
        self.text_edit.setStyleSheet("font-size: 14px; padding: 10px;")
        layout.addWidget(self.text_edit)
        self.setLayout(layout)

# --- 1. 复用之前的 DictTreeWidget (保持不变) ---
class DictTreeWidget(QTreeWidget):
    def __init__(self, data=None):
        super().__init__()
        self.init_ui()
        self.showDeserialized = False
        if data:
            self.load_data(data)

    def init_ui(self):
        self.setHeaderLabels(["Key", "Value"])
        self.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.setAlternatingRowColors(True)

    def load_data(self, data):
        self.clear()
        data = self.extract_diarkis_property(data)
        print(data)
        self._populate_tree(self.invisibleRootItem(), data)

    def extract_diarkis_property(self, data):
            """
            递归遍历 data。
            如果 showDeserialized 为 True，则尝试将所有深层嵌套的 bytes 提取为 Diarkis Property。
            """
            # 1. 如果开关没开，或者是 None，直接返回
            if not self.showDeserialized or data is None:
                return data

            # 2. 处理字典：递归处理每一个 value
            if isinstance(data, dict):
                new_data = {}
                for key, value in data.items():
                    new_data[key] = self.extract_diarkis_property(value)
                return new_data

            # 3. 处理列表：递归处理每一个 item (这是处理复杂结构的关键)
            if isinstance(data, list):
                return [self.extract_diarkis_property(item) for item in data]

            # 4. 处理 bytes：尝试解析
            if isinstance(data, bytes):
                success, _type, parsed = SyncProperty.ParseSyncPropertyData(data)
                if success:
                    # 解析成功后，递归调用自身。
                    # 原因是：解析出来的对象(parsed)可能本身也是一个包含 bytes 的 dict/list
                    return self.extract_diarkis_property(parsed)
                else:
                    # 解析失败，保持原样
                    return data

            # 5. 其他基本类型 (int, str, bool 等)，直接返回
            return data

    def _populate_tree(self, parent_item, data):
        if isinstance(data, dict):
            for key, value in data.items():
                node = QTreeWidgetItem(parent_item)
                node.setText(0, str(key))
                node.setData(1, Qt.ItemDataRole.UserRole, value)
                if isinstance(value, (dict, list)):
                    type_name = "dict" if isinstance(value, dict) else "list"
                    node.setText(1, f"<{type_name} len={len(value)}>")
                    node.setForeground(1, Qt.GlobalColor.gray)
                    self._populate_tree(node, value)
                else:
                    node.setText(1, str(value))
        elif isinstance(data, list):
            for index, value in enumerate(data):
                node = QTreeWidgetItem(parent_item)
                node.setText(0, f"[{index}]")
                node.setData(1, Qt.ItemDataRole.UserRole, value)
                if isinstance(value, (dict, list)):
                    type_name = "dict" if isinstance(value, dict) else "list"
                    node.setText(1, f"<{type_name} len={len(value)}>")
                    node.setForeground(1, Qt.GlobalColor.gray)
                    self._populate_tree(node, value)
                else:
                    node.setText(1, str(value))
        else:
            node = QTreeWidgetItem(parent_item)
            node.setText(0, "Root")
            node.setText(1, str(data))
            node.setData(1, Qt.ItemDataRole.UserRole, data)
        

# --- 2. 新的 Dialog 定义 (左右分栏) ---
class SplitViewerDialog(QDialog):
    def __init__(self, parent=None, content=None):
        super().__init__(parent)
        self.setWindowTitle("Diarkis Msgpack 结构化查看器")
        self.resize(1000, 800) # 稍微宽一点，方便左右展示
        
        # 主布局
        main_layout = QVBoxLayout()
        self.setLayout(main_layout)

        # 顶部工具栏 (放一个按钮来触发解析)
        top_bar = QHBoxLayout()
        self.btn_parse = QPushButton("解析并生成树形图 (>>)")
        self.ori_chkbox = QCheckBox("显示解析后的Diarkis Property")
        self.btn_parse.clicked.connect(self.parse_and_display)
        self.ori_chkbox.clicked.connect(self.parse_and_display)
        top_bar.addWidget(QLabel("原始文本 (JSON/Dict):"))
        top_bar.addStretch()
        top_bar.addWidget(self.btn_parse)
        top_bar.addWidget(self.ori_chkbox)
        main_layout.addLayout(top_bar)


        # --- 核心部分：QSplitter ---
        # 创建水平分割器
        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # 左边：TextEdit
        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setPlaceholderText("在此处粘贴 JSON 字符串或 Python 字典文本...")
        
        # 右边：我们封装好的 TreeWidget
        self.tree_widget = DictTreeWidget()

        # 将控件添加到分割器
        self.splitter.addWidget(self.text_edit)
        self.splitter.addWidget(self.tree_widget)

        self.tree_widget.itemClicked.connect(self.on_tree_item_clicked)
        
        # 设置分割器的初始比例 (例如 4:6)
        self.splitter.setStretchFactor(0, 4)
        self.splitter.setStretchFactor(1, 6)

        # 将分割器添加到主布局
        main_layout.addWidget(self.splitter)

        self.diarkis_property = None
        if content:
            try:
                self.diarkis_property = ast.literal_eval(content)
            except Exception as e:
                print(f"解析初始内容失败: {e}")
        self.text_edit.setText(content)

    def parse_and_display(self):
        """
        获取左侧文本，尝试解析，并在右侧显示
        """
        text = self.text_edit.toPlainText().strip()
        if not text:
            return
        try:
            # 1. 尝试按标准 JSON 解析
            data = ast.literal_eval(text)
        except Exception:
            QMessageBox.critical(self, "解析错误", f"不是有效的Diarkis MsgPack Dict格式")
            return
        self.tree_widget.showDeserialized = self.ori_chkbox.isChecked()
        # 成功解析后，加载到树形图
        self.tree_widget.load_data(data)
        self.tree_widget.expandAll() # 自动展开所有节点

    def on_tree_item_clicked(self, item: QTreeWidgetItem, column):
        """
        当树节点被点击时触发
        """
        # 获取存储在 UserRole 里的原始数据 (注意我们存在了第1列)
        raw_data = item.data(1, Qt.ItemDataRole.UserRole)
        TextViewerDialog(str(raw_data), "节点详细信息", self).exec()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("diarkis helper")
        self.resize(1280, 800)
        self.init_menu()
        self.init_ui()
        self.diarkis_proto = {
            1: 'UDP_PROTO',
            2: 'SYN',
            3: 'DAT',
            4: 'ACK',
            5: 'RST',
            6: 'EACK',
            7: 'FIN'
        }

    def init_menu(self):
        menu_bar = self.menuBar()

        # --- 文件菜单 ---
        file_menu = menu_bar.addMenu("文件")

        # 动作：打开
        open_action = QAction("打开文件...", self)
        open_action.setShortcut("Ctrl+O")
        # 2. 修改连接：不再打印 print，而是连接到 self.open_file_dialog
        open_action.triggered.connect(self.open_file_dialog) 
        file_menu.addAction(open_action)

        close_action = QAction("关闭", self)
        close_action.triggered.connect(self.close)
        file_menu.addAction(close_action)

        # --- 视图菜单 ---
        view_menu = menu_bar.addMenu("视图")
        reset_action = QAction("重置", self)
        reset_action.setShortcut("Ctrl+R")
        reset_action.triggered.connect(self.reset_all_filters)
        view_menu.addAction(reset_action)

        # --- 帮助菜单 ---
        help_menu = menu_bar.addMenu("帮助")
        about_action = QAction("关于", self)
        about_action.triggered.connect(lambda: QMessageBox.information(self, "关于", "文件选择演示"))
        help_menu.addAction(about_action)

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        central_widget.setLayout(layout)

        self.table = QTableWidget(0, 9)
        self.headers = ["发送方", "SendSeq", "SID", "Proto", "Push", "Cmd", "Ver", "Status", "Data"]
        self.column_filters = {}
        self.table.setHorizontalHeaderLabels(self.headers)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        header.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        header.customContextMenuRequested.connect(self.show_header_menu)

        self.table.cellClicked.connect(self.on_cell_clicked)
        layout.addWidget(self.table)

    def show_header_menu(self, pos):
        """显示表头的筛选菜单"""
        header = self.table.horizontalHeader()
        logical_index = header.logicalIndexAt(pos)
        if logical_index in [8]:
            return
        unique_values = self.get_column_unique_values(logical_index)
        
        menu = QMenu(self)
        
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # 标题
        col_name = self.headers[logical_index]
        layout.addWidget(QLabel(f"筛选: {col_name}"))

        # 功能按钮区（全选/清空）
        btn_layout = QHBoxLayout()
        btn_all = QPushButton("全选")
        btn_none = QPushButton("清空")
        btn_layout.addWidget(btn_all)
        btn_layout.addWidget(btn_none)
        layout.addLayout(btn_layout)

        list_widget = QListWidget()
        list_widget.setFixedHeight(200)
        
        current_filter_set = self.column_filters.get(logical_index, None)
        
        # 填充列表
        items = []
        sorted_values = sorted(list(unique_values))
        for val in sorted_values:
            item = QListWidgetItem(val)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable) # 开启复选框
            
            if current_filter_set is None or val in current_filter_set:
                item.setCheckState(Qt.CheckState.Checked)
            else:
                item.setCheckState(Qt.CheckState.Unchecked)
            
            list_widget.addItem(item)
            items.append(item)
            
        layout.addWidget(list_widget)

        # 全选/清空按钮逻辑
        def select_all():
            for item in items: item.setCheckState(Qt.CheckState.Checked)
        def select_none():
            for item in items: item.setCheckState(Qt.CheckState.Unchecked)
            
        btn_all.clicked.connect(select_all)
        btn_none.clicked.connect(select_none)

        # 确定按钮
        confirm_btn = QPushButton("确定")
        layout.addWidget(confirm_btn)

        # 将 Widget 放入菜单
        action = QWidgetAction(menu)
        action.setDefaultWidget(widget)
        menu.addAction(action)

        # 连接确定按钮信号
        confirm_btn.clicked.connect(lambda: self.apply_filter(logical_index, list_widget, menu))

        menu.exec(header.mapToGlobal(pos))

    def get_column_unique_values(self, col):
        values = set()
        for row in range(self.table.rowCount()):
            item = self.table.item(row, col)
            text = item.text() if item else ""
            values.add(text)
        return values
    
    def apply_filter(self, col_index, list_widget, menu):
        """应用筛选条件"""
        menu.close()
        
        # 收集所有被勾选的项目
        selected_values = set()
        all_items_count = list_widget.count()
        checked_count = 0
        
        for i in range(all_items_count):
            item = list_widget.item(i)
            if item.checkState() == Qt.CheckState.Checked:
                selected_values.add(item.text())
                checked_count += 1
        
        # 逻辑判断：
        # 如果全部都选了，或者一个都没选（通常视为重置或不显示，这里视为重置），则移除过滤器
        # 这里的逻辑是：只有当 用户选择了部分内容 时，才记录过滤器
        if checked_count == all_items_count:
            # 如果全选，相当于移除该列过滤
            if col_index in self.column_filters:
                del self.column_filters[col_index]
            self.table.horizontalHeaderItem(col_index).setText(self.headers[col_index])
        else:
            # 记录过滤集合
            self.column_filters[col_index] = selected_values
            # 修改表头显示，提示已筛选
            self.table.horizontalHeaderItem(col_index).setText(f"{self.headers[col_index]} ▼")

        self.refresh_table_visibility()

    def refresh_table_visibility(self):
        """根据所有列的过滤条件，刷新表格行的显示/隐藏状态"""
        row_count = self.table.rowCount()
        
        for row in range(row_count):
            should_show = True
            
            for col, allowed_values in self.column_filters.items():
                item = self.table.item(row, col)
                text = item.text() if item else ""
                
                if text not in allowed_values:
                    should_show = False
                    break
            
            self.table.setRowHidden(row, not should_show)

    # --- 新增部分：核心重置逻辑 ---
    def reset_all_filters(self):
        """清除所有列的筛选条件，还原表格"""
        
        # 1. 清空字典
        self.column_filters.clear()
        
        # 2. 还原所有表头的文字（去掉 ▼）
        for col in range(self.table.columnCount()):
            if col < len(self.headers):
                self.table.horizontalHeaderItem(col).setText(self.headers[col])
        
        # 3. 显示所有行
        for row in range(self.table.rowCount()):
            self.table.setRowHidden(row, False)

    # --- 3. 新增：文件选择逻辑 ---
    def open_file_dialog(self):
        """弹出文件选择框并处理文件"""
        file_path, filter_type = QFileDialog.getOpenFileName(
            self,                  # 父窗口
            "请选择一个文本文件",     # 弹窗标题
            "",                    # 默认打开路径 (空字符串表示当前目录或上次打开的目录)
            "har文件 (*.har);;所有文件 (*)" # 文件过滤器
        )

        # 如果用户点击了“取消”，file_path 会是空字符串
        if file_path:
            print(f"用户选择了: {file_path}")
            har = har_helper.export_diarkis_responses(file_path)
            if not har:
                QMessageBox.critical(self, "错误", "没找到任何 diarkis-auth 相关内容")
                return
            diarkis_rsps, udp_ports = har

            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "请选择一个pcap文件",
                "",
                "pcap文件 (*.pcap);;所有文件 (*)"
            )
            if file_path:
                print(f"用户选择了: {file_path}")
                pcap = pcap_helper.parse_udp_cap(file_path, udp_ports)
                if not pcap:
                    QMessageBox.critical(self, "错误", "pcap解析失败或未找到相关UDP包")
                    return
            self.table.clearContents()
            self.table.setRowCount(len(pcap))
            for row, data in enumerate(pcap):
                payload = data["payload"]
                packet: Packet.UDPPacket = Packet.ParseUDPPacket(payload)
                packet_flag = packet.Flag in (Packet.RUDP_PROTO_DAT, Packet.RUDP_PROTO_RST)
                if packet_flag:
                    parsed_packet: Packet.Parsed = Packet.ParseProtocolPacket(packet.Packet)
                    secret = Packet.Secret()
                    for diarkis_rsp in diarkis_rsps:
                        secret.Key = bytes.fromhex(diarkis_rsp['response_body']["encryptionKey"])
                        secret.Iv = bytes.fromhex(diarkis_rsp['response_body']["encryptionIv"])
                        secret.MacKey = bytes.fromhex(diarkis_rsp['response_body']["encryptionMacKey"])
                        try:
                            real_payload = Packet.ParseProtocolPayload(parsed_packet, secret)
                            break
                        except:
                            continue
                col_data = ''
                if packet_flag and (packet.Flag in [Packet.RUDP_PROTO_DAT, Packet.RUDP_PROTO_RST]):
                    try:
                        col_data = Packet.UnpackMsgPack(real_payload.ActualPayload)
                    except:
                        traceback.print_exc()
                        col_data = str(real_payload.ActualPayload)
                self.table.setItem(row, 0, QTableWidgetItem(data["client"] and "客户端" or "服务器"))
                self.table.setItem(row, 1, QTableWidgetItem(str(packet.Seq)))
                self.table.setItem(row, 2, QTableWidgetItem(str()))
                self.table.setItem(row, 3, QTableWidgetItem(self.diarkis_proto.get(packet.Flag, "Unknown")))
                self.table.setItem(row, 4, QTableWidgetItem(str()))
                self.table.setItem(row, 5, QTableWidgetItem(str(packet_flag and parsed_packet.Header.Cmd or '')))
                self.table.setItem(row, 6, QTableWidgetItem(str(packet_flag and parsed_packet.Header.Ver or '')))
                self.table.setItem(row, 7, QTableWidgetItem(str((packet_flag and not data["client"]) and parsed_packet.Header.Status or '')))
                self.table.setItem(row, 8, QTableWidgetItem(str(col_data or '')))

    def on_cell_clicked(self, row, col):
        if col != 8:
            return
        item = self.table.item(row, col)
        if item:
            dialog = SplitViewerDialog(content=item.text(), parent=self)
            dialog.exec()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())