import sys
import json
import traceback
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget, QDialog, QTextEdit, QMessageBox, QHeaderView,
    QFileDialog  # <--- 1. 新增引入 QFileDialog
)
from PyQt6.QtGui import QAction

from DiarkisUtils import Packet, Encryption
import har_helper
import pcap_helper

class ReadOnlyDialog(QDialog):
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

        self.table = QTableWidget(0, 10)
        self.table.setHorizontalHeaderLabels(["Seq", "发送方", "SendSeq", "SID", "Proto", "Push", "Cmd", "Ver", "Status", "Data"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)

        self.table.cellClicked.connect(self.on_cell_clicked)
        layout.addWidget(self.table)

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
                self.table.setItem(row, 0, QTableWidgetItem(str(row+1)))
                self.table.setItem(row, 1, QTableWidgetItem(data["client"] and "客户端" or "服务器"))
                self.table.setItem(row, 2, QTableWidgetItem(str(packet.Seq)))
                self.table.setItem(row, 3, QTableWidgetItem(str()))
                self.table.setItem(row, 4, QTableWidgetItem(self.diarkis_proto.get(packet.Flag, "Unknown")))
                self.table.setItem(row, 5, QTableWidgetItem(str()))
                self.table.setItem(row, 6, QTableWidgetItem(str(packet_flag and parsed_packet.Header.Cmd or '')))
                self.table.setItem(row, 7, QTableWidgetItem(str(packet_flag and parsed_packet.Header.Ver or '')))
                self.table.setItem(row, 8, QTableWidgetItem(str((packet_flag and not data["client"]) and parsed_packet.Header.Status or '')))
                self.table.setItem(row, 9, QTableWidgetItem(str(col_data or '')))

    def on_cell_clicked(self, row, col):
        item = self.table.item(row, col)
        if item:
            dialog = ReadOnlyDialog(item.text(), parent=self)
            dialog.exec()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())