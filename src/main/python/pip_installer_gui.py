# -*- coding: utf-8 -*-

# pylint: disable=no-name-in-module
# pylint: disable=logging-format-interpolation
# pylint: disable=logging-fstring-interpolation
# pylint: disable=missing-function-docstring
# pylint: disable=too-many-locals
# pylint: disable=too-many-arguments

""" Main module """

import logging
import logging.config
import json
import os
import asyncio
import sys
import re
import datetime
import time
import traceback
import subprocess
import paramiko

from PyQt5 import uic
from PyQt5.QtWidgets import QMainWindow, QApplication, QFileDialog
from PyQt5.QtGui import QTextCursor
from qasync import QEventLoop


CFG_FILE_NAME = ''.join(['config', os.sep, 'pig.cfg'])
PEM_FILE = ''.join(['config', os.sep, 'keyy.pem'])
PIG_LOG_CFG = ''.join(['config', os.sep, 'logger.cfg'])
PIG_LOG_FILE = ''.join(['log', os.sep, 'PipInstallerGui.log'])
CACHE = {}


class MainWindow(QMainWindow):  # pylint: disable=too-few-public-methods
    """ Main Window """

    def __init__(self, ctx, parent):

        super(MainWindow, self).__init__()  # pylint: disable=super-with-arguments
        self.ctx = ctx
        self.parent = parent
        self.has_config = False
        self.ui_path = self.ctx.get_resource('main_window.ui')
        uic.loadUi(self.ui_path, self)

        self.btn_open_folder_files.clicked.connect(self.__get_wheel_file)
        self.pushButton_validate.clicked.connect(self.on_btn_validate_clicked)
        self.pushButton_install.clicked.connect(self.on_btn_install_clicked)
        self.pushButton_clear.clicked.connect(self.on_btn_clear_clicked)

        self.qline_ip.textChanged.connect(self.on_text_changed)

        self.setFixedSize(800,600)
        self.__init_ui()

    def handle_error(self, error_msg=None):  # pylint:  disable=no-self-use

        if error_msg:
            logging.critical(f'err: {error_msg}')
            self.update_gui_msg_board(error_msg)

    def on_btn_validate_clicked(self):
        text_ip_to_check = self.qline_ip.text()
        result = self.parent.validate_ip_machine(text_ip_to_check)
        self.update_gui_msg_board(result)
        if isinstance(result, dict) and 'error' in result.keys():
            self.setup_btn_ui('validate_err')
        elif isinstance(result, dict) and 'message' in result.keys():
            self.setup_btn_ui('validated')

    def on_btn_install_clicked(self):

        try:
            path_pem_file = self.ctx.get_resource(PEM_FILE)
            ip_machine = self.qline_ip.text()
            if self.qline_folder_path.text() == '':
                no_whl_msg = 'Please select a wheel file!'
                self.update_gui_msg_board(no_whl_msg)
            else:
                logging.warning('Start the wheel installation to remote machine')
                wheel_path = self.qline_folder_path.text()
                selected_venv = self.comboBox_venvs.currentText()
                app_names_list = CACHE.get('app_names')
                ignore_requires = self.comboBox_requires.currentText()
                self.setup_btn_ui('start_install')
                self.parent.install_on_target(path_pem_file,
                                              ip_machine,
                                              wheel_path,
                                              selected_venv,
                                              app_names_list,
                                              ignore_requires)

        except FileNotFoundError:
            self.update_gui_msg_board('PEM File NOT found! Please contact IT support')
        except Exception as excp: # pylint: disable=broad-except
            self.update_gui_msg_board(excp)

    def on_text_changed(self):
        if self.has_config:
            self.pushButton_validate.setEnabled(bool(self.qline_ip.text()))
        else:
            self.pushButton_validate.setEnabled(False)

    def on_btn_clear_clicked(self):
        self.update_gui_msg_board('Clearing all base settings')
        self.setup_btn_ui('init')

        self.qline_ip.setText('')
        self.qline_folder_path.setText('')

    def update_gui_msg_board(self, msg):
        formatted_date = datetime.datetime.fromtimestamp(time.time()).strftime('%d %b %y %H:%M:%S')
        _msg = msg
        # logging.debug(f'{type(msg)} >> {msg}')
        if isinstance(msg, dict):
            if 'error' in msg.keys():
                _msg = msg.get('error')
            else:
                _msg = msg.get('message')

        messag = f'[{formatted_date}] {_msg}\n'
        logging.warning(f'messag >> {messag}')
        self.textBrowser_board.moveCursor(QTextCursor.End)
        self.textBrowser_board.ensureCursorVisible()
        self.textBrowser_board.insertPlainText(messag)

    def setup_btn_ui(self, method):

        if method == 'init':
            self.pushButton_validate.setEnabled(False)
            self.pushButton_install.setEnabled(False)
            self.pushButton_clear.setEnabled(True)
        elif method == 'validated':
            self.pushButton_validate.setEnabled(False)
            self.pushButton_install.setEnabled(True)
            self.pushButton_clear.setEnabled(True)
        elif method == 'validate_err':
            self.pushButton_validate.setEnabled(True)
            self.pushButton_install.setEnabled(False)
            self.pushButton_clear.setEnabled(True)
        elif method == 'start_install':
            self.pushButton_validate.setEnabled(False)
            self.pushButton_install.setEnabled(False)
            self.pushButton_clear.setEnabled(False)
        elif method == 'end_install':
            self.pushButton_validate.setEnabled(False)
            self.pushButton_install.setEnabled(False)
            self.pushButton_clear.setEnabled(True)

    def __get_wheel_file(self):
        wheel_file_dialog = QFileDialog()
        path_whl = QFileDialog.getOpenFileName(parent=wheel_file_dialog,
                                               filter ="wheel (*.whl)")
        self.qline_folder_path.setText(path_whl[0])
        logging.info(f'selected wheel file: {path_whl[0]}')

    def __init_ui(self):

        app_version = self.ctx.build_settings.get('version')
        self.version_lbl.setText(app_version)
        self.setup_btn_ui('init')
        # self.textBrowser_board.ensureCursorVisible()
        if CACHE:
            self.has_config = True
            config_venvs = CACHE.get('venvs')
            for _venv in config_venvs:
                self.comboBox_venvs.addItem(_venv, config_venvs[_venv])
        else:
            self.update_gui_msg_board('CONFIG file NOT found!')

        for option in ['yes', 'no']:
            self.comboBox_requires.addItem(option, option)


class PipInstallerGuiApplication(QApplication):    # pylint: disable=too-many-instance-attributes
    """ Pip Installer Gui (PIG) Application """

    def __init__(self, fbs_ctx, main_window_class, *args, **kwargs):

        super().__init__(*args, **kwargs)

        self.fbs_ctx = fbs_ctx
        self.__setup_logger(self.fbs_ctx)
        logging.warning('**** Starting Pip Installer Gui Application ****')
        self.__get_config(self.fbs_ctx)
        # Instantiating MainWindow passed as 'main_windows_class'
        self.main_window = main_window_class(self.fbs_ctx, self)

        logging.debug('self: {}'.format(self))
        self.__async_qt_event_loop = self.__init_async_event_loop()
        self.run_forever()

    def validate_ip_machine(self, ip_to_validate):  # pylint: disable=no-self-use

        result = {}
        flag_valid_ip = False
        regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
        if re.search(regex, ip_to_validate):
            flag_valid_ip = True

        if flag_valid_ip:

            if sys.platform == "linux" or sys.platform == "linux2":
                _ping_counter = '-c 1'
            elif sys.platform == "win32":
                _ping_counter = '-n 1'

            cmd_ = f"ping {_ping_counter} -w 1000 {ip_to_validate}"
            logging.warning(cmd_)
            out = subprocess.run(cmd_, shell=True, check=True)
            logging.warning(f'output ping subprocess > {out}')
            if out.returncode == 1:
                error_msg = f'IP {ip_to_validate} is valid! IP unreachable!'
                result = {'error': error_msg}
            else:
                result = {'message': f'IP {ip_to_validate} is valid and reachable!'}
        else:
            error_msg = f'IP {ip_to_validate} is not valid IP'
            result = {'error': error_msg}

        logging.warning(f'result: {result}')
        return result

    def install_on_target(self,
                          path_pem_file,
                          machine_ip,
                          wheel_path,
                          selected_venv_name,
                          app_names_list,
                          ignore_requires):

        "Install the wheel into the target."

        tmp_remote_path = CACHE.get('tmp_dir').get(selected_venv_name)
        venv_path = CACHE.get('venvs').get(selected_venv_name)
        validation_result = self.__validation_wheel_venv(app_names_list, selected_venv_name, wheel_path)
        logging.info(f'result of validation > {validation_result}')

        if validation_result.get('result') == 'ko' and validation_result.get('error'):
            self.main_window.update_gui_msg_board(validation_result.get('error'))
            self.main_window.setup_btn_ui('validated')
        else:
            _username = 'admin'
            ssh_key = paramiko.RSAKey.from_private_key_file(path_pem_file)
            ssh_conn = paramiko.SSHClient()
            # ssh_conn.load_system_host_keys()
            ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            # ssh_conn.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())
            logging.warning("connecting")
            ssh_conn.connect(hostname=machine_ip, username=_username, pkey=ssh_key)
            logging.warning("connected")

            asyncio.ensure_future(
                self.__async_install_on_target(
                    ssh_conn,
                    wheel_path,
                    venv_path,
                    tmp_remote_path,
                    selected_venv_name,
                    ignore_requires))

    def run_forever(self):

        self.main_window.show()

        try:
            self.__async_qt_event_loop.run_forever()

        except KeyboardInterrupt:
            pass

        except Exception as excp:  # pylint: disable=broad-except
            logging.critical('Exception: {}'.format(excp))

        finally:

            logging.warning('**** closing PIG ***')
            logging.warning('')

        # https://doc.qt.io/qt-5/qobject.html#deleteLater
        self.deleteLater()
        self.__async_qt_event_loop.stop()
        self.__async_qt_event_loop.run_until_complete(
            self.__async_qt_event_loop.shutdown_asyncgens()
        )
        self.__async_qt_event_loop.close()

        sys.exit()

    def __setup_logger(self, fbs_ctx):      # pylint: disable=no-self-use

        path_pig_log_cfg = fbs_ctx.get_resource(PIG_LOG_CFG)
        path_pig_log = fbs_ctx.get_resource(PIG_LOG_FILE)

        with open(path_pig_log_cfg, 'r') as log_file:
            config_log = log_file.read()

        if 'testing.log' in config_log:
            path_pig_log = path_pig_log.replace('\\', '\\\\')
            config_log = config_log.replace('testing.log', path_pig_log)

            logging.debug('config_log: {}'.format(config_log))
            # Write the file out again
            with open(path_pig_log_cfg, 'w') as log_file:
                log_file.write(config_log)

        logging.config.fileConfig(path_pig_log_cfg)

    def __get_config(self, fbs_ctx, cfg_filename=CFG_FILE_NAME):    # pylint: disable=no-self-use

        try:
            filename_cfg = fbs_ctx.get_resource(cfg_filename)
            logging.warning('filename_cfg: {}'.format({filename_cfg}))
            with open(filename_cfg, 'r') as f_alias:
                json_data = json.loads(f_alias.read())

            logging.warning('json_data: {}'.format(json_data))
            CACHE.update(json_data)

        except FileNotFoundError:
            file_not_found = '{} not FOUND!'.format(cfg_filename)
            logging.warning(file_not_found)

    def __validation_wheel_venv(self, app_names, venv_name, whl_path):  # pylint: disable=no-self-use
        """
        Check if selected wheel file is compatible with the selected venv name
        """

        whl_name = os.path.basename(whl_path)
        validation_err_msg = f'Selected wheel ({whl_name}) not compatible with selected venv ({venv_name})!'
        _validation = {'result': 'ko',
                       'error': validation_err_msg}

        for _app_name in app_names:
            logging.info(f'app name > {_app_name} | venv name > {venv_name} | wheel name > {whl_name}')
            if _app_name in venv_name and _app_name in whl_name:
                _validation.update({'result': 'ok', 'error': None})

        return _validation

    def __init_async_event_loop(self):
        qt_event_loop = QEventLoop(self)
        asyncio.set_event_loop(qt_event_loop)
        return qt_event_loop

    async def __async_install_on_target(self,
                                        ssh_conn,
                                        wheel_path,
                                        venv_path,
                                        tmp_remote_path,
                                        selected_venv_name,
                                        ignore_requires):

        try:
            logging.warning("copying wheel file")
            whl_filename = os.path.basename(wheel_path)
            sftp = ssh_conn.open_sftp()
            _tmp_remote_path = ''.join([tmp_remote_path, '/', whl_filename])
            logging.debug(f'wheel_path(local) > {wheel_path} || _tmp_remote_path > {_tmp_remote_path}  ')
            start_time = time.time()
            obj_ = sftp.put(localpath=wheel_path,
                            remotepath=_tmp_remote_path)
            end_time = time.time()
            delta_time = end_time - start_time
            if hasattr(obj_, 'st_size') and obj_.st_size > 0:
                # {'_flags': 15, 'st_size': 4, 'st_uid': 1001, 'st_gid': 1001, 'st_mode': 33204, 'st_atime': 1627568878, 'st_mtime': 1627568878, 'attr': {}}
                logging.info(f'obj_ > {obj_}')
                _original_file_size = os.stat(wheel_path).st_size
                _copied_file_size = obj_.st_size
                logging.debug(f'_copied_file_size({_copied_file_size}) - _original_file_size ({_original_file_size})')
                if _original_file_size != _copied_file_size:
                    size_err_msg = f'copied file size ({os.stat(wheel_path).st_size}) NOT equal to original file size ({obj_.st_size})'
                    self.main_window.update_gui_msg_board(size_err_msg)
                else:
                    copied_msg = f'{whl_filename} was successfully copied in {delta_time}s!'
                    self.main_window.update_gui_msg_board(copied_msg)
                    await asyncio.sleep(1)
                    activate_on_target = f". {venv_path}/bin/activate"
                    app_name = selected_venv_name.split(' - ')[0]
                    logging.debug(f'app_name > {app_name}')

                    cmd_ignore_requires = ''
                    if ignore_requires == 'yes':
                        cmd_ignore_requires = '--ignore-requires --no-dependencies'

                    cmds_ = [
                        f'{activate_on_target}; pip uninstall -y {app_name}',
                        f'{activate_on_target}; pip install {venv_path}/{whl_filename} {cmd_ignore_requires}',
                    ]

                    cmds_.append('sudo supervisorctl reload')
                    logging.warning(cmds_)

                    for command in cmds_:
                        logging.info(f'Executing: {command}')
                        _ , stdout, stderr = ssh_conn.exec_command(command)
                        for line in stdout.readlines():
                            _line = line.rstrip()
                            logging.info(_line)
                            self.main_window.update_gui_msg_board(_line)
                        if stderr and stderr.read().decode() != '':
                            ssh_errors = '{}'.format(stderr.read().decode())
                            logging.error('Errors: {}'.format(ssh_errors))
                            self.main_window.update_gui_msg_board(ssh_errors)

                        await asyncio.sleep(.5)
            else:
                logging.warning('Something wrong with SFPT PUT')

        except Exception:   # pylint: disable=broad-except
            logging.error(traceback.format_exc())

        ssh_conn.close()
        logging.warning(f'closed ssh_conn ({ssh_conn})')
        self.main_window.setup_btn_ui('end_install')
