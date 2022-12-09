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
import glob
import paramiko
import configparser

from pip_errors import PipValidationError
from deepdiff import DeepDiff
from PyQt5 import uic
from PyQt5.QtWidgets import QMainWindow, QApplication, QFileDialog
from PyQt5.QtGui import QTextCursor
from qasync import QEventLoop


CFG_FILE_NAME = ''.join(['config', os.sep, 'config.ini'])
PEM_FILE = ''.join(['config', os.sep, 'keyy.pem'])
PIG_LOG_CFG = ''.join(['config', os.sep, 'logger.cfg'])
PIG_LOG_FILE = ''.join(['log', os.sep, 'PipInstallerGui.log'])
CACHE = {}


class Config:

    def __init__(self, config_file):
  
        self.config_file = config_file       
        self.config_dict = {}
        self.config_sections = None
        self.config_parser = None

    def __repr__(self):
        return f'Config(path={self.config_file})'

    def __get_current_section_as_dict(self, section):
        s_dict = {}
        for key in self.config_parser[section]:  
            s_dict.update({key: self.config_parser[section][key]})
        return s_dict

    def ini_to_dict(self):
        self.config_parser = configparser.ConfigParser(allow_no_value=True)
        self.config_parser.read(self.config_file, encoding='utf-8')

        for s in self.config_parser.sections():

            s_d = self.__get_current_section_as_dict(s)

            if s == 'venvs' or s == 'tmp_dir':
                self.config_dict.update({s: s_d})

            if s == 'wheel_path' or s == 'conf_files_path':
                if s_d:
                    _path = list(s_d.values()).pop()

                    self.config_dict.update({s: _path})

            if s == 'configurations' or s == 'app_names':
                s_list = list(s_d.keys())
                self.config_dict.update({s: s_list})

        return self.config_dict


class MainWindow(QMainWindow):  # pylint: disable=too-few-public-methods
    """ Main Window """

    def __init__(self, ctx, parent):

        super(MainWindow, self).__init__()  # pylint: disable=super-with-arguments
        self.ctx = ctx
        self.parent = parent
        self.has_valid_config = False
        self.ui_path = self.ctx.get_resource('main_window.ui')
        uic.loadUi(self.ui_path, self)

        self.btn_open_folder_files.clicked.connect(self.__get_wheel_file)
        self.pushButton_validate.clicked.connect(self.on_btn_validate_clicked)
        self.pushButton_install.clicked.connect(self.on_btn_install_clicked)
        self.pushButton_deploy.clicked.connect(self.on_btn_deploy_clicked)
        self.pushButton_clear.clicked.connect(self.on_btn_clear_clicked)
        self.pushButton_choose_conf.clicked.connect(self.__get_conf_file_dir)

        self.qline_ip.textChanged.connect(self.on_ip_text_changed)

        self.comboBox_config_files.activated.connect(self.handle_pushButton_choose_conf)

        self.setFixedSize(1024,600)
        self.__init_ui()

    def on_btn_validate_clicked(self):

        try:
            text_ip_to_check = self.qline_ip.text()
            result = self.parent.validate_ip_machine(text_ip_to_check)
            self.setup_or_update_btn_ui('validated')
            self.update_gui_msg_board(result)
        except Exception as exc:    # pylint: disable=broad-except
            logging.error(traceback.format_exc())
            self.update_gui_msg_board(exc)
            self.setup_or_update_btn_ui('validate_err')

    def on_btn_install_clicked(self):

        try:
            map_str_to_bool = {
                'yes': True,
                'no': False
            }
            path_pem_file = self.ctx.get_resource(PEM_FILE)
            ip_machine = self.qline_ip.text()
            wheel_path = self.qline_folder_path.text()
            if wheel_path == '':
                raise RuntimeError('Please select a wheel file!')

            logging.warning('Start the wheel installation to remote machine')
            selected_venv = self.comboBox_venvs.currentText()
            app_names_list = CACHE.get('app_names', [])
            self.setup_or_update_btn_ui('start_install')
            ignore_requires = map_str_to_bool.get(self.comboBox_requires.currentText())
            deploy_user_choose = map_str_to_bool.get(self.comboBox_config_files.currentText())
            self.parent.install_and_deploy_on_target(
                path_pem_file,
                ip_machine,
                wheel_path,
                selected_venv,
                app_names_list,
                ignore_requires,
                deploy_user_choose)

        except FileNotFoundError:
            self.update_gui_msg_board('PEM File NOT found! Please contact IT support')
        except Exception as excp: # pylint: disable=broad-except
            logging.error(traceback.format_exc())
            self.update_gui_msg_board(excp)

    def on_btn_deploy_clicked(self):

        try:
            path_pem_file = self.ctx.get_resource(PEM_FILE)
            ip_machine = self.qline_ip.text()
            if self.qline_folder_conf_path.text() == '':
                no_cfg_folder_msg = 'Please select a CONF Directory'
                self.update_gui_msg_board(no_cfg_folder_msg)
            else:
                logging.warning('Start the config deploy to remote machine')
                cfg_folder_path = self.qline_folder_conf_path.text()
                self.setup_or_update_btn_ui('start_deploy')
                self.parent.deploy_on_target(
                    path_pem_file,
                    ip_machine,
                    cfg_folder_path)

        except FileNotFoundError:
            self.update_gui_msg_board('PEM File NOT found! Please contact IT support')
        except Exception as excp: # pylint: disable=broad-except
            self.update_gui_msg_board(excp)

    def on_ip_text_changed(self):
        if self.has_valid_config:
            self.pushButton_validate.setEnabled(bool(self.qline_ip.text()))
        else:
            self.pushButton_validate.setEnabled(False)

    def on_btn_clear_clicked(self):
        self.update_gui_msg_board(
            msg='Clearing all base settings',
            pretty_print=True)
        self.setup_or_update_btn_ui('init_or_clear')

        self.qline_ip.setText('')
        self.qline_folder_path.setText('')

    def update_gui_msg_board(self, msg, show_datetime=True, pretty_print=False):
        formatted_date = datetime.datetime.fromtimestamp(time.time()).strftime('%d %b %y %H:%M:%S')
        _msg = msg
        # logging.debug(f'{type(msg)} >> {msg}')
        if isinstance(msg, dict):
            if 'error' in msg.keys():
                _msg = msg.get('error')
            else:
                _msg = msg.get('message')

        messag = f'{_msg}\n'
        if show_datetime:
            messag = f'[{formatted_date}] {messag}'
        if pretty_print:
            messag = f'\n{messag}\n'
        logging.debug(f'messag >> {messag}')

        self.textBrowser_board.moveCursor(QTextCursor.End)
        self.textBrowser_board.ensureCursorVisible()
        self.textBrowser_board.insertPlainText(messag)

    def setup_or_update_btn_ui(self, method):

        if method == 'init_or_clear':
            self.pushButton_validate.setEnabled(False)
            self.pushButton_install.setEnabled(False)
            self.pushButton_deploy.setEnabled(False)
            self.pushButton_clear.setEnabled(True)
            self.pushButton_choose_conf.setEnabled(False)
            self.comboBox_requires.setCurrentIndex(0)
            self.comboBox_config_files.setCurrentIndex(0)
            self.qline_folder_conf_path.setText('')
            self.qline_folder_path.setText('')
            self.comboBox_config_files.setEnabled(False)
        elif method == 'validated':
            self.pushButton_validate.setEnabled(False)
            self.pushButton_install.setEnabled(True)
            self.pushButton_deploy.setEnabled(True)
            self.pushButton_clear.setEnabled(True)
            self.comboBox_config_files.setEnabled(True)
        elif method == 'validate_err':
            self.pushButton_validate.setEnabled(True)
            self.pushButton_install.setEnabled(False)
            self.pushButton_deploy.setEnabled(False)
            self.pushButton_clear.setEnabled(True)
            self.comboBox_config_files.setEnabled(False)
        elif method in ('start_install', 'start_deploy'):
            self.pushButton_validate.setEnabled(False)
            self.pushButton_install.setEnabled(False)
            self.pushButton_deploy.setEnabled(False)
            self.pushButton_clear.setEnabled(False)
            self.pushButton_choose_conf.setEnabled(False)
            self.comboBox_config_files.setEnabled(False)
        elif method in ('end_install', 'end_deploy'):
            self.pushButton_validate.setEnabled(False)
            self.pushButton_install.setEnabled(False)
            self.pushButton_deploy.setEnabled(False)
            self.pushButton_clear.setEnabled(True)
            self.pushButton_choose_conf.setEnabled(False)
            self.comboBox_requires.setCurrentIndex(0)
            self.comboBox_config_files.setCurrentIndex(0)
            self.qline_folder_conf_path.setText('')
            self.qline_folder_path.setText('')
            self.comboBox_config_files.setEnabled(False)

    def handle_pushButton_choose_conf(self):
        selected_choose = self.comboBox_config_files.currentText()

        if selected_choose == 'yes':
            self.pushButton_choose_conf.setEnabled(True)
        else:
            self.pushButton_choose_conf.setEnabled(False)

    def __get_wheel_file(self):
        config_wheel_path = CACHE.get('wheel_path')
        path_whl = QFileDialog.getOpenFileName(
            QFileDialog(),
            'Open file',
            config_wheel_path,
            "wheel (*.whl)",)
        self.qline_folder_path.setText(path_whl[0])
        logging.info(f'selected wheel file: {path_whl[0]}')

    def __get_conf_file_dir(self):
        conf_files_path = CACHE.get('conf_files_path')
        path_whl = QFileDialog.getExistingDirectory(
            QFileDialog(),
            'Open Directory',
            conf_files_path,
            QFileDialog.ShowDirsOnly)
        self.qline_folder_conf_path.setText(path_whl)
        logging.info(f'selected wheel file: {path_whl}')

    def __init_ui(self):

        app_version = self.ctx.build_settings.get('version')
        self.version_lbl.setText(app_version)
        self.setup_or_update_btn_ui('init_or_clear')

        for option in ['no', 'yes']:
            self.comboBox_requires.addItem(option, option)

        for option in ['no', 'yes']:
            self.comboBox_config_files.addItem(option, option)

        try:
            if not CACHE:
                raise RuntimeError('CONFIG file NOT found!')

            self.parent.validate_configuration(CACHE)
            self.has_valid_config = True
            config_venvs = CACHE.get('venvs')
            for _venv in config_venvs:
                self.comboBox_venvs.addItem(_venv, config_venvs[_venv])
        except Exception as exc:    # pylint: disable=broad-except
            logging.error(traceback.format_exc())
            self.update_gui_msg_board(exc)


class PipInstallerGuiApplication(QApplication):    # pylint: disable=too-many-instance-attributes
    """ Pip Installer Gui (PIG) Application """

    def __init__(self, fbs_ctx, main_window_class, *args, **kwargs):

        super().__init__(*args, **kwargs)

        self.fbs_ctx = fbs_ctx
        self.__setup_logger(self.fbs_ctx)
        logging.warning('**** Starting Pip Installer Gui Application ****')
        self.__load_config_from_file(self.fbs_ctx)
        # Instantiating MainWindow passed as 'main_windows_class'
        self.main_window = main_window_class(self.fbs_ctx, self)

        logging.debug('self: {}'.format(self))
        self.__async_qt_event_loop = self.__init_async_event_loop()
        self.run_forever()

    def install_and_deploy_on_target(self,
                                     path_pem_file,
                                     machine_ip,
                                     wheel_path,
                                     selected_venv_name,
                                     app_names_list,
                                     ignore_requires,
                                     deploy_choose):

        """
        Install the selected wheel file into the target.
        If deploy choose is selected, deploy the conf files to the target
        """

        tmp_remote_path = CACHE.get('tmp_dir').get(selected_venv_name)
        venv_path = CACHE.get('venvs').get(selected_venv_name)
        validation_result = self.__validation_wheel_venv(app_names_list, selected_venv_name, wheel_path)
        logging.info(f'result of validation > {validation_result}')

        if validation_result.get('result') == 'ko' and validation_result.get('error'):
            validation_wheel_err_msg = validation_result.get('error')
            self.main_window.setup_or_update_btn_ui('validated')
            raise PipValidationError(validation_wheel_err_msg)

        ssh_conn = self.create_ssh_connection_to_server(machine_ip, path_pem_file)

        asyncio.ensure_future(
            self.__async_install_and_deploy_on_target(
                ssh_conn,
                wheel_path,
                venv_path,
                tmp_remote_path,
                selected_venv_name,
                ignore_requires,
                deploy_choose)
        )

    def deploy_on_target(
            self,
            path_pem_file,
            ip_machine,
            cfg_folder_path,):

        "Deploy the selected config files into the target"

        logging.warning(f'cfg_folder_path > {cfg_folder_path}')

        try:
            ssh_conn = self.create_ssh_connection_to_server(ip_machine, path_pem_file)
            asyncio.ensure_future(
                self.__async_deploy_on_target(
                    ssh_conn=ssh_conn,
                    cfg_folder_path=cfg_folder_path,
                    reload_supervisor=True)
            )
        except Exception as e:  # pylint: disable=broad-except
            logging.error(traceback.format_exc())
            self.main_window.update_gui_msg_board(e)

    def run_forever(self):

        self.main_window.show()

        try:
            self.__async_qt_event_loop.run_forever()

        except KeyboardInterrupt:
            pass

        except Exception as excp:  # pylint: disable=broad-except
            logging.critical('Exception: {}'.format(excp))

        finally:

            logging.warning('**** Closing Pip Installer Gui Application ***')
            logging.warning('')

        # https://doc.qt.io/qt-5/qobject.html#deleteLater
        self.deleteLater()
        self.__async_qt_event_loop.stop()
        self.__async_qt_event_loop.run_until_complete(
            self.__async_qt_event_loop.shutdown_asyncgens()
        )
        self.__async_qt_event_loop.close()

        sys.exit()

    def __init_async_event_loop(self):
        qt_event_loop = QEventLoop(self)
        asyncio.set_event_loop(qt_event_loop)
        return qt_event_loop

    async def __async_paramiko_sftp_put(self,
                                        ssh_conn,
                                        local_path,
                                        remote_path,
                                        sftp=None,
                                        print_to_gui=True):

        # https://docs.paramiko.org/en/latest/api/sftp.html

        if sftp is None:
            sftp = ssh_conn.open_sftp()
        start_time = time.time()
        obj_ = sftp.put(
            localpath=local_path,
            remotepath=remote_path)
        end_time = time.time()
        delta_time = end_time - start_time
        self.processEvents()

        # sample of SFTPAttributes object
        # {'_flags': 15, 'st_size': 4, 'st_uid': 1001, 'st_gid': 1001, 'st_mode': 33204, 'st_atime': 1627568878, 'st_mtime': 1627568878, 'attr': {}}

        if not hasattr(obj_, 'st_size'):
            raise AttributeError('SFTPAttributes object from "put" does not have the attribute "st_size"')

        if not obj_.st_size != 0:
            raise ValueError('SFTPAttributes object must have a size greater than 0')

        logging.info(f'obj_ > {obj_}')
        _original_file_size = os.stat(local_path).st_size
        _copied_file_size = obj_.st_size
        logging.debug(f'_copied_file_size({_copied_file_size}) - _original_file_size ({_original_file_size})')

        if _original_file_size != _copied_file_size:
            size_err_msg = f'Copied file size ({os.stat(local_path).st_size}) NOT equal to original file size ({obj_.st_size})'
            raise ValueError(size_err_msg)

        filename = os.path.basename(local_path)
        copied_msg = f'{filename} was successfully copied in {delta_time}s!'
        logging.info(copied_msg)
        if print_to_gui:
            self.main_window.update_gui_msg_board(copied_msg)

    async def __async_paramiko_exec_commands(self, ssh_conn, cmd_list, timeout=.5, print_to_gui=True):

        if ssh_conn.get_transport() is None:
            raise_msg = f"SSH CONNECTION TRANSPORT not founded! Failed to execute cmds {cmd_list}"
            raise RuntimeError(raise_msg)

        if not ssh_conn.get_transport().is_active():
            raise_msg = f"SSH CONNECTION TRANSPORT is not active! Failed to execute cmds {cmd_list}"
            raise RuntimeError(raise_msg)

        stdouts = []
        stderrs = []
        for command in cmd_list:
            logging.info(f'Executing: {command}')
            _, stdout, stderr = ssh_conn.exec_command(command)
            for line in stdout.readlines():
                _line = line.rstrip()
                logging.info(_line)
                stdouts.append(_line)
                if print_to_gui:
                    self.main_window.update_gui_msg_board(_line)
            if stderr and stderr.read().decode() != '':
                ssh_errors = '{}'.format(stderr.read().decode())
                if ssh_errors:
                    logging.error('Errors: {}'.format(ssh_errors))
                    stderrs.append(ssh_errors)
                    if print_to_gui:
                        self.main_window.update_gui_msg_board(ssh_errors)

            await asyncio.sleep(timeout)

        return (stdouts, stderrs)

    async def __validate_platform_alfa(self, ssh_client):
        """
        Platform alfa must be a generic-purpose platform in order to
        deploy configs.
        """

        validated = False
        lsb_release = {}

        try:
            with ssh_client.open_sftp() as sftp_client:
                with sftp_client.open('/etc/lsb-release') as remote_file:
                    for line in remote_file:
                        if line and line.rstrip():
                            (key, value) = line.split('=')
                            value = value.strip('\"\n')
                            lsb_release[key] = value

            logging.debug(lsb_release)
            validated = 'general-purpose' in lsb_release.get('DISTRIB_DESCRIPTION', None)
            validated = validated and lsb_release.get('PLATFORM_VERSION', None)

        except IOError as e:
            no_lsbrelease_file_found_msg = 'File "lsb-release" not found ! Validation failed !'
            no_lsbrelease_file_found_msg += '\n ABORTING ...'
            raise PipValidationError(no_lsbrelease_file_found_msg) from e
        except Exception as excpp:
            validation_platform_excp_err = 'Impossible to verify the Alfa Platform! Please read log file for more details.'
            validation_platform_excp_err += '\n ABORTING ...'
            logging.error(traceback.format_exc())
            raise PipValidationError(validation_platform_excp_err) from excpp

        return validated

    async def __validate_config(self, conf_name, conf_path, ssh_conn):
        """
        Config folder name must be check (we do not want to remote copy
        files from a wrong folder or from a subfolder inside the Config folder)

        We then compare the tree json file (adapted from the Linux command
        'tree -J <folder conf>') with the same structure generated
        at runtime from the path provided to check the validity of
        the configuration.
        """

        cfg_validated = True
        validate_cfg_names = CACHE.get('configurations', [])
        if not validate_cfg_names:
            missing_cfg_names_msg = 'Missing config names in Pip Installer Gui Config file !'
            missing_cfg_names_msg += '\n ABORTING ...'
            raise PipValidationError(missing_cfg_names_msg)

        def generate_folder_tree_dict(path):
            folder_tree_dict = {'name': os.path.basename(path)}
            if os.path.isdir(path):
                folder_tree_dict['type'] = "directory"
                folder_tree_dict["contents"] = [
                    generate_folder_tree_dict(os.path.join(path, x))
                    for x in os.listdir(path)
                    if "tree_validator" not in x
                ]
            else:
                folder_tree_dict['type'] = "file"
            return folder_tree_dict

        try:

            if conf_name not in validate_cfg_names:
                no_valid_conf_name_msg = f'Current selected configuration "{conf_name}" is not allowed !'
                no_valid_conf_name_msg += f'\n Allowed configurations: {validate_cfg_names}'
                no_valid_conf_name_msg += '\n ABORTING ...'
                raise PipValidationError(no_valid_conf_name_msg)

            validator_tree_file_path = os.path.join(
                conf_path, f'{conf_path}/{conf_name}_tree_validator.json')
            config_folder_tree_dict = generate_folder_tree_dict(conf_path)

            platform = await self.__get_platform_type(ssh_conn)
            if any(x in conf_name for x in ['CR6_485', 'CR4_485']):
                if not platform in conf_name:
                    invalid_platform_msg = f'Current selected configuration "{conf_name}" is not compatible with '
                    invalid_platform_msg += f'the current platform "{platform}" !'
                    invalid_platform_msg += '\n ABORTING ...'
                    raise PipValidationError(invalid_platform_msg)

            with open(validator_tree_file_path) as f:
                validator_tree_dict = json.load(f)
                logging.debug(f'Config tree: {config_folder_tree_dict}')
                logging.debug(f'Validator file tree: {validator_tree_dict}')
                diff_dict = DeepDiff(validator_tree_dict, config_folder_tree_dict, ignore_order=True)
                logging.info(f'Config tree files diff >>>> {diff_dict}')
                if diff_dict:
                    cfg_validated = False

        except FileNotFoundError as fexcp:
            no_tree_json_file_found_msg = f'File "{conf_name}_tree_validator.json" not found ! Validation failed !'
            no_tree_json_file_found_msg += '\n ABORTING ...'
            raise PipValidationError(no_tree_json_file_found_msg) from fexcp
        except Exception as excpt:
            logging.error(traceback.format_exc())
            raise PipValidationError(excpt)

        return cfg_validated

    async def __get_installed_chromium_browser_debian_pkg(self, ssh_conn):
        """
        On BPi it is installed the pkg "chromium"
        On RBPi usually it is installed the pkg "chromium"
        On RBPi general-purpose platform it is installed the pkg "chromium-browser" to fix
        an issue on AlfaTint (legacy software)

        # RBPi uname -a -> Linux raspberrypi 5.10.63-v7l+ #1459 SMP Wed Oct 6 16:41:57 BST 2021 armv7l GNU/Linux
        # BPi uname -a -> Linux bananapi 4.9.241-BPI-M5 #2 SMP PREEMPT Mon Jun 21 16:29:40 HKT 2021 aarch64 GNU/Linux

        """

        browser_cmd = [
            '[[ -f /usr/bin/chromium-browser ]] && echo "chromium-browser founded!"']
        std_outs, std_errs = await self.__async_paramiko_exec_commands(
            ssh_conn=ssh_conn,
            cmd_list=browser_cmd,
            print_to_gui=False)

        logging.debug(f'std_outs >> {std_outs}')
        logging.debug(f'std_errs >> {std_errs}')

        assert not std_errs

        installed_browser = 'chromium'
        if len(std_outs) > 0 and any('chromium-browser' in out for out in std_outs):
            installed_browser = 'chromium-browser'

        logging.debug(f'installed_browser >> {installed_browser}')

        return installed_browser

    async def __get_platform_type(self, ssh_conn):
        """
        uname -a Alfa images
        # RBPi -> Linux raspberrypi 5.10.63-v7l+ #1459 SMP Wed Oct 6 16:41:57 BST 2021 armv7l GNU/Linux
        # BPi -> Linux bananapi 4.9.241-BPI-M5 #2 SMP PREEMPT Mon Jun 21 16:29:40 HKT 2021 aarch64 GNU/Linux
        # BPi Armbian -> Linux bananapim5 5.10.51-meson64 #trunk SMP PREEMPT Tue Jul 20 00:56:03 CST 2021 aarch64 GNU/Linux

        """

        std_outs, std_errs = await self.__async_paramiko_exec_commands(
            ssh_conn=ssh_conn,
            cmd_list=['uname -a'],
            print_to_gui=False)

        logging.debug(f'std_outs >> {std_outs}')
        logging.debug(f'std_errs >> {std_errs}')

        assert not std_errs
        assert std_outs

        current_platform = None
        if 'bananapi' in std_outs[0]:
            current_platform = 'Bananapi'
        if 'raspberrypi' in std_outs[0]:
            current_platform = 'RBpi'

        logging.debug(f'current_platform >> {current_platform}')

        return current_platform

    async def __async_upload_multiple_files(
            self,
            ssh_conn,
            curr_cfg_folder_path,
            conf_remote_path):

        async def sftp_multiple_upload(path_files, remote_path_files, sftp_client):
            for elem in path_files:
                filename = os.path.basename(elem)
                elem_remote_path = ''.join([remote_path_files, '/', filename])
                logging.debug(f'elem_remote_path > {elem_remote_path}')
                if os.path.isfile(elem):
                    logging.info(f'{elem} is a FILE')
                    await self.__async_paramiko_sftp_put(
                        ssh_conn=ssh_conn,
                        local_path=elem,
                        remote_path=elem_remote_path,
                        sftp=sftp_client)
                else:
                    logging.info(f'{elem} is a DIRECTORY')
                    sftp_client.mkdir(elem_remote_path)
                    logging.info(f'Created remote Directory named "{filename}"')
                    logging.info(f'elements inside the DIRECTORY "{filename}" > {glob.glob(f"{elem}/*")}')
                    dir_files = glob.glob(f"{elem}/*")
                    remote_dir_files = f'{remote_path_files}/{filename}'
                    await sftp_multiple_upload(
                        path_files=dir_files,
                        remote_path_files=remote_dir_files,
                        sftp_client=sftp_client)

        current_cfg_files = glob.glob(f"{curr_cfg_folder_path}/*")
        logging.info(f"current_cfg_files: {current_cfg_files}")
        current_cfg_name = os.path.basename(curr_cfg_folder_path)

        sftp_client = ssh_conn.open_sftp()

        await sftp_multiple_upload(
            path_files=current_cfg_files,
            remote_path_files=conf_remote_path,
            sftp_client=sftp_client)

        if 'alfalib' in current_cfg_name and any('supervisor_conf.d' in p for p in current_cfg_files):
            supervisor_cmds = [
                f'sudo cp -r {CACHE.get("remote_conf_path")}/supervisor_conf.d/* {CACHE.get("remote_supervisor_conf_path")}',
                f'sudo rm -rf {CACHE.get("remote_conf_path")}/supervisor_conf.d/'
            ]
            await self.__async_paramiko_exec_commands(
                ssh_conn=ssh_conn,
                cmd_list=supervisor_cmds)

    async def __async_install_and_deploy_on_target(
            self,
            ssh_conn,
            wheel_path,
            venv_path,
            tmp_remote_path,
            selected_venv_name,
            ignore_requires,
            deploy_choose):

        try:
            logging.warning("copying wheel file")
            whl_filename = os.path.basename(wheel_path)
            _tmp_remote_path = ''.join([tmp_remote_path, '/', whl_filename])
            logging.warning(f'wheel_path(local) > {wheel_path} || _tmp_remote_path > {_tmp_remote_path}  ')

            await self.__async_paramiko_sftp_put(
                ssh_conn=ssh_conn,
                local_path=wheel_path,
                remote_path=_tmp_remote_path,)

            await asyncio.sleep(1)
            activate_on_target = f". {venv_path}/bin/activate"
            app_name = selected_venv_name.split(' - ')[0]
            logging.debug(f'app_name > {app_name}')

            cmd_ignore_requires = ''
            if ignore_requires:
                cmd_ignore_requires = '--ignore-requires --no-dependencies'

            cmds_ = [
                f'{activate_on_target}; pip uninstall -y {app_name}',
                f'{activate_on_target}; pip install {_tmp_remote_path} {cmd_ignore_requires}',
            ]
            logging.warning(cmds_)
            await self.__async_paramiko_exec_commands(
                ssh_conn=ssh_conn,
                cmd_list=cmds_)

            if deploy_choose:
                platform_config_path = self.main_window.qline_folder_conf_path.text()
                logging.warning(f'platform_config_path >> {platform_config_path}')
                await self.__async_deploy_on_target(
                    ssh_conn=ssh_conn,
                    cfg_folder_path=platform_config_path,
                    close_ssh=False)

            await self.__async_paramiko_exec_commands(
                ssh_conn=ssh_conn,
                cmd_list=['sudo supervisorctl reload'])

        except Exception:   # pylint: disable=broad-except
            logging.error(traceback.format_exc())

        if ssh_conn.get_transport() is not None and ssh_conn.get_transport().is_active():
            logging.warning(f'ssh_conn active: {ssh_conn.get_transport().is_active()}')
            ssh_conn.close()
            logging.warning(f'closed ssh_conn ({ssh_conn})')
            self.main_window.setup_or_update_btn_ui('end_install')

    async def __async_deploy_on_target(self, ssh_conn, cfg_folder_path, close_ssh=True, reload_supervisor=False):

        conf_name = os.path.basename(cfg_folder_path)

        try:
            validated_platform = await self.__validate_platform_alfa(ssh_conn)
            if not validated_platform:
                invalid_platform_msg = 'Invalid platform version! The current platform is not an "Alfa custom general-purpose platform" !'
                invalid_platform_msg += '\n ABORTING ...'
                raise PipValidationError(invalid_platform_msg)

            await self.__validate_config(conf_name, cfg_folder_path, ssh_conn)

            conf_remote_path = CACHE.get("remote_conf_path", "")
            autostart_remote_path = CACHE.get("remote_autostart_path", "")
            supervisor_conf_remote_path = CACHE.get("remote_supervisor_conf_path", "")

            assert conf_remote_path
            assert autostart_remote_path
            assert supervisor_conf_remote_path

            chromium_browser = await self.__get_installed_chromium_browser_debian_pkg(ssh_conn)
            autostart_cmd_pt1 = f'grep -q "@/usr/bin/{chromium_browser}" /home/admin/.config/lxsession/LXDE/autostart'
            autostart_cmd_pt2 = f'&& (sed -i "/{chromium_browser} --disable-restore-session-state --no-first-run --kiosk/d" {autostart_remote_path})'
            if 'alfalib' in conf_name:
                autostart_cmd_pt2 = f'|| (echo "@/usr/bin/{chromium_browser} --disable-restore-session-state --no-first-run --kiosk 127.0.0.1"'
                autostart_cmd_pt2 += f' | sudo tee -a {autostart_remote_path})'

            deploy_msg_start = f'Start to deploy conf "{conf_name}"'
            logging.warning(f'{deploy_msg_start}' + f' ({cfg_folder_path})')
            self.main_window.update_gui_msg_board(deploy_msg_start)

            cmds_ = [
                f'rm -rf {conf_remote_path}/custom_css/',
                f'rm -rf {conf_remote_path}/*supervisor/',
                f'rm -rf {conf_remote_path}/supervisor_conf.d/',
                f'rm {conf_remote_path}/dispatcher_conf.py',
                f'rm {conf_remote_path}/flask_conf.py',
                f'rm {conf_remote_path}/supervisord.conf',
                f'rm {conf_remote_path}/labeler_conf.py',
                f'rm {conf_remote_path}/marshall.elf',
                f'{autostart_cmd_pt1} {autostart_cmd_pt2}',
                f'sudo rm {supervisor_conf_remote_path}/alfadesk.conf',
                f'sudo rm {supervisor_conf_remote_path}/alfadesk.conf.BAK',
                f'sudo rm {supervisor_conf_remote_path}/dispatcher.conf',
                f'sudo rm {supervisor_conf_remote_path}/dispatcher.conf.BAK',
            ]
            await self.__async_paramiko_exec_commands(
                ssh_conn=ssh_conn,
                cmd_list=cmds_)

            self.main_window.update_gui_msg_board('Removed current CONF on TARGET !')

            await self.__async_upload_multiple_files(
                ssh_conn,
                cfg_folder_path,
                conf_remote_path)

            final_cmds = ['sudo /etc/init.d/lightdm restart']
            if reload_supervisor:
                final_cmds.append('sudo supervisorctl reload')

            await self.__async_paramiko_exec_commands(
                ssh_conn=ssh_conn,
                cmd_list=final_cmds,
                timeout=3)

            self.main_window.update_gui_msg_board(f'Successfully uploaded conf "{conf_name}"!! [{cfg_folder_path}]')

        except PipValidationError as val_err:
            self.main_window.update_gui_msg_board(val_err)
        except Exception as e:  # pylint: disable=broad-except
            logging.error(traceback.format_exc())
            self.main_window.update_gui_msg_board(e)
            self.main_window.update_gui_msg_board('More on logs')

        if close_ssh:
            ssh_conn.close()
            logging.warning(f'closed ssh_conn ({ssh_conn})')
            self.main_window.setup_or_update_btn_ui('end_deploy')

    @staticmethod
    def __setup_logger(fbs_ctx):

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

    @staticmethod
    def __load_config_from_file(fbs_ctx, cfg_filename=CFG_FILE_NAME):

        try:
            filename_cfg = fbs_ctx.get_resource(cfg_filename)
            logging.info('Config file: {}'.format({filename_cfg}))
            app_cfg = Config(filename_cfg)
            config_dict = app_cfg.ini_to_dict()
            logging.info('Config file data: {}'.format(config_dict))
            CACHE.update(config_dict)

            remote_keys = ('conf_remote_path', 'remote_supervisor_conf_path', 'remote_autostart_path')
            if remote_keys not in CACHE:
                CACHE.update({
                    'remote_conf_path': '/opt/alfa/conf',
                    'remote_supervisor_conf_path': '/etc/supervisor/conf.d',
                    'remote_autostart_path': '/home/admin/.config/lxsession/LXDE/autostart',
                })

        except FileNotFoundError:
            file_not_found = '{} not FOUND!'.format(cfg_filename)
            logging.error(file_not_found)
        except Exception:   # pylint: disable=broad-except
            logging.error(traceback.format_exc())

    @staticmethod
    def __validation_wheel_venv(app_names, venv_name, whl_path):
        """
        Check if selected wheel file is compatible with the selected venv name
        """

        whl_name = os.path.basename(whl_path)
        validation_err_msg = f'Selected wheel ({whl_name}) not compatible with selected venv ({venv_name})!'
        _validation = {'result': 'ko',
                       'error': validation_err_msg}

        # fix idiocracy about wheel name and app name
        if 'rs485_master' in whl_name:
            whl_name = 'rs485-master'
        for _app_name in app_names:
            logging.info(f'app name > {_app_name} | venv name > {venv_name} | wheel name > {whl_name}')
            if _app_name in venv_name and _app_name in whl_name:
                _validation.update({'result': 'ok', 'error': None})

        return _validation

    @staticmethod
    def validate_configuration(config):

        control_cfg_keys = ['venvs', 'tmp_dir', 'app_names', 'wheel_path',
                            'conf_files_path', 'configurations', 
                            'remote_autostart_path', 'remote_supervisor_conf_path',
                            'remote_conf_path']
        config_keys = list(config.keys())
        diffs = set(control_cfg_keys) - set(config_keys)
        if diffs:
            raise RuntimeError(f'Missing Config key(s) {diffs} ! Invalid Configuration.')

        for k_ in config_keys:
            if k_ == 'wheel_path' or k_ == 'conf_files_path':
                continue
            if not config.get(k_):
                raise ValueError(f'Empty Config key "{k_}"! Invalid Configuration.')

    @staticmethod
    def validate_ip_machine(ip_to_validate):

        regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
        error_regex_msg = f'IP {ip_to_validate} is not valid IP'
        assert re.search(regex, ip_to_validate), error_regex_msg

        ping_counter = '-n 1'
        if sys.platform == "linux" or sys.platform == "linux2":
            ping_counter = '-c 1'

        try:
            cmd_ = f"ping {ping_counter} -w 1000 {ip_to_validate}"
            logging.warning(cmd_)
            out = subprocess.run(cmd_, shell=True, check=True, timeout=5)
            logging.warning(f'output ping subprocess > {out}')
            if out.returncode == 0:
                result = {'message': f'IP {ip_to_validate} is valid and reachable!'}

        except subprocess.CalledProcessError as e:
            raise RuntimeError(f'IP {ip_to_validate} is valid! IP unreachable!') from e

        logging.warning(f'result: {result}')
        return result

    @staticmethod
    def create_ssh_connection_to_server(machine_ip, path_pem_file):

        """ Connect to an SSH server and authenticate to it """

        _username = 'admin'
        ssh_key = paramiko.RSAKey.from_private_key_file(path_pem_file)
        ssh_client = paramiko.SSHClient()
        # ssh_conn.load_system_host_keys()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # ssh_conn.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())
        logging.warning("connecting")
        ssh_client.connect(hostname=machine_ip, username=_username, pkey=ssh_key)
        logging.warning("connected")
        return ssh_client
