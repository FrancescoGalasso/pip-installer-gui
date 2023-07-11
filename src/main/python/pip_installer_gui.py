# -*- coding: utf-8 -*-

# pylint: disable=no-name-in-module
# pylint: disable=logging-format-interpolation, logging-fstring-interpolation, consider-using-f-string
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
import configparser
import paramiko                                                     # pylint: disable=import-error
import redis
import smtplib
import requests

from pip_errors import PipValidationError
from deepdiff import DeepDiff                                       # pylint: disable=import-error
from PyQt5 import uic
from PyQt5.QtWidgets import QMainWindow, QApplication, QFileDialog  # pylint: disable=import-error
from PyQt5.QtGui import QTextCursor                                 # pylint: disable=import-error
from qasync import QEventLoop                                       # pylint: disable=import-error


CFG_FILE_NAME = ''.join(['config', os.sep, 'config.ini'])
PEM_FILE = ''.join(['config', os.sep, 'keyy.pem'])
PIG_LOG_CFG = ''.join(['config', os.sep, 'logger.cfg'])
PIG_LOG_FILE = ''.join(['log', os.sep, 'PipInstallerGui.log'])
PIG_MANIFEST_FILE = ''.join(['platform_scripts', os.sep, 'manifest.json'])
PIG_RESULT_FIXES_JSON = ''.join(['platform_scripts', os.sep, 'fix_results.json'])
MAIL_CREDENTIALS_FILE = ''.join(['config', os.sep, 'credentials.txt'])
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

        self.pushButton_validate.clicked.connect(self.on_btn_validate_clicked)
        self.pushButton_install.clicked.connect(self.on_btn_install_clicked)
        self.pushButton_deploy.clicked.connect(self.on_btn_deploy_clicked)
        self.pushButton_clear.clicked.connect(self.on_btn_clear_clicked)
        self.pushButton_fix_platform.clicked.connect(self.on_btn_fix_platform_clicked)

        self.btn_open_folder_files.clicked.connect(self.__get_wheel_file)
        self.pushButton_choose_conf.clicked.connect(self.__get_conf_file_dir)
        self.pushButton_choose_docker_img.clicked.connect(self.__get_docker_img)

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

    def on_btn_fix_platform_clicked(self):
        try:
            path_pem_file = self.ctx.get_resource(PEM_FILE)
            ip_machine = self.qline_ip.text()
            docker_img_path = self.qline_docker_img_path.text()
            if docker_img_path == '':
                raise RuntimeError('Please select an Alfa Docker Image file!')
            self.parent.apply_fix_on_target(path_pem_file, ip_machine, docker_img_path)

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
            self.qline_docker_img_path.setText('')
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
            self.qline_docker_img_path.setText('')
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

    def __get_docker_img(self):
        path_docker_img = QFileDialog.getOpenFileName(
            QFileDialog(),
            'Open file',
            '',
            "docker image (*.tar)",)
        self.qline_docker_img_path.setText(path_docker_img[0])
        logging.info(f'selected docker img file: {path_docker_img[0]}')

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

    def apply_fix_on_target(self, path_pem_file, machine_ip, docker_img_path):
        
        try:
            self.validate_ip_machine(machine_ip)
            ssh_conn = self.create_ssh_connection_to_server(machine_ip, path_pem_file)
        except Exception as exc:    # pylint: disable=broad-except
            logging.error(traceback.format_exc())
            self.main_window.update_gui_msg_board(exc)
            return

        extra_ = {
            'machine_ip': machine_ip,
            'docker_img': docker_img_path,
        }
        asyncio.ensure_future(
            self.__async_apply_fix_on_target(ssh_conn, extra=extra_)
        )

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

    async def __send_mail(self, credentials, msg_subject, msg_body):

        try:

            mail = None
            app_passwd = None
            with open(credentials, 'r') as f:
                lines = f.readlines()
                mail = lines[0].strip()
                app_passwd = lines[1].strip()

            MAIL_RECIPIENTS = [
                'francescogalasso@alfadispenser.com',
                'filippogurgoglione@alfadispenser.com',
                'giulianosolera@alfadispenser.com',
                'marcolunghini@alfadispenser.com',
                'fernandocarbajal@alfadispenser.com',
                'alessandroveronesi@alfadispenser.com',
                'lauragiamporcaro@alfadispenser.com'
            ]
            # MAIL_RECIPIENTS = ['francescogalasso@alfadispenser.com']

            assert mail
            assert app_passwd

            with smtplib.SMTP_SSL(host="smtp.gmail.com", port=465, timeout=15) as smtp_ssl:
                logging.debug("Connection Object : {}".format(smtp_ssl))
                resp_code, response = smtp_ssl.login(user=mail, password=app_passwd)

                logging.info("Response Code : {}".format(resp_code))
                logging.info("Response      : {}".format(response.decode()))
                assert int(resp_code)==235, 'Authentication failed ..'

                message_body = ""
                for key, value in msg_body.items():
                    if key == 'details' and isinstance(value, dict):
                        message_body += f"{key}:\n"
                        for detail_key, detail_value in value.items():
                            message_body += f"  {detail_key}:\n  {detail_value}\n"
                    else:
                        message_body += f"{key}:\n{value}\n"

                message = 'Subject: {}\n\n{}'.format(msg_subject, message_body)

                response = smtp_ssl.sendmail(
                    from_addr=mail,
                    to_addrs=MAIL_RECIPIENTS,
                    msg=message
                )

        except (smtplib.SMTPConnectError, socket.gaierror) as e:
            logging.error("Failed to connect to the server. Possible causes:")
            logging.error("1. No internet connection.")
            logging.error("2. The SMTP server is blocked by a firewall.")
            logging.error(f"System message: {e}")

        except  socket.timeout as etout:
            logging.error(etout)

        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")

        else:
            logging.info('Mail inviata !')

    async def __update_docker_image(self, docker_img_path, manifest_docker_info, ssh_conn):

        if manifest_docker_info not in docker_img_path:
            result_ko = 'Invalid Docker image! Skipping update Docker image ..'
            logging.error(f'{docker_img_path} {result_ko}')
            self.main_window.update_gui_msg_board(f'{result_ko}')
            return result_ko

        self.main_window.update_gui_msg_board('Starting upload new Docker image..')
        cmd_ = f"rm -f /home/admin/alfa-legacy_arm64.tar"
        logging.debug(f'cmd -> {cmd_}')
        await self.__async_paramiko_exec_commands(
            ssh_conn=ssh_conn,
            cmd_list=[cmd_],
            print_to_gui=False)

        await asyncio.sleep(0.25)
        remote_path = '/home/admin/alfa-legacy_arm64.tar'
        logging.debug(f'local path: {docker_img_path}')
        logging.debug(f'remote path: {remote_path}')
        await self.__async_paramiko_sftp_put(
            ssh_conn=ssh_conn,
            local_path=docker_img_path,
            remote_path=remote_path)

        docker_cmds = [
            'sudo supervisorctl stop dispatcher_alfadesk',
            'sudo docker system prune -a -f',
            'sudo docker load -i ~/alfa-legacy_arm64.tar',
            'sudo docker run \
              --name alfa-legacy-instance \
              --add-host=host.docker.internal:host-gateway \
              -p 80:80/tcp \
              --mount source=alfa-legacy-db,destination=/var/lib/postgresql/ \
              -v /dev:/dev \
              -v /etc/timezone:/etc/timezone \
              --tmpfs /var/log:uid=1000,gid=1000 \
              --tmpfs /tmp:uid=1000,gid=1000 \
              --tmpfs /run:uid=1000,gid=1000 \
              --privileged \
              -d -i alfa-legacy',
            'sleep 5',
            'sudo supervisorctl start dispatcher_alfadesk'
        ]
        await self.__async_paramiko_exec_commands(
            ssh_conn=ssh_conn,
            cmd_list=docker_cmds,
            print_to_gui=False)

        result_ok = 'Docker image updated!'
        self.main_window.update_gui_msg_board(result_ok)
        return result_ok

    async def __async_apply_fix_on_target(self, ssh_conn, extra, show_info_to_gui=True):

        mail_messages = {
            'error': None,
            'docker message': None,
            'platform message': None,
            'details': {}
        }

        try:
            changelog_messages = []
            # tricky way to assigning a value to the self.lsb_release attribute
            await self.__validate_platform_alfa(ssh_conn)
            logging.info(self.lsb_release)

            target_plat_name = self.lsb_release.get('DISTRIB_DESCRIPTION')
            target_plat_ver = self.lsb_release.get('PLATFORM_VERSION', '5')
            logging.info(f'target_plat_name: {target_plat_name}')
            logging.info(f'target_plat_ver: {target_plat_ver}')

            if not target_plat_name:
                raise RuntimeError('Missing DISTRIB_DESCRIPTION in file /etc/lsb-release ... Aborting')

            path_manifest_file = self.fbs_ctx.get_resource(PIG_MANIFEST_FILE)
            manifest = {}
            with open(path_manifest_file, 'r') as manifest_file:
                manifest = json.load(manifest_file)
                if manifest:
                    manifest = manifest.pop('platforms')

            platform_fixed = False
            platform_fixed_excp = False
            manifest_platform = False
            # the BPi-M5 Armbian platform was released with VERSION=5
            if target_plat_name == 'Armbian Alfa general-purpose BPi-M5':
                bananapim5_manifest = manifest.get('bananapi', {})
                logging.debug(bananapim5_manifest)

                for v in bananapim5_manifest:
                    if v[1:] in target_plat_ver:
                        manifest_platform = True
                        fixes = bananapim5_manifest.get(v, {}).get('fixes', {})
                        for curr_fix in fixes:
                            logging.info(f'Applying `{curr_fix}`')

                            target_scripts_dir_path = "/home/admin/plat_fix_scripts"
                            cmd_mkdir_scripts = f"mkdir -p {target_scripts_dir_path}"
                            await self.__async_paramiko_exec_commands(
                                ssh_conn=ssh_conn,
                                cmd_list=[cmd_mkdir_scripts],
                                print_to_gui=False)

                            await asyncio.sleep(0.25)
                            _script_path = ''.join(['platform_scripts', os.sep, f'{curr_fix}.sh'])
                            script_path = self.fbs_ctx.get_resource(_script_path)
                            logging.debug(f'local path: {script_path}')
                            logging.debug(f'remote path: {target_scripts_dir_path}')
                            script_remote_path = ''.join([target_scripts_dir_path, '/', f'v5_{curr_fix}.sh'])
                            await self.__async_paramiko_sftp_put(
                                ssh_conn=ssh_conn,
                                local_path=script_path,
                                remote_path=script_remote_path)

                            script_cmd = f"""chmod +x /home/admin/plat_fix_scripts/v5_{curr_fix}.sh
                                             sleep 0.25
                                             sed -i 's/\r$//' /home/admin/plat_fix_scripts/v5_{curr_fix}.sh"""

                            std_outs, std_errs = await self.__async_paramiko_exec_commands(
                                ssh_conn=ssh_conn,
                                cmd_list=[script_cmd],
                                print_to_gui=False)
                            assert not std_errs

                            # invoke_shell sends both stdout and stderr to the same place (the channel)
                            # unlike exec_command which separates them.
                            channel = ssh_conn.invoke_shell()
                            channel.send(f"/usr/bin/bash /home/admin/plat_fix_scripts/v5_{curr_fix}.sh\n")
                            while not channel.recv_ready():
                                time.sleep(1)

                            sleep_time = 3
                            if curr_fix == 'fix_alfa_legacy_2':
                                sleep_time = 9
                            time.sleep(sleep_time)
                            output = channel.recv(2048).decode()
                            logging.info(output)
                            if channel.get_transport().is_active():
                                logging.debug('Closing channel for invoke_shell')
                                channel.close()

                            if output and 'is not running' in output:
                                raise RuntimeError('Supervisor process "dispatcher_alfadesk" must be in RUNNING status ..')

                            mail_messages['details'].update({
                               curr_fix: output
                            })
                            if output and f'{curr_fix} terminated' in output:
                                 platform_fixed = True

                            if platform_fixed and show_info_to_gui:
                                self.main_window.update_gui_msg_board(f'Applied `{curr_fix}`')
                                changelog_messages.append(f'{datetime.datetime.now()} - Applied {curr_fix} on platform {target_plat_name} v{v[1:]}')

                        if extra and extra.get("docker_img"):
                            docker_img_info = bananapim5_manifest.get(v, {}).get('docker_image_fixed', "")
                            result = await self.__update_docker_image(extra.get("docker_img"), docker_img_info, ssh_conn)
                            docker_msg = f'platform {target_plat_name} v{v[1:]} - {result}'
                            changelog_messages.append(f'{datetime.datetime.now()} - {docker_msg}')
                            mail_messages['docker message'] = docker_msg

        except Exception as e:  # pylint: disable=broad-except
            logging.error(traceback.format_exc())
            self.main_window.update_gui_msg_board(e)
            platform_fixed = False
            platform_fixed_excp = True
            mail_messages['error'].update({
                'err_msg': e,
                'traceback': traceback.format_exc()
            })

        finally:

            target_sn_alfa40 = None
            target_sn_alfaadmin = None
            if extra and extra.get("machine_ip"):
                m_ip = extra.get("machine_ip")
                target_sn_alfa40 = await self.get_sn_from_alfa40(m_ip)
                target_sn_alfaadmin = await self.get_sn_from_alfaadmin(m_ip)
                logging.info(f'target_sn_alfa40 -> {target_sn_alfa40}')
                logging.info(f'target_sn_alfaadmin -> {target_sn_alfaadmin}')

            if show_info_to_gui:
                if platform_fixed:
                    generate_changelog_cmd = ['touch /home/admin/plat_fix_scripts/CHANGELOG-FIXES']
                    for c_msg in changelog_messages:
                        generate_changelog_cmd.append(f'echo "{c_msg}" >> /home/admin/plat_fix_scripts/CHANGELOG-FIXES')
                    await self.__async_paramiko_exec_commands(
                                ssh_conn=ssh_conn,
                                cmd_list=generate_changelog_cmd,
                                print_to_gui=False)

                    _message = 'Finished to apply the fixes.'
                    mail_messages['platform message'] = _message
                    self.main_window.update_gui_msg_board(_message)

                elif platform_fixed_excp:
                    _message = 'An unexpected error was encountered - more on logs. Aborting ..'
                    mail_messages['platform message'] = _message
                    self.main_window.update_gui_msg_board(_message)
                else:
                    _message = 'Platform already fixed!'
                    if not manifest_platform:
                        _message = 'The current platform does not need fixing!'
                    mail_messages['platform message'] = _message
                    self.main_window.update_gui_msg_board(_message)

                credentials = self.fbs_ctx.get_resource(MAIL_CREDENTIALS_FILE)

                mail_subject = f"PIG platform fix recap - alfa40 SN {target_sn_alfa40} - alfaadmin SN {target_sn_alfaadmin}"
                await self.__send_mail(credentials, mail_subject, mail_messages)
                await self.__async_update_result_fixes_json(target_sn_alfa40, changelog_messages)

            if ssh_conn.get_transport() is not None and ssh_conn.get_transport().is_active():
                logging.warning(f'ssh_conn active: {ssh_conn.get_transport().is_active()}')
                ssh_conn.close()
                logging.warning(f'closed ssh_conn ({ssh_conn})')

    async def __async_check_internet_availability(self, ssh_conn):
        cmds_ = [
            'ping -c 1 -w 1000 8.8.8.8'
        ]
        logging.warning(cmds_)
        rout, rerr = await self.__async_paramiko_exec_commands(
            ssh_conn=ssh_conn,
            cmd_list=cmds_)

        logging.debug(f'rout: {rout}')
        logging.debug(f'rerr: {rerr}')

        if not rout or any('Host Unreachable' in x for x in rout):
            raise RuntimeError('No Internet Connection (eth1 or WiFi) on Machine ... ABORT')

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

    async def __async_update_result_fixes_json(self, target_sn, changelogs):

        try:

            result_fixes = {}
            path_result_fixes_json = self.fbs_ctx.get_resource(PIG_RESULT_FIXES_JSON)
            with open(path_result_fixes_json, 'r') as fixes_json:
                result_fixes = json.load(fixes_json)

            logging.info(f'result_fixes: {result_fixes}')
            result_fixes.update({target_sn: changelogs})
            logging.info(f'result_fixes updated: {result_fixes}')
            with open(path_result_fixes_json, 'w') as fixes_json:
                # result_fixes = json.load(fixes_json)
                fixes_json.write(json.dumps(result_fixes))

        except Exception as e:
            logging.error(traceback.format_exc())
            logging.error(e)
            self.main_window.update_gui_msg_board('ERROR - cannot update result_fixes.json')

    async def __validate_platform_alfa(self, ssh_client):
        """
        Platform alfa must be a generic-purpose platform in order to
        deploy configs.
        """

        validated = False
        self.lsb_release = {}

        try:
            with ssh_client.open_sftp() as sftp_client:
                with sftp_client.open('/etc/lsb-release') as remote_file:
                    for line in remote_file:
                        if line and line.rstrip():
                            (key, value) = line.split('=')
                            value = value.strip('\"\n')
                            self.lsb_release[key] = value

            logging.debug(self.lsb_release)
            validated = 'general-purpose' in self.lsb_release.get('DISTRIB_DESCRIPTION', None)
            validated = validated and self.lsb_release.get('PLATFORM_VERSION', None)

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
            await self.__async_check_internet_availability(ssh_conn)

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

        except Exception as e:  # pylint: disable=broad-except
            logging.error(traceback.format_exc())
            self.main_window.update_gui_msg_board(e)
            self.main_window.update_gui_msg_board('More on logs')

        if ssh_conn.get_transport() is not None and ssh_conn.get_transport().is_active():
            logging.warning(f'ssh_conn active: {ssh_conn.get_transport().is_active()}')
            ssh_conn.close()
            logging.warning(f'closed ssh_conn ({ssh_conn})')
            self.main_window.setup_or_update_btn_ui('end_install')

    async def __async_deploy_on_target(self, ssh_conn, cfg_folder_path, close_ssh=True, reload_supervisor=False):

        conf_name = os.path.basename(cfg_folder_path)

        try:
            await self.__async_check_internet_availability(ssh_conn)

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

            armbian_so = False
            logging.warning(f'self.lsb_release > {self.lsb_release}')
            if 'Armbian' in self.lsb_release.get("DISTRIB_DESCRIPTION"):
                logging.info('Armbian SO ;)')
                armbian_so = True

            chromium_browser = await self.__get_installed_chromium_browser_debian_pkg(ssh_conn)
            autostart_cmd_pt1 = f'grep -q "@/usr/bin/{chromium_browser}" /home/admin/.config/lxsession/LXDE/autostart'
            autostart_cmd_pt2 = f'&& (sed -i "/{chromium_browser} --disable-restore-session-state --no-first-run --kiosk/d" {autostart_remote_path})'
            
            if armbian_so:
                autostart_cmd_pt1 = f'grep -q "start_browser" /home/admin/.config/lxsession/LXDE/autostart'
                autostart_cmd_pt2 = f'&& (sed -i "/start_browser/d" {autostart_remote_path})'
           
            if 'alfalib' in conf_name:
                autostart_cmd_pt2 = f'|| (echo "@/usr/bin/{chromium_browser} --disable-restore-session-state --no-first-run --kiosk 127.0.0.1"'
                if armbian_so:
                    autostart_cmd_pt2 = f'|| (echo "@/home/admin/start_browser.sh"'
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

            if armbian_so and 'alfalib' in conf_name:
                final_cmds.append("sleep 3; sudo ln -nsf /opt/alfa/conf/old_supervisor/alfa40.conf /opt/alfa/conf/supervisor/alfa40.conf; \
                    sudo ln -nsf /opt/alfa/conf/old_supervisor/dispatcher.conf /etc/supervisor/conf.d/dispatcher.conf")

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
    async def get_sn_from_alfa40(m_ip):
        redis_bus_url = f'redis://{m_ip}:6379/0'
        logging.info(f'redis_bus_url -> {m_ip}')
        redis_bus = redis.StrictRedis(host=m_ip, port=6379)
        start_time = time.time()
        ret = None
        while time.time() - start_time < 50:
            ret = redis_bus.get('ALFA_CONFIG')
            if ret:
                logging.debug(f'ret -> {ret}')
                break
            await asyncio.sleep(1)

        assert ret, "Key 'ALFA_CONFIG' not found in Redis bus after waiting for 50 seconds"

        config = json.loads(ret.decode())
        target_sn = config.get('ALFA_SERIAL_NUMBER', 00000000)
        return target_sn

    @staticmethod
    async def get_sn_from_alfaadmin(m_ip):
        sn_alfaadmin = 00000000
        try:
            response = requests.get(f'http://{m_ip}/a9fb26d39e8b7c99/api/devices/')
            devices = response.json().get('results', [])
            if devices:
                for dev in devices:
                    if dev.get('channel', '') == "machine":
                        sn_alfaadmin = dev.get('serial_number')
        except Exception as e:
            logging.error(e)
            logging.traceback.format_exc()

        return sn_alfaadmin


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
        # fix idiocracy n°2 about alfa_CR6 wheel name to avoid validation failure
        # e.g. app_name=venv_name=alfa_cr6 & whl_name=alfa_CR6-0.0.1rc136-py3-none-any.whl
        if 'alfa_CR6' in whl_name:
            whl_name = whl_name.replace("alfa_CR6", "alfa_cr6")

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
