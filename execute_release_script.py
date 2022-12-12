# -*- coding: utf-8 -*-

# pylint: disable=missing-function-docstring
# pylint: disable=missing-class-docstring

"""
Pre build script

* Clear all logs created on develop machine
* Restore the logger configuration file
* Generate application configuration file starting from the current template
* Get ready to distribuite the application
"""

import argparse
import os
import logging
import traceback
import configparser
import subprocess

HERE = os.path.abspath(os.path.dirname(__file__))


class PipInstallerGuiReleaser:

    def __init__(self):
        self.path_log_file = f'{os.sep}'.join([HERE, 'src', 'main', 'resources', 'base', 'log', 'PipInstallerGui.log'])
        self.path_log_config = f'{os.sep}'.join([HERE, 'src', 'main', 'resources', 'base', 'config', 'logger.cfg'])
        self.path_app_config_template = f'{os.sep}'.join([HERE, 'src', 'main', 'resources', 'base', 'config', 'config.ini.template'])
        self.path_app_config = f'{os.sep}'.join([HERE, 'src', 'main', 'resources', 'base', 'config', 'config.ini'])

        self.NAME = 'Pip Installer Gui Releaser'
        self.DESCRIPTION = 'Generate the window installer for Pip Installer Gui'
        self.args = None

    def run(self):
        """
        before launching the cmd "fbs freeze" it is mandatory the execution of this script!
        clear logs, restore log config file, generate config.ini file from its template
        """

        try:

            parser = argparse.ArgumentParser(
                prog=self.NAME,
                description=self.DESCRIPTION,
                formatter_class=argparse.RawDescriptionHelpFormatter)

            parser.add_argument(
                '-s',
                '--server-alfa',
                choices=['True','False'],
                dest="server_alfa_paths",
                default=False,
                help="Setup Alfa server paths for wheels and application configurations")

            self.args = parser.parse_args()
            print(f'server_alfa_paths -> {self.args.server_alfa_paths}')

            self.restore_pig_log()
            self.restore_logger_cfg_file()
            self.generate_app_config_from_template()
            logging.warning('\n**** SUCCESSFULLY COMPLETED THE EXECUTION OF PRE BUILD SCRIPT ! ****')

            self.generate_windows_installer()
        except Exception:
            logging.error(traceback.format_exc())

    def restore_pig_log(self):
        """
        delete all lines in path_log_file
        """

        with open(self.path_log_file, "w", encoding="utf-8") as app_log:
            app_log.writelines([])

    def restore_logger_cfg_file(self):
        """
        restore default args value for app log config
        """

        data = None
        with open(self.path_log_config, "r", encoding="utf-8") as logger_file:

            data = logger_file.readlines()

            for idx, line in enumerate(data):

                if 'args' in line:
                    default_value = "args=('testing.log', 'a', 1000000, 5)\n"
                    data[idx] = default_value

        with open(self.path_log_config, "w", encoding="utf-8") as logger_file:
            logger_file.writelines(data)

    def generate_app_config_from_template(self):
        """
        generate app config ini from template
        """

        server_paths_file = f'{os.sep}'.join([HERE, 'server_paths.ini'])

        application_config = configparser.ConfigParser(allow_no_value=True)
        application_config.optionxform=str  # preserve case
        application_config.read(self.path_app_config_template, encoding='utf-8')

        try:
            assert self.args.server_alfa_paths, "Skip using Alfa Server paths for Pip Installer Gui"
            assert os.path.isfile(server_paths_file), "Missing Alfa Server paths file! Using default paths .."

            server_file_config = configparser.ConfigParser()
            server_file_config.read(server_paths_file, encoding='utf-8')
            print(server_file_config.sections())

            if server_file_config.has_section('wheel_path') and server_file_config.has_section('conf_files_path'):
                server_path_wheels = server_file_config['wheel_path']
                server_path_applications_confs = server_file_config['conf_files_path']

                assert server_path_wheels, "Missing Alfa Server wheels path"
                assert server_path_applications_confs, "Missing Alfa Server application confs path"
                application_config['wheel_path'] = server_path_wheels
                application_config['conf_files_path'] = server_path_applications_confs

                logging.warning('Updated application config file with Alfa Server paths !')

        except AssertionError as a_err:
            logging.warning(a_err)       

        with open(self.path_app_config, 'w', encoding='utf-8') as configfile:
            application_config.write(configfile)
            logging.warning('Created application config !')

    @staticmethod
    def generate_windows_installer():
        """
        wrapper for fman build system commands
        see: https://github.com/mherrmann/fbs
        """

        # modificare il file srb/build/settings/base.json per modificare il nome dell'eseguibile (Customer - Alfa Internal)
        # subprocess.run("dir", shell=True, check=True) per fbs freeze & fbs run

        cmds = [
            f'cd {HERE}',
            f'{HERE}\\fbs_venv\\Scripts\\activate && fbs freeze',
            f'{HERE}\\fbs_venv\\Scripts\\activate && fbs installer'
        ]

        for cmd in cmds:
            subprocess.run(cmd, shell=True, check=True)

if __name__ == '__main__':
    PipInstallerGuiReleaser().run()
