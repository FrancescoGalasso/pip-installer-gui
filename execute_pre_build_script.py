# -*- coding: utf-8 -*-

import os
import logging
import traceback
import configparser

HERE = os.path.abspath(os.path.dirname(__file__))


class Prerelease:

    def __init__(self):
        self.path_log_file = f'{os.sep}'.join([HERE, 'src', 'main', 'resources', 'base', 'log', 'PipInstallerGui.log'])
        self.path_log_config = f'{os.sep}'.join([HERE, 'src', 'main', 'resources', 'base', 'config', 'logger.cfg'])
        self.path_app_config_template = f'{os.sep}'.join([HERE, 'src', 'main', 'resources', 'base', 'config', 'config.ini.template'])
        self.path_app_config = f'{os.sep}'.join([HERE, 'src', 'main', 'resources', 'base', 'config', 'config.ini'])

    def run(self):
        """
        before launching the cmd "fbs freeze" it is mandatory the execution of this script!
        clear logs, restore log config file, generate config.ini file from its template
        """

        try:
            self.restore_pig_log()
            self.restore_logger_cfg_file()
            self.generate_app_config_from_template()
            logging.warning('\n**** SUCCESSFULLY COMPLETED THE EXECUTION OF PRE BUILD SCRIPT ! ****')
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

        server_path_wheels = ""
        server_path_applications_confs = "None"
        server_paths_file = f'{os.sep}'.join([HERE, 'server_paths.ini'])
        if os.path.exists(server_paths_file) and os.path.isfile(server_paths_file):
            server_file_config = configparser.ConfigParser()
            server_file_config.read(server_paths_file, encoding='utf-8')
            print(server_file_config.sections())

            if server_file_config.has_section('wheel_path') and server_file_config.has_section('conf_files_path'):
                server_path_wheels = server_file_config['wheel_path']
                server_path_applications_confs = server_file_config['conf_files_path']

        application_config = configparser.ConfigParser(allow_no_value=True)
        application_config.optionxform=str  # preserve case
        application_config.read(self.path_app_config_template, encoding='utf-8')

        if server_path_wheels and server_path_applications_confs:
            # add them to app config and create config.ini
            application_config['wheel_path'] = server_path_wheels
            application_config['conf_files_path'] = server_path_applications_confs

        with open(self.path_app_config, 'w') as configfile:
            application_config.write(configfile)


if __name__ == '__main__':
    Prerelease().run()
