# -*- coding: utf-8 -*-

import os
import logging

HERE = os.path.abspath(os.path.dirname(__file__))
PATH_PIG_LOG = f'{os.sep}'.join([HERE, 'src', 'main', 'resources', 'base', 'log', 'PipInstallerGui.log'])
PATH_LOGGER_CFG = f'{os.sep}'.join([HERE, 'src', 'main', 'resources', 'base', 'config', 'logger.cfg'])

def execute_pre_build():
	"""
	before launching the cmd "fbs freeze" it is mandatory the execution of this script!
	"""
	
	logging.warning(f'HERE > {HERE}')
	logging.warning(f'PATH_PIG_LOG > {PATH_PIG_LOG}')
	logging.warning(f'PATH_LOGGER_CFG > {PATH_LOGGER_CFG}')

	__restore_pig_log()
	__restore_logger_cfg_file()

	logging.warning('\n**** SUCCESSFULLY COMPLETED THE EXECUTION OF PRE BUILD SCRIPT ! ****')

def __restore_pig_log():
	"""
	delete all lines in PATH_PIG_LOG
	"""
	file = open(PATH_PIG_LOG,"w")
	file.close()

def __restore_logger_cfg_file():
	"""
	restore default args value for LOGGER_CFG
	"""

	data = None
	with open(PATH_LOGGER_CFG, "r") as logger_file:

		data = logger_file.readlines()

		for idx, line in enumerate(data):

			if 'args' in line:
				default_value = "args=('testing.log', 'a', 1000000, 5)\n"
				data[idx] = default_value

	with open(PATH_LOGGER_CFG, "w") as logger_file:
		logger_file.writelines(data)

if __name__ == '__main__':
	execute_pre_build()