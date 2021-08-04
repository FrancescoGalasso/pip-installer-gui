# -*- coding: utf-8 -*-

# pylint: disable=no-name-in-module

""" Main module """

import sys
from fbs_runtime.application_context.PyQt5 import ApplicationContext, cached_property


class PipInstallerGuiAppContext(ApplicationContext):
    """ FBS pip-installer-gui App Context """

    @cached_property            # pylint: disable=missing-function-docstring
    def app(self):
        sys.path.append('.')
        import pip_installer_gui         # pylint: disable=import-error, import-outside-toplevel
        sys.path.remove('.')

        application = pip_installer_gui.PipInstallerGuiApplication(self, pip_installer_gui.MainWindow, sys.argv)
        return application

    def run(self):              # pylint: disable=missing-function-docstring
        return self.app.exec_()


if __name__ == '__main__':
    appctxt = PipInstallerGuiAppContext()
    exit_code = appctxt.run()
    sys.exit(exit_code)
