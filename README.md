# pip-installer-gui

Pip Installer Gui (aka PIG) is an application build upon PyQt5: install custom Python Wheels files to the target machine.

The project is based on Python 3.6 due to [fbs tool](https://build-system.fman.io/manual/)


## Requirements

##### Linux
    $ virtualenv -p /usr/bin/python3.6 fbs_venv/ 
    $ source fbs_venv/bin/activate
    (fbs_venv)$ pip install -r requirements-dev.txt

##### Win
    > virtualenv -p C:\Python36\python.exe fbs_venv
    > fbs_venv\Scripts\activate.bat
    (fbs_venv) > pip install -r requirements-dev.txt

## File .pem

Pip Installer Gui (aka PIG) requires a .pem file in order to autenticate to a target machine.

##### Windows

Using Windows it is possibile to convert a .ppk file to a .pem file using PuTTYgen ([download link](https://www.puttygen.com/)).

1. Start PuTTYgen. For Actions, choose Load, and then navigate to your .ppk file.
2. Choose the .ppk file, and then choose Open.
3. (Optional) For Key passphrase, enter a passphrase. For Confirm passphrase, re-enter your passphrase.
	Note: Although a passphrase isn't required, you should specify one as a security measure to protect the 	private key from unauthorized use. Using a passphrase makes automation difficult, because human intervention is needed to log in to an instance or to copy files to an instance.
4. From the menu at the top of the PuTTY Key Generator, choose Conversions, Export OpenSSH Key.
5. Note: If you didn't enter a passphrase, you receive a PuTTYgen warning. Choose Yes.
	Name the file and add the .pem extension.
6. Choose Save.

##### Linux (preferred mode)

    sudo apt-get install putty-tools 
	puttygen server1.ppk -O private-openssh -o server1.pem
	chmod 400 server1.pem 


## Release fbs application

To release a new version it is necessary to execute the Python script [execute_release_script](execute_release_script.py)

```
python execute_release_script.py --help
usage: Pip Installer Gui Releaser [-h] [-s {True,False}]

Generate the window installer for Pip Installer Gui

optional arguments:
  -h, --help            show this help message and exit
  -s {True,False}, --server-alfa {True,False}
                        Setup Alfa server paths for wheels and application
                        configurations
```

```
(fbs_venv) C:\Users\francesco.galasso\Documents\GitHub\pip-installer-gui>python execute_release_script.py -s True
server_alfa_paths -> True
['wheel_path', 'conf_files_path']
WARNING:root:Updated application config file with Alfa Server paths !
WARNING:root:Created application config !
WARNING:root:executing cmd: cd C:\Users\francesco.galasso\Documents\GitHub\pip-installer-gui
WARNING:root:executing cmd: C:\Users\francesco.galasso\Documents\GitHub\pip-installer-gui\fbs_venv\Scripts\activate && fbs freeze
Done. You can now run `target\PipInstallerGui\PipInstallerGui.exe`. If
that doesn't work, see https://build-system.fman.io/troubleshooting.
WARNING:root:executing cmd: C:\Users\francesco.galasso\Documents\GitHub\pip-installer-gui\fbs_venv\Scripts\activate && fbs installer
Created target\PipInstallerGuiSetup.exe.
WARNING:root:path_installer -> C:\Users\francesco.galasso\Documents\GitHub\pip-installer-gui\target\PipInstallerGuiSetup.exe
WARNING:root:path_installer_renamed -> C:\Users\francesco.galasso\Documents\GitHub\pip-installer-gui\target\Alfa_PipInstallerGuiSetup.exe
WARNING:root:Renamed Installer file to "Alfa_PipInstallerGuiSetup"

(fbs_venv) C:\Users\francesco.galasso\Documents\GitHub\pip-installer-gui>python execute_release_script.py
server_alfa_paths -> False
WARNING:root:Skip using Alfa Server paths for Pip Installer Gui
WARNING:root:Created application config !
WARNING:root:executing cmd: cd C:\Users\francesco.galasso\Documents\GitHub\pip-installer-gui
WARNING:root:executing cmd: C:\Users\francesco.galasso\Documents\GitHub\pip-installer-gui\fbs_venv\Scripts\activate && fbs freeze
Done. You can now run `target\PipInstallerGui\PipInstallerGui.exe`. If
that doesn't work, see https://build-system.fman.io/troubleshooting.
WARNING:root:executing cmd: C:\Users\francesco.galasso\Documents\GitHub\pip-installer-gui\fbs_venv\Scripts\activate && fbs installer
Created target\PipInstallerGuiSetup.exe.
WARNING:root:path_installer -> C:\Users\francesco.galasso\Documents\GitHub\pip-installer-gui\target\PipInstallerGuiSetup.exe
WARNING:root:path_installer_renamed -> C:\Users\francesco.galasso\Documents\GitHub\pip-installer-gui\target\Customer_PipInstallerGuiSetup.exe
WARNING:root:Renamed Installer file to "Customer_PipInstallerGuiSetup"
```