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

To release a new version it is necessary:

1. execute the Python script [execute_pre_build_script](execute_pre_build_script.py)
2. execute command `fbs freeze`
3. execute command `fbs installer`
