#!/bin/bash

set -e

if ! systemctl is-active --quiet supervisor; then
    echo "Supervisor is not running."
    exit 1
fi

status_output=$(supervisorctl status)
if ! echo "$status_output" | grep -q 'dispatcher_alfadesk.*RUNNING'; then
    echo "Dispatcher_alfadesk is not running."
    exit 1
fi

DISPATCHER_PATH="/home/alfadesk/dispatcher/venv/lib/python3.8/site-packages/dispatcher"
serial_port_mapper_path="$DISPATCHER_PATH/serial_port_mapper.py"

if [ ! -f /home/admin/plat_fix_scripts/docker-alfa-legacy-instance-v1-fix-3 ]; then

    touch /home/admin/plat_fix_scripts/docker-alfa-legacy-instance-v1-fix-3

    # create a temporary script file
    temp_script=$(mktemp)
    echo $temp_script

    # write commands to the script file
    cat >$temp_script <<EOF
    if [ ! -f $DISPATCHER_PATH/serial_port_mapper.py.bak.1 ]; then 
        cp $DISPATCHER_PATH/serial_port_mapper.py $DISPATCHER_PATH/serial_port_mapper.py.bak.1
    fi
    sed -i '62d' $serial_port_mapper_path
    sed -i '61a\    ln_cmd = "sleep 5;sudo rm -f {0};sudo ln -s {1} {0}".format(link_name, dev_name)' $serial_port_mapper_path
    sed -i '68d' $serial_port_mapper_path
    sed -i '67a\    dev_names = get_out_lines("ls /dev/ | grep ttyUSB") + \\\' $serial_port_mapper_path
    sed -i '68a\                get_out_lines("ls /dev/ | grep ttyACM")'  $serial_port_mapper_path

EOF

    # copy the script into the Docker container
    cat $temp_script | sudo docker exec -i alfa-legacy-instance bash

    # remove the temporary script file
    rm $temp_script

    sudo sed -i 's/^PLATFORM_VERSION=5-fix-resolv.conf-and-alfa-legacy$/PLATFORM_VERSION=5-fix-resolv.conf-and-alfa-legacy-and-slow-alfatint-and-scale-port-mapper/g' /etc/lsb-release
    sudo sed -i 's/^PLATFORM_VERSION=5-fix-resolv.conf-and-alfa-legacy-and-slow-alfatint$/PLATFORM_VERSION=5-fix-resolv.conf-and-alfa-legacy-and-slow-alfatint-and-scale-port-mapper/g' /etc/lsb-release
    echo 'fix_alfa_legacy_3 terminated - fixed scale serial port mapper'
    sudo supervisorctl reload
fi
