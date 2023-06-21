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

if [ ! -f /home/admin/plat_fix_scripts/docker-alfa-legacy-instance-v1-fix-2 ]; then

    touch /home/admin/plat_fix_scripts/docker-alfa-legacy-instance-v1-fix-2

    sudo docker exec -i alfa-legacy-instance supervisorctl stop all
    sleep 3

    # create a temporary script file
    temp_script=$(mktemp)
    echo $temp_script

    # write commands to the script file
    cat >$temp_script <<'EOF'
    if [ ! -f /home/alfadesk/public/static/js/components/erogations.js.bak.1 ]; then 
        cp /home/alfadesk/public/static/js/components/erogations.js /home/alfadesk/public/static/js/components/erogations.js.bak.1
    fi
    sed -i '29a\
        this.getErogationsReq = false;' /home/alfadesk/public/static/js/components/erogations.js
    sed -i '40d' /home/alfadesk/public/static/js/components/erogations.js
    sed -i '39a\
        if (this.getErogationsReq) {' /home/alfadesk/public/static/js/components/erogations.js
    sed -i '40a\
          console.log("skipping erogations req");' /home/alfadesk/public/static/js/components/erogations.js
    sed -i '41a\
        } else {' /home/alfadesk/public/static/js/components/erogations.js
    sed -i '42a\
          this.getErogationsReq = true;' /home/alfadesk/public/static/js/components/erogations.js
    sed -i '43a\
          this.fetchErogations();' /home/alfadesk/public/static/js/components/erogations.js
    sed -i '44a\
        }' /home/alfadesk/public/static/js/components/erogations.js
    sed -i '50a\
            this.getErogationsReq = false;' /home/alfadesk/public/static/js/components/erogations.js

    sed -i '43a\
        this.pendingDeviceStatusReq = false;' /home/alfadesk/public/static/js/services/main-service.js

    sed -i '323a\
        this.pendingDeviceStatusReq = false;' /home/alfadesk/public/static/js/services/main-service.js

    sed -i '336a\
        if (this.pendingDeviceStatusReq) {' /home/alfadesk/public/static/js/services/main-service.js

    sed -i '337a\
            console.log("skipping collecting device status");' /home/alfadesk/public/static/js/services/main-service.js

    sed -i '338a\
            return;' /home/alfadesk/public/static/js/services/main-service.js

    sed -i '339a\
        }' /home/alfadesk/public/static/js/services/main-service.js

    sed -i '340a\
        this.pendingDeviceStatusReq = true;' /home/alfadesk/public/static/js/services/main-service.js

EOF

    # copy the script into the Docker container
    cat $temp_script | sudo docker exec -i alfa-legacy-instance bash

    # remove the temporary script file
    rm $temp_script

    sudo sed -i 's/^PLATFORM_VERSION=5-fix-resolv.conf-and-alfa-legacy$/PLATFORM_VERSION=5-fix-resolv.conf-and-alfa-legacy-and-slow-alfatint/g' /etc/lsb-release
    echo 'fix_alfa_legacy_2 terminated - fixed slow alfatint'
    sudo supervisorctl reload
fi
