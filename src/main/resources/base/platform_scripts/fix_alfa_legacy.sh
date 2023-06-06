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

if [ ! -f /home/admin/plat_fix_scripts/docker-alfa-legacy-instance-v1-fix-1 ]; then
	touch /home/admin/plat_fix_scripts/docker-alfa-legacy-instance-v1-fix-1
    sudo docker exec -it alfa-legacy-instance bash -c "sed -i '48a\\
    def connection_lost(self, exc):' /home/alfadesk/dispatcher/venv/lib/python3.8/site-packages/dispatcher/protocols.py"
    sudo docker exec -it alfa-legacy-instance bash -c "sed -i '49a\\
        print(\"exc: {}, port closed\".format(exc))' /home/alfadesk/dispatcher/venv/lib/python3.8/site-packages/dispatcher/protocols.py"
    sudo docker exec -it alfa-legacy-instance bash -c "sed -i '50a\\
        sys.exit(0)' /home/alfadesk/dispatcher/venv/lib/python3.8/site-packages/dispatcher/protocols.py"
    sudo docker exec -it alfa-legacy-instance bash -c "sed -i '113,115c\\\\n          self._close(exc=e)' /home/alfadesk/dispatcher/venv/lib/python3.8/site-packages/dispatcher/serial_asyncio.py"
    sudo sed -i 's/^PLATFORM_VERSION=5$/PLATFORM_VERSION=5-fix-resolv.conf-and-alfa-legacy/g' /etc/lsb-release
    sudo sed -i 's/^PLATFORM_VERSION=5-fix-resolv.conf$/PLATFORM_VERSION=5-fix-resolv.conf-and-alfa-legacy/g' /etc/lsb-release
    echo 'fix_alfa_legacy terminated'
    sudo supervisorctl reload
fi
