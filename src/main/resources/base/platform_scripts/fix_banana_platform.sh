#!/bin/bash

set -e

patch_applied=0

start_browser_patch="/home/admin/start_browser.patch"
start_browser="/home/admin/start_browser.sh"
start_browser_orig="${start_browser}.ORIG"
rtc_ds3231_patch="/home/admin/rtc_ds3231.patch"
rtc_ds3231="/etc/systemd/system/rtc_ds3231.service"
rtc_ds3231_orig="${rtc_ds3231}.ORIG"
restore_display_resolution_patch="/home/admin/restore_display_resolution.patch"
restore_display_resolution="/home/admin/restore_display_resolution.sh"
restore_display_resolution_orig="${restore_display_resolution}.ORIG"

### Create the patch files
cat > $start_browser_patch << "EOF"
--- start_browser.sh.ORIG    2019-02-14 11:50:18.840001097 +0100
+++ start_browser.sh    2019-02-14 11:50:44.584001109 +0100
@@ -1,7 +1,7 @@
 #!/bin/bash
 
 while [ true ]; do
-   wget http://localhost/ -q 
+   wget http://localhost/ -q -O /dev/null
    if [ $? -ne 0 ]; then
       sleep 1
    else
@@ -10,4 +10,4 @@
 done
 
 
-exec /usr/bin/chromium --disable-restore-session-state --no-first-run --kiosk --load-extension=/home/admin/.config/chromium/Default/Extensions/pflmllfnnabikmfkkaddkoolinlfninn/1.12.8_0/ 127.0.0.1
\ No newline at end of file
+exec /usr/bin/chromium --disable-restore-session-state --no-first-run --kiosk --load-extension=/home/admin/.config/chromium/Default/Extensions/pflmllfnnabikmfkkaddkoolinlfninn/1.12.8_0/ 127.0.0.1
EOF

cat > $rtc_ds3231_patch <<"EOF"
--- rtc_ds3231.service.ORIG 2019-02-14 12:38:26.484002474 +0100
+++ rtc_ds3231.service  2019-02-14 12:39:18.564002498 +0100
@@ -6,7 +6,7 @@
 Type=oneshot
 User=root
 ExecStartPre=/usr/bin/bash -c '/usr/bin/sudo /usr/bin/echo ds3231 0x68 > /sys/class/i2c-adapter/i2c-0/new_device'
-ExecStart=hwclock -s
+ExecStart=/usr/bin/bash -c '/bin/sleep 2 && /sbin/hwclock -s'
 
 [Install]
-WantedBy=multi-user.target
\ No newline at end of file
+WantedBy=multi-user.target
EOF

cat > $restore_display_resolution_patch << "EOF"
--- restore_display_resolution.sh.ORIG  2023-07-05 00:37:58.044745443 +0200
+++ restore_display_resolution.sh 2023-07-05 00:38:35.345544873 +0200
@@ -6,8 +6,8 @@
 while [ 1 ]; do
   xrandr  | grep -q "current 1920 x 1080"
   if [ $? -ne 0 ]; then
-     date
-     echo "fixing resolution"               
+     #date
+     #echo "fixing resolution"               
      xrandr --output HDMI-1 --auto
   fi
   sleep 1 
EOF

### Create ORIG files
if [ ! -f "$start_browser_orig" ]; then
    cp "$start_browser" "$start_browser_orig"
fi

if [ ! -f "$rtc_ds3231_orig" ]; then
    sudo cp "$rtc_ds3231" "$rtc_ds3231_orig"
fi

if [ ! -f "$restore_display_resolution_orig" ]; then
    cp "$restore_display_resolution" "$restore_display_resolution_orig"
fi


### Applying patches
output_start_browser_patch=$(cd /home/admin && patch -N -i $start_browser_patch -p0 -r - $start_browser)
if echo "$output_start_browser_patch" | grep -q "Skipping patch"; then
    echo "Skipping patch .. Start Browser Patch already applied !"
else
    patch_applied=1
    echo "Start Browser Patch applied !"
fi

output_rtc_ds3231_patch=$(cd /etc/systemd/system/ && sudo patch -N -i $rtc_ds3231_patch -p0 -r - $rtc_ds3231)
if echo "$output_rtc_ds3231_patch" | grep -q "Skipping patch"; then
    echo "Skipping patch .. RTC DS3231 Patch already applied !"
else
    patch_applied=1
    echo "RTC DS3231 Patch applied !"
fi

output_restore_display_resolution_patch=$(cd /home/admin && patch -N -i $restore_display_resolution_patch -p0 -r - $restore_display_resolution)
if echo "$output_restore_display_resolution_patch" | grep -q "Skipping patch"; then
    echo "Skipping patch .. Restore Display Resolution Patch already applied !"
else
    patch_applied=1
    echo "Restore Display Resolution Patch applied !"
fi

### Other stuffs related to platform
if [ ! -f "/etc/udev/rules.d/99-rtc1.rules" ]; then
  content='KERNEL=="rtc1", SYMLINK+="rtc"'
  echo -e "$content" | sudo tee /etc/udev/rules.d/99-rtc1.rules > /dev/null
  sudo udevadm control --reload-rules
  sudo udevadm trigger
  echo "Added 99-rtc1.rules"
fi

rm -f /home/admin/index.*

if [ "$patch_applied" -eq 1 ]; then
    echo "fix_banana_platform terminated"
fi
