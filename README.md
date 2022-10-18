# Python API for Tp-Link TL-WPA4220 Powerline

A simple API to control and get information from the [Tp-Link TL-WPA4220
Powerline](https://www.tp-link.com/en/home-networking/powerline/tl-wpa4220/).

```python
>>> import TL_WPA4220
>>> p = TL_WPA4220.TL_WPA4220(ip='192.168.1.3')
>>> p.login(password='admin')
>>> p.get_firmware_info()
{'firmware_version': '4.0.4 Build 20220408 Rel.36351', 'hardware_version': 'TL-WPA4220 v4.0', 'totaltime': 60, 'is_default': 0, 'model': 'TL-WPA4220'}
>>> p.get_led_status()
True
>>> p.led_switch(False)
False
>>> p.get_led_status()
False
>>> p.get_plc_device_status()
[{'device_mac': 'F4-F2-6D-75-00-9F', 'device_password': '', 'rx_rate': '53', 'tx_rate': '111', 'status': 'on'}]
>>>> p.get_lan_settings()
{'lan_type': 'static', 'lan_ip': '192.168.1.3', 'old_ipaddr': '192.168.1.3', 'lan_mask': '255.255.255.0', 'lan_gw': '192.168.1.1'}
>> p.get_system_log()
[{'time': '0 days 03:48:46', 'type': 'OTHERS', 'level': 'INFO', 'content': 'Username and password are successfully updated.'}, {'time': '0 days 03:45:33', 'type': 'OTHERS', 'level': 'INFO', 'content': 'Username and password are successfully updated.'}, {'time': '0 days 02:10:29', 'type': 'WIFI-SCHEDULES', 'level': 'INFO', 'content': 'Wifi schedules disabled.'}, {'time': '0 days 02:09:55', 'type': 'WIFI-SCHEDULES', 'level': 'INFO', 'content': 'Wifi schedules enabled.'}, {'time': '0 days 01:57:28', 'type': 'WIFI-MOVE', 'level': 'INFO', 'content': 'Wi-Fi Move start.'}, {'time': '0 days 01:57:18', 'type': 'WIFI-MOVE', 'level': 'INFO', 'content': 'Wi-Fi Move stopped.'}, {'time': '0 days 00:00:17', 'type': 'PARENTAL-CONTROLS', 'level': 'INFO', 'content': 'Parental control disabled.'}, {'time': '0 days 00:00:16', 'type': 'MAC-FILTER', 'level': 'INFO', 'content': 'Access control disabled.'}, {'time': '0 days 00:00:05', 'type': 'WIFI-SCHEDULES', 'level': 'INFO', 'content': 'Wifi schedules disabled.'}, {'time': '0 days 00:00:05', 'type': 'WIFI-MOVE', 'level': 'INFO', 'content': 'Wi-Fi Move start.'}, {'time': '0 days 00:00:05', 'type': 'LED-SCHEDULES', 'level': 'INFO', 'content': 'Led schedules enabled.'}, {'time': '0 days 00:00:04', 'type': 'WIFI-SCHEDULES', 'level': 'INFO', 'content': 'Wifi schedules disabled.'}, {'time': '0 days 00:00:04', 'type': 'OTHERS', 'level': 'INFO', 'content': 'System started.'}]
>>> # p.reboot()
>>> p.logout()
```

Most of parameters can be configured, although it still needs testing and
tuning of some parameters.

It also comes with a base command-line tool, check `TL_WPA4220.py --help`

```
usage: TL_WPA4220.py [-h] [-p password] [-i] [-d] target [action]

Tools to manage the TL-WPA4220

positional arguments:
  target                IP of the TL-WPA4220 device
  action                Action to perform: [show | led-status | led-off | led-on | reboot]

optional arguments:
  -h, --help            show this help message and exit
  -p password, --password password
                        Password of the TL-WPA4220 Web interface (default: admin)
  -d, --debug
```
