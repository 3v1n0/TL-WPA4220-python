#!/bin/env python3

# Copyright 2022 - Marco Trevisan <mail@3v1n0.net>
# License: LGPL-2.1
#
# Based on work from Oriol Castejon @foolisses

import argparse
import base64
import hashlib
import json
import logging
import os
import requests
import sys
import time
from enum import Enum
from Crypto.Cipher import AES
from urllib.parse import urlencode
from simplejson.errors import JSONDecodeError

class TL_WPA4220(object):
    # From tpEncrypt.js:
    KEY_LEN = 128 / 8
    CRYPTO_MODE = AES.MODE_CBC

    def __init__(self, ip):
        self._ip = ip
        self._password_hash = None
        self._seq = None
        self._e = None
        self._n = None
        self._timeout = 15*1000
        self._logger = logging.getLogger(__class__.__name__)
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(
            '[%(levelname)s] %(name)s: %(funcName)s: %(message)s'))
        self._logger.addHandler(console_handler)

    @property
    def ip(self):
        return self._ip

    @property
    def logger(self):
        return self._logger

    class TpError(Exception):
        def __init__(self, msg, error_code=None):
            super().__init__(msg)
            self.error_code = error_code

    class Op(Enum):
        LOGIN = 'login'
        READ = 'read'
        WRITE = 'write'
        LOAD = 'load'
        INSERT = 'insert'

    class LogType(Enum):
        ALL = 'ALL'
        DHCP = 'dhcp'
        LED_SWITCH = 'led-switch'
        OTHER = 'other'
        WIFI_SCHEDULES = 'wifi-schedules'
        WIFI_CLONE = 'wifi-clone'
        WIFI_MOVE = 'wifi-move'
        WIFI_SWITCH = 'wifi-switch'

    class LogLevel(Enum):
        ALL = 'ALL'
        ERROR = 'ERROR'
        INFO = 'INFO'

    def login(self, password):
        if self._password_hash:
            raise self.TpError('Already logged in!')

        self._key = os.urandom(16)
        self._iv = os.urandom(16)
        def get_random_bytes(size):
            return ''.join([f'{i:02x}' for i in os.urandom(int(size / 2))]).encode(
                'utf-8')

        self._key = get_random_bytes(self.KEY_LEN)
        self._iv = get_random_bytes(AES.block_size)
        self.logger.debug(f'Using key: {self._key}, iv: {self._iv}')

        self._get_rsa_pubkey_seq()

        m = hashlib.md5()
        m.update(password.encode('utf-8'))
        self._password_hash = m.hexdigest()

        encrypted_pw = self._rsa_encrypt(password)
        for _i in range(2):
            try:
                self._encrypted_req("login?form=login", self.Op.LOGIN, {
                    'password': encrypted_pw,
                })
                break
            except TL_WPA4220.TpError as e:
                if e.error_code != 'decode-error':
                    self._unset_login_data()
                    raise e
                self.logger.debug(f'Got error {e.error_code}, retrying...')
                time.sleep(0.5)

    def logged_in(self):
        return self._password_hash != None

    def logout(self):
        self._require_login()
        old_timeout = self._timeout
        self._timeout = 0.1 # Do not block in this case...
        self._encrypted_req('admin/logout.htm', self.Op.WRITE, extra_headers={
            'Cookie': 'Authorization=;path=/'
        })
        self._timeout = old_timeout
        self._unset_login_data()

    def reboot(self):
        self._require_login()
        ret = self._encrypted_req('admin/reboot.json', self.Op.WRITE).get(
            'success')
        self._unset_login_data()
        return ret

    def get_firmware_info(self):
        self._require_login()
        return self._encrypted_req('admin/firmware?form=upgrade', self.Op.READ)

    def get_region(self):
        self._require_login()
        return self._encrypted_req('admin/wireless?form=region', self.Op.READ)

    def get_locales(self):
        self._require_login()
        return self._encrypted_req('admin/locale?form=list', self.Op.READ)

    def get_locale(self):
        self._require_login()
        return self._encrypted_req('admin/locale?form=index_lang', self.Op.READ)

    def set_locale(self, locale):
        self._require_login()
        return self._encrypted_req('admin/locale?form=index_lang', self.Op.WRITE, {
            'locale': locale,
        })

    def get_profile(self):
        self._require_login()
        return self._encrypted_req('data/profile.json', self.Op.READ);

    def set_password(self, current_password, new_password):
        self._require_login()
        # FIXME: Something is still missing here...
        return self._encrypted_req('/admin/administration?form=account', self.Op.WRITE, {
            'old_acc': 'admin',
            'old_pwd': current_password,
            'new_acc': 'admin',
            'new_pwd': new_password,
            'cfm_pwd': new_password,
        }, extra_headers={'Cookie': 'Authorization=;path=/' })

    def get_lan_settings(self):
        self._require_login()
        return self._encrypted_req('admin/lanCfg', self.Op.READ)

    def set_lan_settings(self, static=True, ip=None, mask=None, gateway=None):
        self._require_login()
        if static:
            data = {}
            if not ip or not mask or not gateway:
                data = self.get_lan_settings()
            data['lan_type'] = 'static'
            if ip:
                data['lan_ip'] = ip
            if mask:
                data['lan_mask'] = mask
            if gateway:
                data['lan_gw'] = gateway
        else:
            data = {'lan_type': 'dynamic'}
        ret = self._encrypted_req('admin/lanCfg', self.Op.WRITE, data)
        self._unset_login_data()
        return ret

    def get_dhcp_settings(self):
        self._require_login()
        return self._encrypted_req('admin/dhcps?form=setting', self.Op.READ)

    def set_dhcp_settings(self, enabled, ip_start, ip_end, lease_time, gateway,
                          pri_dns='0.0.0.0', snd_dns='0.0.0.0'):
        self._require_login()
        if not enabled:
            return self._encrypted_req('admin/dhcps?form=setting', self.Op.WRITE, {
                'enable': enabled,
            })
        return self._encrypted_req('admin/dhcps?form=setting', self.Op.WRITE, {
            'enable': enabled,
            'ipaddr_start': ip_start,
            'ipaddr_end': ip_end,
            'leasetime': lease_time,
            'gateway': gateway,
            'pri_dns': pri_dns,
            'snd_dns': snd_dns,
        })

    def get_dhcp_clients(self):
        if not self._get_enabled_value(self.get_dhcp_settings()):
            return []
        return self._encrypted_req('admin/dhcps?form=client', self.Op.READ)

    def get_wlan_status(self):
        self._require_login()
        return self._encrypted_req('admin/wlan_status', self.Op.READ)

    def get_guest_wlan_2g_status(self):
        self._require_login()
        return self._encrypted_req('admin/guest?form=guest_2g', self.Op.READ)

    def get_guest_wlan_5g_status(self):
        self._require_login()
        return self._encrypted_req('admin/guest?form=guest_5g', self.Op.READ)

    def get_wifi_move_status(self):
        self._require_login()
        val = self._encrypted_req('admin/wifiMove.json', self.Op.READ)
        return self._get_enabled_value(val)

    def toggle_wifi_move(self, enabled):
        self._require_login()
        val = self._encrypted_req('admin/wifiMove.json', self.Op.WRITE, {
            'enable': int(enabled),
        })
        return self._get_enabled_value(val)

    def get_wifi_time_control_enabled(self):
        self._require_login()
        return self._encrypted_req('admin/wifiTimeEnable', self.Op.READ)

    def get_wifi_time_control_status(self):
        self._require_login()
        return self._encrypted_req('admin/wifiTimeControl', self.Op.READ)

    def get_wifi_clients(self):
        self._require_login()
        # return self._encrypted_req('data/wireless.statistics.json', self.Op.LOAD)
        return self._encrypted_req('admin/wireless?form=statistics', self.Op.LOAD)

    def get_plc_device_status(self):
        self._require_login()
        return self._encrypted_req('admin/powerline?form=plc_device', self.Op.LOAD)

    def get_plc_local_settings(self):
        self._require_login()
        return self._encrypted_req('admin/powerline?form=plc_local', self.Op.READ)

    def set_plc_local_settings(self, network_name):
        self._require_login()
        current_settings = self.get_plc_local_settings()
        return self._encrypted_req('admin/powerline?form=plc_local', self.Op.WRITE, {
            'macaddr': current_settings['macaddr'],
            'password': current_settings['password'],
            'networkname': network_name,
        })

    def get_system_log(self):
        self._require_login()
        try:
            return self._encrypted_req('admin/syslog?form=log', self.Op.LOAD)
        except self.TL_WPA4220.TpError as e:
            if e.error_code:
                raise e
            self.logger.warning('No log level set, impossible to get logging')
            return []

    def get_system_log_filters(self, log_type=None):
        if not log_type:
            log_type = self.LogType.ALL
        if not log_type in list(self.LogType):
            raise self.TpError(f'Invalid log type: {log_type}')
        self._require_login()
        return self._encrypted_req('admin/syslog?form=filter', self.Op.READ, {
            'type': log_type,
        })

    def set_system_log_filters(self, log_type, level):
        if not log_type in list(self.LogType):
            raise self.TpError(f'Invalid log type: {log_type}')
        if not level in list(self.LogLevel):
            raise self.TpError(f'Invalid log level: {level}')

        self._require_login()
        return self._encrypted_req('admin/syslog?form=filter', self.Op.WRITE, {
            'type': log_type.value,
            'level': level.value,
        })

    def _led_toggle(self, operation, data={}):
        value = self._encrypted_req('admin/ledSettings?form=enable', operation, data)
        return self._get_enabled_value(value)

    def get_led_status(self):
        self._require_login()
        return self._led_toggle(self.Op.READ, {
            'enable': 'toggle',
        })

    def led_switch(self, value):
        self._require_login()
        return self._led_toggle(self.Op.WRITE, {
            'enable': 'toggle',
            'toggle': 'on' if value else 'off'
        })

    def get_mac_filters_list(self):
        self._require_login()
        return self._encrypted_req('admin/wireless?form=maclist', self.Op.LOAD)

    def _require_login(self):
        if not self.logged_in():
            raise self.TpError('Not logged in!')

    def _get_enabled_value(self, data):
        val = {'on': 1, 'off': 0}.get(data.get('enable'), data.get('enable'))
        return bool(int(val))

    def _unset_login_data(self):
        self._iv = None
        self._key = None
        self._password_hash = None
        self._seq = None
        self._e = None
        self._n = None

    def _rsa_encrypt(self, plaintext):
        encrypted = ''
        for i in range(len(plaintext) // 64 + 1):
            block = plaintext[i * 64:(i + 1) * 64]
            encoded = [format(ord(c), 'x') for c in block] + ['00'] * (64 - len(block))
            encoded = int("".join(encoded), 16)
            encrypted_block = pow(encoded, self._e, self._n)
            encrypted += format(encrypted_block, 'x')
        if len(encrypted) % 2 == 1:
            encrypted = '0' + encrypted
        return encrypted

    def _pad(self, plaintext):
        pad = AES.block_size - len(plaintext) % AES.block_size
        return plaintext + pad * chr(pad)

    def _aes_encrypt(self, plaintext):
        padded = self._pad(plaintext)
        cipher = AES.new(self._key, self.CRYPTO_MODE, self._iv)
        encrypted = cipher.encrypt(padded.encode())
        return base64.b64encode(encrypted).decode('utf-8')

    def _aes_decrypt(self, encrypted):
        cipher = AES.new(self._key, self.CRYPTO_MODE, self._iv)
        plaintext = cipher.decrypt(base64.b64decode(encrypted))
        return plaintext[:-ord(plaintext[len(plaintext) - 1:])].decode('utf-8')

    def _get_rsa_pubkey_seq(self):
        r = requests.post("http://{}/login?form=auth".format(self.ip),
            data={"operation": "read"})
        r = r.json()
        if not r.get("success"):
            raise TpError("Something went wrong, couldn't retrieve RSA public key",
                r.get("errorcode"))

        self._n = int(r["data"]["key"][0], 16)
        self._e = int(r["data"]["key"][1], 16)
        self._seq = int(r["data"]["seq"])

        self.logger.debug(f'n: {self._n}, e: {self._e}, seq: {self._seq}')

    def _encrypted_req(self, path, operation, data={}, extra_headers={}):
        uri = "http://{}/{}".format(self.ip, path)
        data = dict(data)
        data['operation'] = operation.value
        encoded_data = urlencode(data)
        encrypted_data = self._aes_encrypt(encoded_data) if encoded_data else None

        sign_dict = {
            'h': self._password_hash,
            's': self._seq + (len(encrypted_data) if encrypted_data else 0),
        }

        if operation == self.Op.LOGIN:
            sign_dict.update({
                'k': self._key.decode('utf-8'),
                'i': self._iv.decode('utf-8'),
            })

        self.logger.debug(f'uri {uri}')
        self.logger.debug(f'data {encoded_data}')
        self.logger.debug(f'sign: {urlencode(sign_dict)}')

        data = {
            'sign': self._rsa_encrypt(urlencode(sign_dict)),
            'data': encrypted_data
        }

        headers = {
            "Host": self.ip,
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": "http://{}".format(self.ip),
            "Connection": "close",
            "Referer": "http://{}/".format(self.ip),
            "Cookie": "Authorization="
        }
        headers.update(extra_headers)

        try:
            r = requests.post(uri, data=data, headers=headers, timeout=self._timeout)
        except requests.exceptions.ReadTimeout:
            return None

        r.raise_for_status()

        try:
            encrypted_data = r.json().get("data")
            response = self._aes_decrypt(encrypted_data)
            self.logger.debug(f'response: {response}')
            parsed_response = json.loads(response)
            if parsed_response.get("success"):
                return parsed_response.get("data")

            error_code = parsed_response.get("errorcode")
        except JSONDecodeError as e:
            raise TL_WPA4220.TpError(f'Failed to decode: {e}', 'decode-error')
        except Exception as e:
            print("There was some error, could not decrypt response. Error: {}".format(e))
            raise e

        raise TL_WPA4220.TpError(
            f'Failed to execute command, error code: {error_code}', error_code)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Tools to manage the TL-WPA4220')
    parser.add_argument('target', type=str, metavar='target', help='IP of the TL-WPA4220 device')
    parser.add_argument('action', type=str, metavar='action',
        default='show', nargs="?",
        help='Action to perform: [show | led-status | led-off | led-on | reboot]')
    parser.add_argument('-p', '--password', type=str, metavar='password',
                        help='Password of the TL-WPA4220 Web interface (default: admin)', default='admin')
    parser.add_argument('-d', '--debug', action='store_true', default=False)
    args = parser.parse_args()
    device = TL_WPA4220(args.target)

    if args.debug:
        device.logger.setLevel(logging.DEBUG)

    try:
        device.login(args.password)
        print("[+] Login executed successfully")
    except TL_WPA4220.TpError as e:
        if (e.error_code == 'timeout'):
            # We could get the reason by the first value of JS httpAutErrorArray
            print(f"[!] Login failed, password invalid or another device is logged in")
        else:
            print(f"[!] Login failed: {e}")
        sys.exit(1)

    exit_status = True
    if args.action == 'show':
        device.set_system_log_filters(
            TL_WPA4220.LogType.ALL, TL_WPA4220.LogLevel.ALL)

        print('FirmwareInfo:', device.get_firmware_info())
        print('Region:', device.get_region())
        print('Locale:', device.get_locale())
        print('Locales:', device.get_locales())
        print('Profile:', device.get_profile())
        print('LanSettings', device.get_lan_settings())
        print('DhcpSettings', device.get_dhcp_settings())
        print('DhcpClients', device.get_dhcp_clients())
        print('WlanStatus:', device.get_wlan_status())
        print('WifiMoveStatus:', device.get_wifi_move_status())
        print('WifiTimeControl:', device.get_wifi_time_control_enabled())
        print('WifiTimeControlStatus:', device.get_wifi_time_control_status())
        print('WifiClients:', device.get_wifi_clients())
        print('GuestWlan_2gStatus:', device.get_guest_wlan_2g_status())
        print('GuestWlan_5gStatus:', device.get_guest_wlan_5g_status())
        print('PlcDeviceStatus:', device.get_plc_device_status())
        print('PlcLocalSettings:', device.get_plc_local_settings())
        print('MacFilterList:', device.get_mac_filters_list())
        print('LedStatus:', device.get_led_status())
        print('SystemLog', device.get_system_log())
        print('SystemLogFilters', device.get_system_log_filters())
    elif args.action == 'led-status':
        led_status = device.get_led_status()
        print('Led status:', 'on' if led_status else 'off')
        exit_status = led_status
    elif args.action == 'led-on':
        device.led_switch(True)
        exit_status = device.get_led_status()
    elif args.action == 'led-off':
        device.led_switch(False)
        exit_status = not device.get_led_status()
    elif args.action == 'reboot':
        sys.exit(0 if device.reboot() else 1)
    else:
        device.logout()
        raise argparse.ArgumentError(None, f'Unknown action {args.action}')

    device.logout()

    if not exit_status:
        sys.exit(1)
