# -*- coding: utf_8 -*-
"""Module holding the functions for code analysis."""

import io
import ntpath
import shutil
import re
import os

from django.conf import settings
from django.utils.html import escape

from MalwareAnalyzer.views import MalwareCheck

from MobSF.utils import (
    PrintException
)

def _get_code_dict():
    code = {
        key: [] for key in (
            'inf_act',
            'inf_ser',
            'inf_bro',
            'log',
            'fileio',
            'rand',
            'd_hcode',
            'd_app_tamper',
            'dex_cert',
            'dex_tamper',
            'd_rootcheck',
            'd_root',
            'd_ssl_pin',
            'dex_root',
            'dex_debug_key',
            'dex_debug',
            'dex_debug_con',
            'dex_emulator',
            'd_prevent_screenshot',
            'd_webviewdisablessl',
            'd_webviewdebug',
            'd_sensitive',
            'd_ssl',
            'd_sqlite',
            'd_con_world_readable',
            'd_con_world_writable',
            'd_con_private',
            'd_extstorage',
            'd_tmpfile',
            'd_jsenabled',
            'gps',
            'crypto',
            'exec',
            'server_socket',
            'socket',
            'datagramp',
            'datagrams',
            'ipc',
            'msg',
            'webview_addjs',
            'webview',
            'webviewget',
            'webviewpost',
            'httpcon',
            'urlcon',
            'jurl',
            'httpsurl',
            'nurl',
            'httpclient',
            'notify',
            'cellinfo',
            'cellloc',
            'subid',
            'devid',
            'softver',
            'simserial',
            'simop',
            'opname',
            'contentq',
            'refmethod',
            'obf',
            'gs',
            'bencode',
            'bdecode',
            'dex',
            'mdigest',
            'sqlc_password',
            'd_sql_cipher',
            'd_con_world_rw',
            'ecb',
            'rsa_no_pad',
            'weak_iv'
        )
    }
    return code


def _get_api_desc_dict():
    #API Description
    api_desc = {
        'gps':'GPS Location',
        'crypto':'Crypto ',
        'exec': 'Execute System Command ',
        'server_socket':'TCP Server Socket ',
        'socket': 'TCP Socket ',
        'datagramp': 'UDP Datagram Packet ',
        'datagrams': 'UDP Datagram Socket ',
        'ipc': 'Inter Process Communication ',
        'msg': 'Send SMS ',
        'webview_addjs':'WebView JavaScript Interface ',
        'webview': 'WebView Load HTML/JavaScript ',
        'webviewget': 'WebView GET Request ',
        'webviewpost': 'WebView POST Request ',
        'httpcon': 'HTTP Connection ',
        'urlcon':'URL Connection to file/http/https/ftp/jar ',
        'jurl':'JAR URL Connection ',
        'httpsurl':'HTTPS Connection ',
        'nurl':'URL Connection supports file,http,https,ftp and jar ',
        'httpclient':'HTTP Requests, Connections and Sessions ',
        'notify': 'Android Notifications ',
        'cellinfo':'Get Cell Information ',
        'cellloc':'Get Cell Location ',
        'subid':'Get Subscriber ID ',
        'devid':'Get Device ID, IMEI,MEID/ESN etc. ',
        'softver':'Get Software Version, IMEI/SV etc. ',
        'simserial': 'Get SIM Serial Number ',
        'simop': 'Get SIM Provider Details ',
        'opname':'Get SIM Operator Name ',
        'contentq':'Query Database of SMS, Contacts etc. ',
        'refmethod':'Java Reflection Method Invocation ',
        'obf': 'Obfuscation ',
        'gs':'Get System Service ',
        'bencode':'Base64 Encode ',
        'bdecode':'Base64 Decode ',
        'dex':'Load and Manipulate Dex Files ',
        'mdigest': 'Message Digest ',
        'fileio': 'Local File I/O Operations',
        'inf_act': 'Starting Activity',
        'inf_ser': 'Starting Service',
        'inf_bro': 'Sending Broadcast'
    }
    return api_desc


def _get_desc_dict():
    desc = {
        'd_sensitive' :
            (
                'Files may contain hardcoded sensitive informations like '
                'usernames, passwords, keys etc.'
            ),
        'd_ssl':
            (
                'Insecure Implementation of SSL. Trusting all the certificates or accepting '
                'self signed certificates is a critical Security Hole. This application is '
                'vulnerable to MITM attacks'
            ),
        'd_sqlite':
            (
                'App uses SQLite Database and execute raw SQL query. Untrusted user input in '
                'raw SQL queries can cause SQL Injection. Also sensitive information should be '
                'encrypted and written to the database.'
            ),
        'd_con_world_readable':
            (
                'The file is World Readable. Any App can read from the file'
            ),
        'd_con_world_writable':
            (
                'The file is World Writable. Any App can write to the file'
            ),
        'd_con_world_rw':
            (
                'The file is World Readable and Writable. Any App can read/write to the file'
            ),
        'd_con_private':
            (
                'App can write to App Directory. Sensitive Information should be encrypted.'
            ),
        'd_extstorage':
            (
                'App can read/write to External Storage. Any App can read data written to '
                'External Storage.'
            ),
        'd_tmpfile':
            (
                'App creates temp file. Sensitive information should never be written into a '
                'temp file.'
            ),
        'd_jsenabled':
            (
                'Insecure WebView Implementation. Execution of user controlled code in WebView '
                'is a critical Security Hole.'
            ),
        'd_webviewdisablessl':
            (
                'Insecure WebView Implementation. WebView ignores SSL Certificate errors and '
                'accept any SSL Certificate. This application is vulnerable to MITM attacks'
            ),
        'd_webviewdebug':
            (
                'Remote WebView debugging is enabled.'
            ),
        'dex_debug':
            (
                'DexGuard Debug Detection code to detect wheather an App is debuggable or not '
                'is identified.'
            ),
        'dex_debug_con':
            (
                'DexGuard Debugger Detection code is identified.'
            ),
        'dex_debug_key':
            (
                'DecGuard code to detect wheather the App is signed with a debug key or not '
                'is identified.'
            ),
        'dex_emulator':
            (
                'DexGuard Emulator Detection code is identified.'
            ),
        'dex_root':
            (
                'DexGuard Root Detection code is identified.'
            ),
        'dex_tamper' :
            (
                'DexGuard App Tamper Detection code is identified.'
            ),
        'dex_cert' :
            (
                'DexGuard Signer Certificate Tamper Detection code is identified.'
            ),
        'd_ssl_pin':
            (
                ' This App uses an SSL Pinning Library (org.thoughtcrime.ssl.pinning) to '
                'prevent MITM attacks in secure communication channel.'
            ),
        'd_root' :
            (
                'This App may request root (Super User) privileges.'
            ),
        'd_rootcheck' :
            (
                'This App may have root detection capabilities.'
            ),
        'd_hcode' :
            (
                'This App uses Java Hash Code. It\'s a weak hash function and should never be '
                'used in Secure Crypto Implementation.'
            ),
        'rand' :
            (
                'The App uses an insecure Random Number Generator.'
            ),
        'log' :
            (
                'The App logs information. Sensitive information should never be logged.'
            ),
        'd_app_tamper' :
            (
                'The App may use package signature for tamper detection.'
            ),
        'd_prevent_screenshot' :
            (
                'This App has capabilities to prevent against Screenshots from Recent Task '
                'History/ Now On Tap etc.'
            ),
        'd_sql_cipher' :
            (
                'This App uses SQL Cipher. SQLCipher provides 256-bit AES encryption to sqlite '
                'database files.'
            ),
        'sqlc_password' :
            (
                'This App uses SQL Cipher. But the secret may be hardcoded.'
            ),
        'ecb' :
            (
                'The App uses ECB mode in Cryptographic encryption algorithm. ECB mode is '
                'known to be weak as it results in the same ciphertext for identical blocks '
                'of plaintext.'
            ),
        'rsa_no_pad' :
            (
                'This App uses RSA Crypto without OAEP padding. The purpose of the padding '
                'scheme is to prevent a number of attacks on RSA that only work when the '
                'encryption is performed without padding.'
            ),
        'weak_iv' :
            (
                'The App may use weak IVs like "0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00" or '
                '"0x01,0x02,0x03,0x04,0x05,0x06,0x07". Not using a random IV makes the '
                'resulting ciphertext much more predictable and susceptible to a dictionary '
                'attack.'
            ),
    }
    return desc


def _get_java_src(analysis_dict):
    """Return the correct java_src for typ."""
    if analysis_dict['typ'] == "apk":
        analysis_dict['java_src'] = os.path.join(analysis_dict['app_dir'], 'java_source/')
    elif analysis_dict['typ'] == "studio":
        analysis_dict['java_src'] = os.path.join(analysis_dict['app_dir'], 'app/src/main/java/')
    elif analysis_dict['typ'] == "eclipse":
        analysis_dict['java_src'] = os.path.join(analysis_dict['app_dir'], 'src/')
    return analysis_dict


def _get_api_analysis(analysis_dict):
    """Analyze used APIs."""
    api_desc = _get_api_desc_dict()
    html = ''
    for api_key in api_desc:
        if analysis_dict['code'][api_key]:
            link = ''
            # TODO(No idea what hd means here..)
            h_d = "<tr><td>" + api_desc[api_key] + "</td><td>"
            for elem in analysis_dict['code'][api_key]:
                link += (
                    "<a href='../ViewSource/?file=" + escape(elem) + "&md5=" +
                    analysis_dict['md5'] + "&type=" + analysis_dict['typ'] + "'>" +
                    escape(ntpath.basename(elem)) + "</a> "
                )
            html += h_d + link + "</td></tr>"

    return html


def _get_dangers_per_file(analysis_dict):
    """Get the dangers per file."""
    # Init
    dang = ''

    # Security Code Review Description
    desc = _get_desc_dict()

    span_dict = {
        'spn_dang': '<span class="label label-danger">high</span>',
        'spn_info': '<span class="label label-info">info</span>',
        'spn_sec': '<span class="label label-success">secure</span>',
        'spn_warn': '<span class="label label-warning">warning</span>'
    }

    for k in desc:
        if analysis_dict['code'][k]:
            link = ''
            if re.findall('d_con_private|log', k):
                h_d = '<tr><td>' + desc[k] + '</td><td>' + span_dict['spn_info'] + '</td><td>'
            elif re.findall(
                    (
                        'd_sql_cipher|d_prevent_screenshot|d_app_tamper|d_rootcheck|dex_cert|'
                        'dex_tamper|dex_debug|dex_debug_con|dex_debug_key|dex_emulator|dex_root'
                        '|d_ssl_pin'
                    ),
                    k
            ):
                h_d = '<tr><td>' + desc[k] + '</td><td>' + span_dict['spn_sec'] + '</td><td>'
            elif re.findall('d_jsenabled', k):
                h_d = '<tr><td>' + desc[k] + '</td><td>' + span_dict['spn_warn'] + '</td><td>'
            else:
                h_d = '<tr><td>' + desc[k] + '</td><td>' + span_dict['spn_dang'] + '</td><td>'

            for elem in analysis_dict['code'][k]:
                link += (
                    "<a href='../ViewSource/?file=" + escape(elem) + "&md5=" +
                    analysis_dict['md5'] + "&type=" + analysis_dict['typ'] + "'>" +
                    escape(ntpath.basename(elem)) + "</a> "
                )

            dang += h_d + link + "</td></tr>"

    return dang


def __get_dexguard(analysis_dict, dat):
    """Analyze code and look for dexuard."""
    if (
            'import dexguard.util' in dat and
            'DebugDetector.isDebuggable' in dat
    ):
        analysis_dict['code']['dex_debug'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if (
            'import dexguard.util' in dat and
            'DebugDetector.isDebuggerConnected' in dat
    ):
        analysis_dict['code']['dex_debug_con'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if (
            ('import dexguard.util') in dat and
            ('EmulatorDetector.isRunningInEmulator') in dat
    ):
        analysis_dict['code']['dex_emulator'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if (
            ('import dexguard.util') in dat and
            ('DebugDetector.isSignedWithDebugKey') in dat
    ):
        analysis_dict['code']['dex_debug_key'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if 'import dexguard.util' in dat and 'RootDetector.isDeviceRooted' in dat:
        analysis_dict['code']['dex_root'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if 'import dexguard.util' in dat and 'TamperDetector.checkApk' in dat:
        analysis_dict['code']['dex_tamper'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if (
            'import dexguard.util' in dat and
            'CertificateChecker.checkCertificate' in dat
    ):
        analysis_dict['code']['dex_cert'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if (
            (
                'dalvik.system.PathClassLoader' in dat or
                'dalvik.system.DexFile' in dat or
                'dalvik.system.DexPathList' in dat or
                'dalvik.system.DexClassLoader' in dat
            ) and (
                'loadDex' in dat or
                'loadClass' in dat or
                'DexClassLoader' in dat or
                'loadDexFile' in dat
            )
    ):
        analysis_dict['code']['dex'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )

    return analysis_dict


def __get_root_detection(analysis_dict, dat):
    """Analyze data for signs of rooting."""
    if (
            'com.noshufou.android.su' in dat or
            'com.thirdparty.superuser' in dat or
            'eu.chainfire.supersu' in dat or
            'com.koushikdutta.superuser' in dat or
            'eu.chainfire.' in dat
    ):
        analysis_dict['code']['d_root'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if (
            ('.contains("test-keys")') in dat or
            ('/system/app/Superuser.apk') in dat or
            ('isDeviceRooted()') in dat or
            ('/system/bin/failsafe/su') in dat or
            ('/system/sd/xbin/su') in dat or
            ('"/system/xbin/which", "su"') in dat or
            ('RootTools.isAccessGiven()') in dat
    ):
        analysis_dict['code']['d_rootcheck'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )

    return analysis_dict


def __get_crypto(analysis_dict, dat):
    """Analyze data for weak crypto."""
    if re.findall(r'Cipher\.getInstance\(\s*"\s*AES\/ECB', dat):
        analysis_dict['code']['ecb'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if re.findall(r'cipher\.getinstance\(\s*"rsa/.+/nopadding', dat.lower()):
        analysis_dict['code']['rsa_no_pad'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if (
            "0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00" in dat or
            "0x01,0x02,0x03,0x04,0x05,0x06,0x07" in dat
    ):
        analysis_dict['code']['weak_iv'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if re.findall(r'java\.util\.Random', dat):
        analysis_dict['code']['rand'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if ".hashCode()" in dat:
        analysis_dict['code']['d_hcode'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if re.findall('javax.crypto|kalium.crypto|bouncycastle.crypto', dat):
        analysis_dict['crypto'] = True
        analysis_dict['code']['crypto'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if 'utils.AESObfuscator' in dat and 'getObfuscator' in dat:
        analysis_dict['code']['obf'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
        analysis_dict['obfus'] = True
    if 'android.util.Base64' in dat and '.decode' in dat:
        analysis_dict['code']['bdecode'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if (
            (
                'android.util.Base64' in dat
            ) and (
                '.encodeToString' in dat or
                '.encode' in dat
            )
    ):
        analysis_dict['code']['bencode'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if (
            (
                'java.security.MessageDigest' in dat
            ) and (
                'MessageDigestSpi' in dat or
                'MessageDigest' in dat
            )
        ):
        analysis_dict['code']['mdigest'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )

    return analysis_dict


def __get_ssl(analysis_dict, dat):
    """Analyze data for ssl-config."""
    if (
            (
                ('javax.net.ssl') in dat
            ) and (
                ('TrustAllSSLSocket-Factory') in dat or
                ('AllTrustSSLSocketFactory') in dat or
                ('NonValidatingSSLSocketFactory') in dat or
                ('ALLOW_ALL_HOSTNAME_VERIFIER') in dat or
                ('.setDefaultHostnameVerifier(') in dat or
                ('NullHostnameVerifier(') in dat
            )
    ):
        analysis_dict['code']['d_ssl'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if (
            'password = "' in dat.lower() or
            'secret = "' in dat.lower() or
            'username = "' in dat.lower() or
            'key = "' in dat.lower()
    ):
        analysis_dict['code']['d_sensitive'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )

    if (
            (
                'org.thoughtcrime.ssl.pinning' in dat
            ) and (
                'PinningHelper.getPinnedHttpsURLConnection' in dat or
                'PinningHelper.getPinnedHttpClient' in dat or
                'PinningSSLSocketFactory(' in dat
            )
    ):
        analysis_dict['code']['d_ssl_pin'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    return analysis_dict


def __get_storage(analysis_dict, dat):
    """Analyze data for storage-conf."""
    if (
            re.findall(r'MODE_WORLD_READABLE|Context\.MODE_WORLD_READABLE', dat) or
            re.findall(r'openFileOutput\(\s*".+"\s*,\s*1\s*\)', dat)
    ):
        analysis_dict['code']['d_con_world_readable'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if (
            re.findall(r'MODE_WORLD_WRITABLE|Context\.MODE_WORLD_WRITABLE', dat) or
            re.findall(r'openFileOutput\(\s*".+"\s*,\s*2\s*\)', dat)
    ):
        analysis_dict['code']['d_con_world_writable'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if re.findall(r'openFileOutput\(\s*".+"\s*,\s*3\s*\)', dat):
        analysis_dict['code']['d_con_world_rw'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if re.findall(r'MODE_PRIVATE|Context\.MODE_PRIVATE', dat):
        analysis_dict['code']['d_con_private'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if (
            'WRITE_EXTERNAL_STORAGE' in analysis_dict['perms'] and
            (
                '.getExternalStorage' in dat or
                '.getExternalFilesDir(' in dat
            )
    ):
        analysis_dict['code']['d_extstorage'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if 'WRITE_EXTERNAL_STORAGE' in analysis_dict['perms'] and '.createTempFile(' in dat:
        analysis_dict['code']['d_tmpfile'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if re.findall(
            (
                'OpenFileOutput|getSharedPreferences|SharedPreferences.Editor|'
                'getCacheDir|getExternalStorageState|openOrCreateDatabase'
            ),
            dat
    ):
        analysis_dict['code']['fileio'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )

    return analysis_dict


def __get_socket(analysis_dict, dat):
    """Analyze data for sockets."""
    if 'ServerSocket' in dat and 'net.ServerSocket' in dat:
        analysis_dict['code']['server_socket'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if 'Socket' in dat and 'net.Socket' in dat:
        analysis_dict['code']['socket'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if 'DatagramPacket' in dat and 'net.DatagramPacket' in dat:
        analysis_dict['code']['datagramp'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if 'DatagramSocket' in dat and 'net.DatagramSocket' in dat:
        analysis_dict['code']['datagrams'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    return analysis_dict


def __get_java_reflect(analysis_dict, dat):
    """Analyze data for java-reflection."""
    if (
            re.findall(
                'java.lang.reflect.Method|java.lang.reflect.Field|Class.forName',
                dat
            )
    ):
        analysis_dict['reflect'] = True
    if 'java.lang.reflect.Method' in dat and 'invoke' in dat:
        analysis_dict['code']['refmethod'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    return analysis_dict


def __get_manager(analysis_dict, dat):
    """Analyze data for managers."""
    if 'app.NotificationManager' in dat and 'notify' in dat:
        analysis_dict['code']['notify'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if 'telephony.TelephonyManager' in dat and 'getAllCellInfo' in dat:
        analysis_dict['code']['cellinfo'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if 'telephony.TelephonyManager' in dat and 'getCellLocation' in dat:
        analysis_dict['code']['cellloc'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if 'telephony.TelephonyManager' in dat and 'getSubscriberId' in dat:
        analysis_dict['code']['subid'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if 'telephony.TelephonyManager' in dat and 'getDeviceId' in dat:
        analysis_dict['code']['devid'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if 'telephony.TelephonyManager' in dat and 'getDeviceSoftwareVersion' in dat:
        analysis_dict['code']['softver'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if 'telephony.TelephonyManager' in dat and 'getSimSerialNumber' in dat:
        analysis_dict['code']['simserial'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if 'telephony.TelephonyManager' in dat and 'getSimOperator' in dat:
        analysis_dict['code']['simop'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if 'telephony.TelephonyManager' in dat and 'getSimOperatorName' in dat:
        analysis_dict['code']['opname'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    return analysis_dict


def __get_sqlite(analysis_dict, dat):
    """Analyze data for sqlite."""
    if "SQLiteOpenHelper.getWritableDatabase(" in dat:
        analysis_dict['code']['sqlc_password'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if "SQLiteDatabase.loadLibs(" in dat and "net.sqlcipher." in dat:
        analysis_dict['code']['d_sql_cipher'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if (
            (
                'rawQuery(' in dat or
                'execSQL(' in dat
            ) and 'android.database.sqlite' in dat
    ):
        analysis_dict['code']['d_sqlite'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    return analysis_dict


def __get_connection(analysis_dict, dat):
    """Analyze data for connections."""
    if (
            (
                'HttpURLConnection' in dat or
                'org.apache.http' in dat
            ) and (
                'openConnection' in dat or
                'connect' in dat or
                'HttpRequest' in dat
            )
    ):
        analysis_dict['code']['httpcon'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if (
            (
                'net.URLConnection' in dat
            ) and (
                'connect' in dat or
                'openConnection' in dat or
                'openStream' in dat
            )
    ):
        analysis_dict['code']['urlcon'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if (
            (
                'net.JarURLConnection' in dat
            ) and (
                'JarURLConnection' in dat or
                'jar:' in dat
            )
    ):
        analysis_dict['code']['jurl'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if (
            (
                'javax.net.ssl.HttpsURLConnection' in dat
            ) and (
                'HttpsURLConnection' in dat or
                'connect' in dat
            )
    ):
        analysis_dict['code']['httpsurl'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if (('net.URL') and ('openConnection' or 'openStream')) in dat:
        analysis_dict['code']['nurl'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if (
            re.findall(
                (
                    'http.client.HttpClient|net.http.AndroidHttpClient|'
                    'http.impl.client.AbstractHttpClient'
                ),
                dat
            )
    ):
        analysis_dict['code']['httpclient'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if re.findall('IRemoteService|IRemoteService.Stub|IBinder|Intent', dat):
        analysis_dict['code']['ipc'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if (
            (
                'sendMultipartTextMessage' in dat or
                'sendTextMessage' in dat or
                'vnd.android-dir/mms-sms' in dat
            ) and (
                'telephony.SmsManager' in dat
            )
    ):
        analysis_dict['code']['msg'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )

    return analysis_dict


def __get_webview(analysis_dict, dat):
    """Analyze data for webview."""
    if 'onReceivedSslError(WebView' in dat and '.proceed();' in dat:
        analysis_dict['code']['d_webviewdisablessl'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if (
            'addJavascriptInterface' in dat and
            'WebView' in dat and
            'android.webkit' in dat
    ):
        analysis_dict['code']['webview_addjs'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if 'WebView' in dat and 'loadData' in dat and 'android.webkit' in dat:
        analysis_dict['code']['webviewget'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if 'WebView' in dat and 'postUrl' in dat and 'android.webkit' in dat:
        analysis_dict['code']['webviewpost'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if (
            '.setWebContentsDebuggingEnabled(true)' in dat and
            'WebView' in dat
    ):
        analysis_dict['code']['d_webviewdebug'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )

    return analysis_dict


def __get_dynamic(analysis_dict, dat):
    """Analyze data for dynmaic class loading."""
    if re.findall(r"System.loadLibrary\(|System.load\(", dat):
        analysis_dict['native'] = True
    if (
            re.findall(
                (
                    r'dalvik.system.DexClassLoader|java.security.ClassLoader|'
                    r'java.net.URLClassLoader|java.security.SecureClassLoader'
                ),
                dat
            )
    ):
        analysis_dict['dynamic'] = True

    return analysis_dict


def __get_urls(analysis_dict, dat):
    """Extract urls from data."""
    # Initialize
    urls = []
    j_file = analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
    base_fl = ntpath.basename(j_file)

    #URLs My Custom regex
    pattern = re.compile(
        (
            ur'((?:https?://|s?ftps?://|file://|javascript:|data:|www\d{0,3}[.])'
            ur'[\w().=/;,#:@?&~*+!$%\'{}-]+)'
        ),
        re.UNICODE
    )

    urllist = re.findall(pattern, dat.lower())
    analysis_dict['url_list'].extend(urllist)
    uflag = 0
    for url in urllist:
        if url not in urls:
            urls.append(url)
            uflag = 1
    if uflag == 1:
        analysis_dict['url_n_file'] += (
            "<tr><td>" + "<br>".join(urls) +
            "</td><td><a href='../ViewSource/?file=" + escape(j_file) +
            "&md5=" + analysis_dict['md5'] + "&type=" + analysis_dict['typ'] + "'>" +
            escape(base_fl) + "</a></td></tr>"
        )
    return analysis_dict


def __get_email(analysis_dict, dat):
    """Extract email adresses from data."""
    # Initialize
    emails = []
    j_file = analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
    base_fl = ntpath.basename(j_file)

    # Email Etraction Regex
    regex = re.compile(r'[\w.-]+@[\w-]+\.[\w.]+')
    eflag = 0
    for email in regex.findall(dat.lower()):
        if (email not in emails) and (not email.startswith('//')):
            emails.append(email)
            eflag = 1
    if eflag == 1:
        analysis_dict['email_n_file'] += (
            "<tr><td>" + "<br>".join(emails) +
            "</td><td><a href='../ViewSource/?file=" + escape(j_file) +
            "&md5=" + analysis_dict['md5'] + "&type=" + analysis_dict['typ'] +"'>" +
            escape(base_fl) + "</a></td></tr>"
        )
    return analysis_dict


def _analyze_file(analysis_dict):
    """Analyze a source file."""

    with io.open(
        analysis_dict['jfile_path'],
        mode='r',
        encoding="utf8",
        errors="ignore"
    ) as file_pointer:
        dat = file_pointer.read()

    #Code Analysis
    #print "[INFO] Doing Code Analysis on - " + jfile_path
    #==========================Android Security Code Review ========================

    # Analyze data for storage-conf.
    analysis_dict = __get_storage(analysis_dict, dat)

    if (
            'setJavaScriptEnabled(true)' in dat and
            '.addJavascriptInterface(' in dat
    ):
        analysis_dict['code']['d_jsenabled'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )

    # Analyze data for webview.
    analysis_dict = __get_webview(analysis_dict, dat)

    # Analyze data to detect dexguard
    analysis_dict = __get_dexguard(analysis_dict, dat)

    # Analyze data for ssl-config
    analysis_dict = __get_ssl(analysis_dict, dat)

    if ('PackageManager.GET_SIGNATURES' in dat) and ('getPackageName(' in dat):
        analysis_dict['code']['d_app_tamper'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )

    # Analyze file for signs of rooting
    analysis_dict = __get_root_detection(analysis_dict, dat)

    # Logging
    if re.findall(r'Log\.(v|d|i|w|e|f|s)|System\.out\.print', dat):
        analysis_dict['code']['log'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )

    if "getWindow().setFlags(" in dat and ".FLAG_SECURE" in dat:
        analysis_dict['code']['d_prevent_screenshot'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )

    # Analyze data for sqlite.
    analysis_dict = __get_sqlite(analysis_dict, dat)

    # Analyze file for bad crypto
    analysis_dict = __get_crypto(analysis_dict, dat)

    #Inorder to Add rule to Code Analysis, add identifier to code, add rule here and
    # define identifier description and severity the bottom of this function.
    #=========================Android API Analysis =========================
    #API Check

    # Analyze data for dynmaic class loading.
    analysis_dict = __get_dynamic(analysis_dict, dat)

    # Analyze data for java-reflection.
    analysis_dict = __get_java_reflect(analysis_dict, dat)

    if 'getRuntime().exec(' in dat and 'getRuntime(' in dat:
        analysis_dict['code']['exec'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )

    # Analyze data for sockets.
    analysis_dict = __get_socket(analysis_dict, dat)



    # Analyze data for connections.
    analysis_dict = __get_connection(analysis_dict, dat)

    # Analyze data for managers.
    analysis_dict = __get_manager(analysis_dict, dat)

    if 'content.ContentResolver' in dat and 'query' in dat:
        analysis_dict['code']['contentq'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if 'getSystemService' in dat:
        analysis_dict['code']['gs'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )



    if (
            (
                'android.location' in dat
            )and (
                ('getLastKnownLocation(') in dat or
                'requestLocationUpdates(' in dat or
                ('getLatitude(') in dat or
                'getLongitude(' in dat
            )
    ):
        analysis_dict['code']['gps'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )

    if re.findall(r'startActivity\(|startActivityForResult\(', dat):
        analysis_dict['code']['inf_act'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if re.findall(r'startService\(|bindService\(', dat):
        analysis_dict['code']['inf_ser'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )
    if re.findall(
            r'sendBroadcast\(|sendOrderedBroadcast\(|sendStickyBroadcast\(', dat
    ):
        analysis_dict['code']['inf_bro'].append(
            analysis_dict['jfile_path'].replace(analysis_dict['java_src'], '')
        )

    # Extract urls.
    analysis_dict = __get_urls(analysis_dict, dat)

    # Extract email.
    analysis_dict = __get_email(analysis_dict, dat)

    return analysis_dict


def code_analysis(app_dir, md5, perms, typ):
    """Perform the code analysis."""
    try:
        print "[INFO] Static Android Code Analysis Started"
        # Create dict for easier param passing
        analysis_dict = {
            'crypto' : False,
            'obfus' : False,
            'reflect' : False,
            'dynamic' : False,
            'native' : False,
            'code': _get_code_dict(),
            'app_dir': app_dir,
            'md5': md5,
            'perms': perms,
            'typ': typ,
            'email_n_file': '',
            'url_n_file': '',
            'url_list': list(),
            'domains': dict(),
            'java_src': '',
            'jfile_path': ''
        }

        # Get the correct java_src for typ of app
        analysis_dict = _get_java_src(analysis_dict)

        print "[INFO] Code Analysis Started on - " + analysis_dict['java_src']
        # pylint: disable=unused-variable
        # Needed by os.walk
        for dir_name, _sub_dir, files in os.walk(analysis_dict['java_src']):
            for jfile in files:
                analysis_dict['jfile_path'] = os.path.join(
                    analysis_dict['java_src'], dir_name, jfile
                )
                if "+" in jfile:
                    p_2 = os.path.join(analysis_dict['java_src'], dir_name, jfile.replace("+", "x"))
                    shutil.move(analysis_dict['jfile_path'], p_2)
                    analysis_dict['jfile_path'] = p_2
                repath = dir_name.replace(analysis_dict['java_src'], '')
                if (
                        jfile.endswith('.java') and
                        any(cls in repath for cls in settings.SKIP_CLASSES) is False
                ):
                    # Analyze a file
                    analysis_dict = _analyze_file(
                        analysis_dict
                    )

        # Domain Extraction and Malware Check
        print "[INFO] Performing Malware Check on extracted Domains"
        analysis_dict['domains'] = MalwareCheck(analysis_dict['url_list'])

        print "[INFO] Finished Code Analysis, Email and URL Extraction"

        # Analyze used APIs
        html = _get_api_analysis(analysis_dict)

        # Get the dangers per file
        dang = _get_dangers_per_file(analysis_dict)

        # Construct the return dictionary
        code_an_dic = {
            'api' : html,
            'dang' : dang,
            'urls' : analysis_dict['url_n_file'],
            'domains' : analysis_dict['domains'],
            'emails': analysis_dict['email_n_file'],
            'crypto' : analysis_dict['crypto'],
            'obfus' : analysis_dict['obfus'],
            'reflect' : analysis_dict['reflect'],
            'dynamic' : analysis_dict['dynamic'],
            'native' : analysis_dict['native']
        }

        return code_an_dic
    except:
        PrintException("[ERROR] Performing Code Analysis")
