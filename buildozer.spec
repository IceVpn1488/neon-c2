[app]
title = Neon C2
package.name = neonc2
package.domain = com.icevpn

source.dir = .
source.include_exts = py,png,jpg,kv,atlas

version = 1.0.0

requirements = python3,kivy==2.3.0,aiohttp,openssl,multidict,yarl,attrs,aiosignal,frozenlist,idna,async_timeout,charset_normalizer,chardet

orientation = portrait
fullscreen = 0

# Android specific
android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE
android.api = 33
android.minapi = 21
android.ndk = 25b
android.sdk = 33
android.archs = arm64-v8a
android.allow_backup = True
android.accept_sdk_license = True
android.logcat_filters = *:S python:D

# splash
presplash.filename = %(source.dir)s/presplash.png
icon.filename = %(source.dir)s/icon.png

[buildozer]
log_level = 2
warn_on_root = 1
