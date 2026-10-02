[app]
title = Neon C2
package.name = neonc2
package.domain = com.icevpn

source.dir = .
source.include_exts = py,png,jpg,kv,atlas

version = 1.0.0

requirements = python3==3.11.5,kivy==2.3.0,aiohttp==3.9.5,openssl

orientation = portrait
fullscreen = 0

android.permissions = INTERNET,ACCESS_NETWORK_STATE
android.api = 31
android.minapi = 21
android.ndk = 25b
android.sdk = 31
android.archs = arm64-v8a
android.allow_backup = True
android.accept_sdk_license = True
android.logcat_filters = *:S python:D

p4a.python_version = 3.11.5
p4a.branch = master

[buildozer]
log_level = 2
warn_on_root = 1
