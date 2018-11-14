@echo off
pushd %~dp0\..
call node-gyp configure build --msvs_version=2015 -debug
popd