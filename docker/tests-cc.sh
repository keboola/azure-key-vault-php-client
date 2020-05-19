#!/usr/bin/env bash
set -e

cd /code/
curl -L https://codeclimate.com/downloads/test-reporter/test-reporter-latest-linux-amd64 > ./cc-test-reporter
chmod +x ./cc-test-reporter
./cc-test-reporter before-build

composer ci

./cc-test-reporter after-build
