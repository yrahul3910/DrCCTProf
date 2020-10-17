#! /bin/bash

# **********************************************************
# Copyright (c) 2020 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

CUR_DIR=$(cd "$(dirname "$0")";pwd)
rm -rf logs/*

$CUR_DIR/test_apps/build.sh
$CUR_DIR/scripts/build_tool/env_init.sh
$CUR_DIR/scripts/build_tool/make.sh

