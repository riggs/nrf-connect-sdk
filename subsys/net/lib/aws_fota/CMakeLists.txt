#
# Copyright (c) 2019 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

zephyr_library()
zephyr_library_sources(
	src/aws_fota.c
	src/aws_fota_json.c
)

add_compile_definitions(MT_APP_VERSION="$ENV{FF_VERSION_MT}")

zephyr_include_directories(./include)
