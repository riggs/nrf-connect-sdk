/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/kernel.h>
#include <string.h>
#include <cJSON.h>
#include <zephyr/sys/util.h>
#include <net/aws_jobs.h>
#include <zephyr/logging/log.h>

#include "aws_fota_json.h"

LOG_MODULE_REGISTER(aws_fota_json, CONFIG_AWS_FOTA_LOG_LEVEL);

/**@brief Copy max maxlen bytes from src to dst. Insert null-terminator.
 */
static void strncpy_nullterm(char *dst, const char *src, size_t maxlen)
{
	size_t len = strlen(src) + 1;

	memcpy(dst, src, MIN(len, maxlen));
	if (len > maxlen) {
		dst[maxlen - 1] = '\0';
	}
}

int aws_fota_parse_UpdateJobExecution_rsp(const char *update_rsp_document,
					  size_t payload_len, char *status_buf)
{
	if (update_rsp_document == NULL || status_buf == NULL) {
		return -EINVAL;
	}

	int ret;

	cJSON *update_response = cJSON_Parse(update_rsp_document);
	if (update_response == NULL) {
		ret = -ENODATA;
		goto cleanup;
	}

	cJSON *status = cJSON_GetObjectItemCaseSensitive(update_response, "status");
	if (cJSON_IsString(status) && status->valuestring != NULL) {
		strncpy_nullterm(status_buf, status->valuestring,
				 STATUS_MAX_LEN);
	} else {
		ret = -ENODATA;
		goto cleanup;
	}

	ret = 0;
cleanup:
	cJSON_Delete(update_response);
	return ret;
}

int aws_fota_parse_DescribeJobExecution_rsp(const char *job_document,
					   uint32_t payload_len,
					   char *job_id_buf,
					   char *hostname_buf,
					   size_t hostname_buf_size,
					   char *file_path_buf,
					   size_t file_path_buf_size,
					   char *protocol_buf,
					   size_t protocol_buf_size,
					   int *execution_version_number,
					   bool* mark_job_as_complete,
						 bool* mark_job_as_failed)
{
	if (job_document == NULL
	    || job_id_buf == NULL
	    || hostname_buf == NULL
	    || file_path_buf == NULL
	    || protocol_buf == NULL
	    || execution_version_number == NULL
			|| mark_job_as_complete == NULL
		|| mark_job_as_failed == NULL) {
		return AWS_FOTA_JSON_RES_INVALID_PARAMS;
	}

	int ret;

	cJSON *json_data = cJSON_Parse(job_document);

	if (json_data == NULL) {
		ret = AWS_FOTA_JSON_RES_INVALID_JOB;
		goto cleanup;
	}

	cJSON *execution = cJSON_GetObjectItemCaseSensitive(json_data, "execution");

	if (execution == NULL) {
		ret = AWS_FOTA_JSON_RES_SKIPPED;
		goto cleanup;
	}

	cJSON *version_number = cJSON_GetObjectItemCaseSensitive(execution, "versionNumber");

	if (cJSON_IsNumber(version_number)) {
		*execution_version_number = version_number->valueint;
	} else {
		ret = AWS_FOTA_JSON_RES_INVALID_JOB;
		goto cleanup;
	}

	cJSON *job_id = cJSON_GetObjectItemCaseSensitive(execution, "jobId");

	if (cJSON_GetStringValue(job_id) != NULL)
	{
		strncpy_nullterm(job_id_buf, job_id->valuestring, AWS_JOBS_JOB_ID_MAX_LEN);
	}
	else
	{
		ret = AWS_FOTA_JSON_RES_INVALID_JOB;
		goto cleanup;
	}

	if (strncmp(job_id_buf, "bulk-reboot", strlen("bulk-reboot")) == 0)
	{
		// NOTE: FOTA jobs have a random job ID, reboot jobs always have an id of "bulk-reboot"
		// If the job id is "bulk-reboot", skip the rest of the FOTA-specific checks and return
		LOG_INF("Received a bulk-reboot job");
		ret = AWS_FOTA_JSON_RES_IS_BULK_REBOOT;
		goto cleanup;
	}

	cJSON *job_data = cJSON_GetObjectItemCaseSensitive(execution, "jobDocument");

	if (!cJSON_IsObject(job_data)) {
		ret = AWS_FOTA_JSON_RES_INVALID_DOCUMENT;
		goto cleanup;
	}

	cJSON *payload = cJSON_GetObjectItemCaseSensitive(job_data, "payload");
	if (!cJSON_IsObject(payload))
	{
		LOG_ERR("Payload is missing from job doc");
		ret = -ENODATA;
		goto cleanup;
	}

	cJSON *model = cJSON_GetObjectItemCaseSensitive(payload, "model");
	if ((cJSON_GetStringValue(model) == NULL))
	{
		LOG_ERR("Model is missing");
		ret = AWS_FOTA_JSON_RES_INVALID_DOCUMENT;
		goto cleanup;

		if (strncmp(model->valuestring, "AG-31", strlen("AG-31")) != 0)
		{
			LOG_ERR("Model is %s not AG-31!  Can not install delivered firmware.", model->valuestring);
			*mark_job_as_failed = true;
		}
	}

	cJSON *target_sw_version = cJSON_GetObjectItemCaseSensitive(payload, "target_sw_version");
	if (cJSON_IsNumber(target_sw_version) == cJSON_True)
	{
		LOG_ERR("Target sw version is missing");
		ret = AWS_FOTA_JSON_RES_INVALID_DOCUMENT;
		goto cleanup;
	}

	cJSON *min_sw_version = cJSON_GetObjectItemCaseSensitive(payload, "min_sw_version");
	if (cJSON_IsNumber(min_sw_version) == cJSON_True)
	{
		LOG_ERR("Min sw version is missing");
		ret = -ENODATA;
		goto cleanup;
	}

	LOG_DBG("Min version %d Target version %d", min_sw_version->valueint, target_sw_version->valueint);
	int current_sw_version = atoi(MT_APP_VERSION);

	if (current_sw_version >= target_sw_version->valueint)
	{
		LOG_ERR("Current firmware %d >= Target sw version %d", current_sw_version, target_sw_version->valueint);
		*mark_job_as_complete = true;
	}
	if (min_sw_version->valueint > current_sw_version)
	{
		LOG_ERR("Invalid min version.  Can not install delivered firmware.");
		*mark_job_as_failed = true;
	}

	/* firmware_url is hostname + complete path i.e fw_path, credentials,
	 * signatures, expiry etc. Whereas fw_path just has the path without the
	 * credentials, signatures etc. So extract the complete path from
	 * firmware_url. The SDK assumes there is a separate hostname and path
	 * and so this patch works around it. */

	cJSON *firmware_url = cJSON_GetObjectItemCaseSensitive(payload, "firmware_url");
	if ((cJSON_GetStringValue(firmware_url) == NULL))
	{
		LOG_ERR("Firmware Url is missing");
		ret = AWS_FOTA_JSON_RES_INVALID_DOCUMENT;
		goto cleanup;
	}

	// LOG_DBG("Got firmware url %s [%d]", firmware_url->valuestring, strlen(firmware_url->valuestring));

	char *path = strstr(firmware_url->valuestring, "/uploads");
	if (path == NULL)
	{
		LOG_ERR("path was NULL");
		ret = AWS_FOTA_JSON_RES_INVALID_DOCUMENT;
	}
	else
	{
		// Remove the / the download client will add onto the path
		strncpy_nullterm(file_path_buf, path+1, CONFIG_AWS_FOTA_FILE_PATH_MAX_LEN);

		/* Remove the complete path from firmware_url to just retain the firmware_url
		 * by terminating the string with null character. */
		// LOG_DBG("firmware_url len %d, path len %d", strlen(firmware_url->valuestring), strlen(path));
		firmware_url->valuestring[strlen(firmware_url->valuestring) - strlen(path)] = '\0';
		strncpy_nullterm(hostname_buf, firmware_url->valuestring, CONFIG_AWS_FOTA_HOSTNAME_MAX_LEN);

		LOG_DBG("firmware_url %s [%d]", hostname_buf, strlen(hostname_buf));
		LOG_DBG("path %s [%d]", file_path_buf, strlen(file_path_buf));

		// Clear the buffer.
		memset(protocol_buf, 0, protocol_buf_size);

		// Get the protocol from the url prefix.
		char* url_ptr = firmware_url->valuestring;
		for (int i = 0; i < protocol_buf_size; i++)
		{
			if (*(url_ptr + i) == ':')
			{
				break;
			}

			*(protocol_buf + i) = *(url_ptr + i);
		}
	}

	ret = AWS_FOTA_JSON_RES_SUCCESS;
cleanup:
	cJSON_Delete(json_data);
	return ret;
}


int aws_fota_parse_update_rejected(const char *json_data, uint32_t payload_len, int *version_number)
{
	if (json_data == NULL || version_number == NULL) {
		return -EINVAL;
	}

	int ret;

	cJSON *error_response_json = cJSON_Parse(json_data);

	if (error_response_json == NULL) {
		LOG_ERR("Parse error failed!");
		ret = -ENODATA;
		goto cleanup;
	}

	cJSON *execution_state = cJSON_GetObjectItemCaseSensitive(error_response_json, "executionState");
	if (execution_state == NULL)
	{
		ret = -ENODATA;
		goto cleanup;
	}

	cJSON *version_number_json = cJSON_GetObjectItemCaseSensitive(execution_state, "versionNumber");

	if (cJSON_IsNumber(version_number_json))
	{
		*version_number = version_number_json->valueint;
	}
	else
	{
		LOG_ERR("Version Number Missing");
		ret = -ENODATA;
		goto cleanup;
	}

	ret = 0;
	cleanup:
	cJSON_Delete(error_response_json);
	return ret;
}
