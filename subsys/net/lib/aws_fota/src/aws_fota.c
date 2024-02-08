/*
 * Copyright (c) 2019-2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/*
 * To update this patch navigate to kt/src/embedded/ff/extern/ncs/nrf/ and then run the command:
 * git diff subsys/net/lib/aws_fota/src/aws_fota.c > ../../../extern_patches/patches_aws_fota/aws_fota_c.patch
 * Commit the updated version of aws_fota_c.patch to ktmr.
 */

#include <zephyr/kernel.h>
#include <stdio.h>
#include <zephyr/data/json.h>
#include <net/fota_download.h>
#include <net/aws_jobs.h>
#include <net/aws_fota.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/reboot.h>
#include <hal/nrf_power.h>
#include <drivers/eeprom.h>

#include "aws_fota_json.h"

LOG_MODULE_REGISTER(aws_fota, CONFIG_AWS_FOTA_LOG_LEVEL);

#define AWS_JOB_ID_DEFAULT "INVALID-JOB-ID"

// Keep in sync with ff_definitions.h in ff project
#define EEPROM_ADDR_REBOOT_REASON (184)

enum reset_reason_extra {
	RESET_REASON_NONE = 0,
	RESET_REASON_IOT = 1,
	RESET_REASON_FOTA = 2
};

static enum internal_state_t internal_state = AWS_FOTA_STATE_UNINIT;

/* Enum used when parsing AWS jobs topics messages are received on. */
enum jobs_topic {
	TOPIC_INVALID,
	TOPIC_GET_NEXT,
	TOPIC_GET_ACCEPTED,
	TOPIC_NOTIFY_NEXT,
	TOPIC_UPDATE_ACCEPTED,
	TOPIC_UPDATE_REJECTED
};

/* Pointer to internal reference of an initialized MQTT client instance. */
static struct mqtt_client *client_internal;

/* Enum used for tracking the job exectuion status. */
static enum execution_status execution_status = AWS_JOBS_QUEUED;

/* Document version is read out from the job execution document and is then
 * incremented with each accepted update to the job execution.
 */
static uint32_t execution_version_number;

/* File download progress in percentage [0-100%]. */
static size_t download_progress;

/* Variable that keeps tracks of the MQTT connection state. */
static bool connected;

/* Allocated strings for topics. */
static uint8_t notify_next_topic[AWS_JOBS_TOPIC_MAX_LEN];
static uint8_t update_topic[AWS_JOBS_TOPIC_MAX_LEN];
static uint8_t get_topic[AWS_JOBS_TOPIC_MAX_LEN];

/* Allocated buffers for keeping hostname, json payload and file_path. */
static uint8_t payload_buf[CONFIG_AWS_FOTA_PAYLOAD_SIZE];
static uint8_t hostname[CONFIG_AWS_FOTA_HOSTNAME_MAX_LEN];
static uint8_t file_path[CONFIG_AWS_FOTA_FILE_PATH_MAX_LEN];

/* Allocated buffer used to keep track the job ID currently being handled by the library. */
static uint8_t job_id_handling[AWS_JOBS_JOB_ID_MAX_LEN] = AWS_JOB_ID_DEFAULT;
static aws_fota_callback_t callback;

/* Convenience functions used in internal state handling. */
static char *state2str(enum internal_state_t state)
{
	switch (state) {
	case AWS_FOTA_STATE_UNINIT:
		return "AWS_FOTA_STATE_UNINIT";
	case AWS_FOTA_STATE_INIT:
		return "AWS_FOTA_STATE_INIT";
	case AWS_FOTA_STATE_DOWNLOADING:
		return "AWS_FOTA_STATE_DOWNLOADING";
	case AWS_FOTA_STATE_DOWNLOAD_COMPLETE:
		return "AWS_FOTA_STATE_DOWNLOAD_COMPLETE";
	case AWS_FOTA_STATE_SUSPENDED:
	  return "AWS_FOTA_STATE_SUSPENDED";
	default:
		return "Unknown";
	}
}

static void internal_state_set(enum internal_state_t new_state)
{
	if (new_state == internal_state) {
		LOG_DBG("State: %s", state2str(internal_state));
		return;
	}

	LOG_DBG("State transition %s --> %s", state2str(internal_state), state2str(new_state));

	internal_state = new_state;
}

static void reset_library(void)
{
	internal_state_set(AWS_FOTA_STATE_INIT);
	execution_status = AWS_JOBS_QUEUED;
	download_progress = 0;
	strncpy(job_id_handling, AWS_JOB_ID_DEFAULT, sizeof(job_id_handling));
	job_id_handling[sizeof(job_id_handling) - 1] = '\0';
	LOG_DBG("Library reset");
}

/* Function that returns AWS jobs specific topic enums depending on the incoming topic. */
static enum jobs_topic topic_type_get(const char *incoming_topic, size_t topic_len)
{
#if defined(CONFIG_AWS_FOTA_LOG_LEVEL_DBG)
	char debug_log[topic_len + 1];

	memcpy(debug_log, incoming_topic, topic_len);
	debug_log[topic_len] = '\0';
	LOG_DBG("Received topic %s", debug_log);
#endif

	if (aws_jobs_cmp(get_topic, incoming_topic, topic_len, "")) {
		return TOPIC_GET_NEXT;
	} else if (aws_jobs_cmp(get_topic, incoming_topic, topic_len, "accepted")) {
		return TOPIC_GET_ACCEPTED;
	} else if (aws_jobs_cmp(notify_next_topic, incoming_topic, topic_len, "")) {
		return TOPIC_NOTIFY_NEXT;
	} else if (aws_jobs_cmp(update_topic, incoming_topic, topic_len, "accepted")) {
		return TOPIC_UPDATE_ACCEPTED;
	} else if (aws_jobs_cmp(update_topic, incoming_topic, topic_len, "rejected")) {
		return TOPIC_UPDATE_REJECTED;
	}

	return TOPIC_INVALID;
}

/**
 * @brief Read the payload out of the published MQTT message from the MQTT
 *	  Client instance
 *
 * @param[in] client  Connected MQTT client instance.
 * @param[out] write_buf  Buffer where the MQTT publish message's payload is
 *			  stored.
 * @param[in] length  Length of the payload received.
 *
 * @return 0 If successful otherwise a negative error code is returned.
 */
static int get_published_payload(struct mqtt_client *client, uint8_t *write_buf,
				 size_t length)
{
	uint8_t *buf = write_buf;
	uint8_t *end = buf + length;

	if (length > sizeof(payload_buf)) {
		return -EMSGSIZE;
	}
	while (buf < end) {
		int ret = mqtt_read_publish_payload_blocking(client, buf,
							     end - buf);

		if (ret < 0) {
			return ret;
		} else if (ret == 0) {
			return -EIO;
		}
		buf += ret;
	}
	return 0;
}

/**
 * @brief Update an AWS IoT Job Execution with a state and status details
 *
 * @param[in] client  Connected MQTT client instance.
 * @param[in] job_id  Pointer to Unique Identifier of the devices Job Execution.
 * @param[in] job_id_len Length of the passed in job ID.
 * @param[in] status  The status to update the Job Execution with.
 * @param[in] client_token  Client identifier which will be repeated in the
 *			    respone of the update.
 *
 * @return 0 If successful otherwise a negative error code is returned.
 */
static int update_job_execution(struct mqtt_client *const client,
				const uint8_t *job_id,
				size_t job_id_len,
				enum execution_status status,
				const char *client_token)
{
	int err;

	/* Check if the library has obtained a job ID. */
	if (strncmp(job_id, AWS_JOB_ID_DEFAULT, job_id_len) == 0) {
		return -ECANCELED;
	}

	LOG_DBG("%s, status: %d, version_number: %d", __func__,
		status, execution_version_number);

	err = aws_jobs_update_job_execution(client, job_id, status,
					    NULL,
					    execution_version_number,
					    client_token, update_topic);

	if (err < 0) {
		LOG_ERR("aws_jobs_update_job_execution failed: %d", err);
		return err;
	}

	execution_status = status;

	return 0;
}

/**
 * @brief Parsing an AWS IoT Job Execution response received on $next/get MQTT
 *	  topic or notify-next. If it is a valid response the program state is
 *	  updated and the MQTT client instance is subscribed to the update
 *	  topics for the job id received.
 *
 * @param[in] client  Connected MQTT client instance
 * @param[in] payload_len  Length of the payload going to be read out from the
 *			   MQTT message.
 *
 * @return 0 If successful otherwise a negative error code is returned.
 */
static int get_job_execution(struct mqtt_client *const client,
			     uint32_t payload_len)
{
	int err;
	bool mark_job_as_complete = false;
	bool mark_job_as_failed = false;
	int execution_version_number_prev = execution_version_number;
	uint8_t job_id_incoming[AWS_JOBS_JOB_ID_MAX_LEN];

	err = get_published_payload(client, payload_buf, payload_len);
	if (err) {
		LOG_ERR("Error when getting the payload: %d", err);
		return err;
	}

#if IS_ENABLED(CONFIG_AWS_FOTA_LOG_LEVEL_DBG)
	if (payload_len > 120) {
		/* '?' is the URL parameter marker */
		uint8_t *q = strchr(payload_buf, '?');
		size_t len = MIN(120, q - payload_buf + 1);
		uint8_t truncated[len + 4];
		memcpy(truncated, payload_buf, len);
		memcpy(&truncated[len], "...\0", 4);
		LOG_DBG("Job doc: %s", truncated);
	} else {
		char job_doc[payload_len + 1];
		memcpy(job_doc, payload_buf, payload_len);
		job_doc[payload_len] = '\0';
		LOG_DBG("Job doc: %s", job_doc);
	}
#endif

	/* Check if message received is a job. */
	err = aws_fota_parse_DescribeJobExecution_rsp(payload_buf, payload_len,
						      job_id_incoming, hostname,
						      file_path,
						      &execution_version_number,
							  &mark_job_as_complete,
							  &mark_job_as_failed);

	if (err < 0) {
		LOG_ERR("Error when parsing the json: %d", err);
		goto cleanup;
	} else if (err == 0) {
		LOG_DBG("Got only one field");
		LOG_DBG("No queued jobs for this device");
		return 0;
	} else if (err == 1) {
		LOG_DBG("Job parsed, continue...");
	}

	/* Check if the incoming job is already being handled. */
	if (strncmp(job_id_incoming, job_id_handling, sizeof(job_id_incoming)) == 0) {
		LOG_WRN("Job already being handled, ignore message");
		err = 0;
		goto cleanup;
	} else {
		strncpy(job_id_handling, job_id_incoming, sizeof(job_id_handling));
		job_id_handling[sizeof(job_id_handling) - 1] = '\0';
	}

#if IS_ENABLED(CONFIG_AWS_FOTA_LOG_LEVEL_DBG)
	LOG_DBG("Job ID: %s", (char *)job_id_handling);
	LOG_DBG("hostname: %s", (char *)hostname);
	if (strlen(file_path) > 80) {
		/* '?' is the URL parameter marker */
		uint8_t *q = strchr(file_path, '?');
		size_t len = MIN(80, q - file_path + 1);
		uint8_t truncated[len + 4];
		memcpy(truncated, file_path, len);
		memcpy(&truncated[len], "...\0", 4);
		LOG_DBG("file_path: %s", truncated);
	} else {
		LOG_DBG("file_path: %s", file_path);
	}
	LOG_DBG("Execution Versions. Prev: %d - Current: %d", execution_version_number_prev, execution_version_number);
#endif

	/* Subscribe to update topic to receive feedback on whether an
	 * update is accepted or not.
	 */
	err = aws_jobs_subscribe_topic_update(client, job_id_handling, update_topic);
	if (err) {
		LOG_ERR("Error when subscribing job_id_update: %d", err);
		goto cleanup;
	}

	LOG_DBG("Subscribed to FOTA update topic %s", (char *)update_topic);

	enum execution_status exe_status;

	if (mark_job_as_complete)
	{
		LOG_ERR("Marking Job as Complete jobid %s", job_id_handling);
		exe_status = AWS_JOBS_SUCCEEDED;
	}

	if (mark_job_as_failed)
	{
		LOG_ERR("Marking Job as Failed jobid %s", job_id_handling);
		exe_status = AWS_JOBS_FAILED;
	}

	if (mark_job_as_complete || mark_job_as_failed)
	{
		err = update_job_execution(client_internal, job_id_handling, sizeof(job_id_handling), exe_status, "");

		if (err < 0)
			goto cleanup;

		// Stop the execution of this job so we don't download the firmware
		struct aws_fota_event aws_fota_evt = { .id = AWS_FOTA_EVT_ERROR	};
		callback(&aws_fota_evt);
		reset_library();
	}

	return 0;

cleanup:
	execution_version_number = execution_version_number_prev;
	return err;
}

/**
 * @brief Updating the program state when a job document update is accepted.
 *
 * @param[in] client  Connected MQTT client instance
 * @param[in] payload_len  Length of the payload going to be read out from the
 *			   MQTT message.
 *
 * @return 0 If successful otherwise a negative error code is returned.
 */
static int job_update_accepted(struct mqtt_client *const client,
			       uint32_t payload_len)
{
	int err;
	int sec_tag = -1;

	err = get_published_payload(client, payload_buf, payload_len);
	if (err) {
		LOG_ERR("Error when getting the payload: %d", err);
		return err;
	}

	/* Update accepted, so the execution version number needs to be
	 * incremented. This can also be parsed out from the response but it's
	 * better if the device handles this state so we need to send less data.
	 * Also it means that the device is the driver of updates to this
	 * document.
	 */
	execution_version_number++;
	LOG_DBG("Execution version number icremented to: %d", execution_version_number);


	LOG_DBG("execution_status: %d", execution_status);
	switch (execution_status) {
	case AWS_JOBS_IN_PROGRESS: {
		struct aws_fota_event aws_fota_evt = {
			.id = AWS_FOTA_EVT_START
		};

		if (strncmp(job_id_handling, "bulk-reboot", strlen("bulk-reboot")) == 0)
		{
			// If the job id is "bulk-reboot", update the status to complete and return
			internal_state_set(AWS_FOTA_STATE_DOWNLOAD_COMPLETE);

			return update_job_execution(client,
										job_id_handling,
										sizeof(job_id_handling),
										AWS_JOBS_SUCCEEDED, "");
		}

#if IS_ENABLED(CONFIG_AWS_FOTA_LOG_LEVEL_DBG)
		if (strlen(file_path) > 80) {
			/* '?' is the URL parameter marker */
			uint8_t *q = strchr(file_path, '?');
			size_t len = MIN(80, q - file_path + 1);
			uint8_t truncated[len + 4];
			memcpy(truncated, file_path, len);
			memcpy(&truncated[len], "...\0", 4);
			LOG_DBG("Start downloading firmware from %s/%s", (char *)hostname, truncated);
		} else {
			LOG_DBG("Start downloading firmware from %s/%s", (char *)hostname, file_path);
		}
#endif

#if defined(CONFIG_AWS_FOTA_DOWNLOAD_SECURITY_TAG)
		sec_tag = CONFIG_AWS_FOTA_DOWNLOAD_SECURITY_TAG;
#endif

		err = fota_download_start(hostname, file_path, sec_tag, 0, 0);
		if (err) {
			LOG_ERR("Error (%d) when trying to start firmware download", err);
			aws_fota_evt.id = AWS_FOTA_EVT_ERROR;
			callback(&aws_fota_evt);
			return update_job_execution(client,
						    job_id_handling,
						    sizeof(job_id_handling),
						    AWS_JOBS_FAILED, "");
		}

		internal_state_set(AWS_FOTA_STATE_DOWNLOADING);
		callback(&aws_fota_evt);
		LOG_DBG("Job document was updated with status IN_PROGRESS");
	}
		break;
	case AWS_JOBS_SUCCEEDED: {
		struct aws_fota_event aws_fota_evt = {
			.id = AWS_FOTA_EVT_DONE
		};

		if (strncmp(job_id_handling, "bulk-reboot", strlen("bulk-reboot")) == 0)
		{
			// Once the bulk-reboot job was marked as succeeded on AWS, reboot the system
			int eeprom_val = RESET_REASON_IOT;

			const struct device *eeprom_dev = device_get_binding("EEPROM_0");

			if (eeprom_dev == NULL)
			{
				LOG_ERR("Could not get EEPROM device\n");
			}
			else
			{
				if (eeprom_write(eeprom_dev, EEPROM_ADDR_REBOOT_REASON, &eeprom_val, sizeof(eeprom_val)) != 0)
				{
					LOG_ERR("Failed to write reboot reason to EEPROM");
				}
			}

			LOG_INF("System is rebooting!");
			sys_reboot(SYS_REBOOT_COLD);

			break;
		}

		LOG_DBG("Job document was updated with status SUCCEEDED");

		const struct device *eeprom_dev = device_get_binding("EEPROM_0");

		// Write to eeprom so we know why we rebooted
		if (eeprom_dev == NULL)
		{
			LOG_ERR("Could not get EEPROM device\n");
		}
		else
		{
			int eeprom_val = RESET_REASON_FOTA;
			if (eeprom_write(eeprom_dev, EEPROM_ADDR_REBOOT_REASON, &eeprom_val, sizeof(eeprom_val)) != 0)
			{
				LOG_ERR("Failed to write reboot reason to EEPROM");
			}
			else
			{
				LOG_INF("Write eeprom reset reason FOTA");
			}
		}

		callback(&aws_fota_evt);

		/* Job is compeleted, reset library. */
		reset_library();
	}
		break;
	default:
		LOG_ERR("Invalid execution status");
		return -EINVAL;
	}

	return 0;
}

/**
 * @brief Handling of a job document update when it is rejected.
 *
 * @param[in] client  Connected MQTT client instance
 * @param[in] payload_len  Length of the payload going to be read out from the
 *			   MQTT message.
 *
 * @return A negative error code is returned.
 */
static int job_update_rejected(struct mqtt_client *const client,
			       uint32_t payload_len)
{
	struct aws_fota_event aws_fota_evt = { .id = AWS_FOTA_EVT_ERROR };
	LOG_ERR("Job document update was rejected");
	execution_version_number--;
	LOG_DBG("Execution version number decremented to: %d", execution_version_number);
	int err = get_published_payload(client, payload_buf, payload_len);

	if (err) {
		LOG_ERR("Error %d when getting the payload", err);
		return err;
	}
	LOG_DBG("Payload:");
	LOG_HEXDUMP_ERR(payload_buf, payload_len, "");

	// If error was "VersionMismatch" then sychnronize to expectation now!
	int version_in_response = 0;
	if (aws_fota_parse_update_rejected(payload_buf, payload_len, &version_in_response) >= 0)
	{
		if (version_in_response != execution_version_number)
		{
			LOG_ERR("VersionNumber was out of synch, expected: %d, had: %d", version_in_response, (execution_version_number+1));
			LOG_INF("Setting Execution version number to: %d", version_in_response);
			execution_version_number = version_in_response;

			callback(&aws_fota_evt);
			reset_library();
			(void)aws_jobs_get_job_execution(client_internal, "$next", get_topic);
		}
	}
	else
	{
			callback(&aws_fota_evt);
	}
	return -EFAULT;
}

/**
 * @brief Check if topic contains job ID string.
 *
 * @param[in] topic Pointer to a string with topic to be checked.
 * @param[in] topic_len Length of the topic.
 * @param[in] job_id Pointer to a NULL terminated string that contains a job ID.
 *
 * @return True if job ID is present in the topic string. Otherwise false is returned.
 */
static int is_job_id_in_topic(const char *topic, size_t topic_len, const char *job_id)
{
	/* strstr() depends on job_id being null terminated and smaller than topic. */
	if (topic_len < strlen(job_id)) {
		LOG_WRN("Job ID cannot be larger than incoming topic");
		return false;
	}

	if (strstr(topic, job_id) == NULL) {
		return false;
	}

	return true;
}

/**
 * @brief Handling of a MQTT publish event. It checks whether the topic matches
 *	  any of the expected AWS IoT Jobs topics used for FOTA.
 *
 * @param[in] client  Connected MQTT client instance.
 * @param[in] topic  String containing the received topic.
 * @param[in] topic_len  Length of the topic string.
 * @param[in] payload_len  Length of the received payload.
 *
 * @return 1 If the topic is not a topic used for AWS IoT Jobs. 0 If the content
 *	     in the topic was successfully handled. Otherwise a negative error
 *	     code is returned.
 */
static int on_publish_evt(struct mqtt_client *const client,
				   const uint8_t *topic,
				   uint32_t topic_len,
				   uint32_t payload_len)
{
	int err;
	enum jobs_topic type = topic_type_get(topic, topic_len);

	switch (type) {
	case TOPIC_GET_NEXT:
	case TOPIC_GET_ACCEPTED:
	case TOPIC_NOTIFY_NEXT:
		if (internal_state != AWS_FOTA_STATE_INIT) {
			goto read_payload;
		}

		LOG_DBG("Checking for an available job");
		return get_job_execution(client, payload_len);
	case TOPIC_UPDATE_ACCEPTED:
		if (internal_state != AWS_FOTA_STATE_INIT &&
		    internal_state != AWS_FOTA_STATE_DOWNLOAD_COMPLETE) {
			goto read_payload;
		}

		if (!is_job_id_in_topic(topic, topic_len, job_id_handling)) {
			LOG_WRN("The currently handled job ID is not in incoming accepted topic");
			goto read_payload;
		}

		return job_update_accepted(client, payload_len);
	case TOPIC_UPDATE_REJECTED:
		if (internal_state != AWS_FOTA_STATE_INIT &&
		    internal_state != AWS_FOTA_STATE_DOWNLOAD_COMPLETE) {
			goto read_payload;
		}

		if (!is_job_id_in_topic(topic, topic_len, job_id_handling)) {
			LOG_WRN("The currently handled job ID is not in incoming rejected topic");
			goto read_payload;
		}

		return job_update_rejected(client, payload_len);
	default:
		/* The incoming topic is not related to AWS FOTA. */
		return 1;
	}

read_payload:

	/* If we get here, a job is already being handled. The incoming
	 * message is most likely a duplicate and must be dropped
	 * to not interfere with the job being processed.
	 * The payload must still be read out in order to clear the
	 * MQTT buffer for next incoming message.
	 */
	err = get_published_payload(client, payload_buf, payload_len);
	if (err) {
		LOG_ERR("Error when getting the payload: %d", err);
		return err;
	}

	LOG_DBG("FOTA already in progress, message is ignored");
	return 0;
}

static int on_connack_evt(struct mqtt_client *const client)
{
	int err;

	switch (internal_state) {
	case AWS_FOTA_STATE_INIT:
		err = aws_jobs_subscribe_topic_notify_next(client, notify_next_topic);
		if (err) {
			LOG_ERR("Unable to subscribe to notify-next topic");
			return err;
		}

		err = aws_jobs_subscribe_topic_get(client, "$next", get_topic);
		if (err) {
			LOG_ERR("Unable to subscribe to jobs/$next/get");
			return err;
		}
		break;
	case AWS_FOTA_STATE_DOWNLOADING:
		/* Fall through */
	case AWS_FOTA_STATE_DOWNLOAD_COMPLETE:
		if (strncmp(job_id_handling, AWS_JOB_ID_DEFAULT, sizeof(job_id_handling)) == 0) {
			return -ECANCELED;
		}

		err = aws_jobs_subscribe_topic_update(client, job_id_handling, update_topic);
		if (err) {
			LOG_ERR("Error when subscribing job_id_update: %d", err);
			return err;
		}

		LOG_DBG("Subscribed to FOTA update topic %s", (char *)update_topic);
		break;
	case AWS_FOTA_STATE_SUSPENDED:
		// Trigger a resume download...
		internal_state_set(AWS_FOTA_STATE_DOWNLOADING);
		if (fota_download_resume() < 0)
		{
			struct aws_fota_event aws_fota_evt;
			LOG_ERR("FOTA RESUME FAILED");
			aws_fota_evt.id = AWS_FOTA_EVT_ERROR;
			callback(&aws_fota_evt);
			return update_job_execution(client,
								job_id_handling,
								sizeof(job_id_handling),
								AWS_JOBS_FAILED, "");
			reset_library();
			callback(&aws_fota_evt);
		}
		break;
	default:
		break;
	}

	return 0;
}

static int on_suback_evt(struct mqtt_client *const client, uint16_t message_id)
{
	int err;

	switch (message_id) {
	case SUBSCRIBE_NOTIFY_NEXT:
		LOG_DBG("Subscribed to notify-next topic");

		err = aws_jobs_get_job_execution(client, "$next", get_topic);
		if (err) {
			LOG_ERR("aws_jobs_get_job_execution failed, error: %d", err);
			return err;
		}

		break;
	case SUBSCRIBE_GET:
		LOG_DBG("Subscribed to get topic");
		break;
	case SUBSCRIBE_JOB_ID_GET:
		LOG_DBG("Subscribed to get next-topic");
		break;
	case SUBSCRIBE_JOB_ID_UPDATE:
		LOG_DBG("Subscribed to job ID update accepted/rejected topics");

		enum execution_status status;

		switch (internal_state) {
		case AWS_FOTA_STATE_INIT:
			status = AWS_JOBS_IN_PROGRESS;
			break;
		case AWS_FOTA_STATE_DOWNLOAD_COMPLETE:
			status = AWS_JOBS_SUCCEEDED;
			break;
		case AWS_FOTA_STATE_DOWNLOADING:
			return 0;
		case AWS_FOTA_STATE_SUSPENDED:
			return 0;
		default:
			LOG_WRN("Invalid state");
			return -ECANCELED;
		}

		err = update_job_execution(client,
					   job_id_handling,
					   sizeof(job_id_handling),
					   status,
					   "");
		if (err) {
			LOG_ERR("update_job_execution failed, error: %d", err);
			return err;
		}

		break;
	default:
		/* Message ID not related to AWS FOTA. */
		break;
	} /* end switch(message_id) */

	return 0;
}

int aws_fota_mqtt_evt_handler(struct mqtt_client *const client,
			      const struct mqtt_evt *evt)
{
	int err;

	if (internal_state == AWS_FOTA_STATE_UNINIT) {
		LOG_WRN("AWS FOTA library not initialized");
		return -ENOENT;
	}

	switch (evt->type) {
	case MQTT_EVT_CONNACK:
		if (evt->result != 0) {
			/* Expect more processing of CONNACK event by another
			 * MQTT Event Handler
			 */
			return 1;
		}

		connected = true;

		err = on_connack_evt(client);
		if (err) {
			LOG_WRN("on_connack_evt failed, error: %d", err);
			goto cleanup;
		}

		/* This expects that the application's mqtt handler will handle
		 * any situations where you could not connect to the MQTT
		 * broker.
		 */
		return 1;

	case MQTT_EVT_DISCONNECT:
		connected = false;
		return 1;

	case MQTT_EVT_PUBLISH: {
		const struct mqtt_publish_param *p = &evt->param.publish;

		err = on_publish_evt(client,
				     p->message.topic.topic.utf8,
				     p->message.topic.topic.size,
				     p->message.payload.len);

		if (err < 0) {
			goto cleanup;
		} else if (err == 1) {
			return err;
		}

		if (p->message.topic.qos == MQTT_QOS_1_AT_LEAST_ONCE) {
			const struct mqtt_puback_param ack = {
				.message_id = p->message_id
			};

			/* Send acknowledgment. */
			err = mqtt_publish_qos1_ack(client_internal, &ack);
			if (err) {
				goto cleanup;
			}
		}

		return 0;

	} break;

	case MQTT_EVT_PUBACK:
		if (evt->result != 0) {
			LOG_ERR("MQTT PUBACK error %d", evt->result);
			return 0;
		}

		return 1;

	case MQTT_EVT_SUBACK:
		if (evt->result != 0) {
			return evt->result;
		}

		err = on_suback_evt(client, evt->param.suback.message_id);
		if (err) {
			LOG_WRN("on_suback_evt, error: %d", err);
			goto cleanup;
		}

		return 1;

	default:
		/* Handling for default case */
		return 1;
	}

cleanup:
	reset_library();
	return err;
}

static void http_fota_handler(const struct fota_download_evt *evt)
{
	__ASSERT_NO_MSG(client_internal != NULL);

	int err = 0;
	struct aws_fota_event aws_fota_evt;

	switch (evt->id) {
	case FOTA_DOWNLOAD_EVT_FINISHED:
		LOG_DBG("FOTA_DOWNLOAD_EVT_FINISHED");

		/* Always send download complete progress */
		aws_fota_evt.id = AWS_FOTA_EVT_DL_PROGRESS;
		aws_fota_evt.dl.progress = AWS_FOTA_EVT_DL_COMPLETE_VAL;
		callback(&aws_fota_evt);

		err = update_job_execution(client_internal,
					   job_id_handling,
					   sizeof(job_id_handling),
					   AWS_JOBS_SUCCEEDED,
					   "");
		if (err != 0 && connected) {
			aws_fota_evt.id = AWS_FOTA_EVT_ERROR;
			callback(&aws_fota_evt);
			reset_library();
			return;
		}

		internal_state_set(AWS_FOTA_STATE_DOWNLOAD_COMPLETE);
		break;

	case FOTA_DOWNLOAD_EVT_ERASE_PENDING:
		LOG_DBG("FOTA_DOWNLOAD_EVT_ERASE_PENDING");
		aws_fota_evt.id = AWS_FOTA_EVT_ERASE_PENDING;
		callback(&aws_fota_evt);
		break;

	case FOTA_DOWNLOAD_EVT_ERASE_DONE:
		LOG_DBG("FOTA_DOWNLOAD_EVT_ERASE_DONE");
		aws_fota_evt.id = AWS_FOTA_EVT_ERASE_DONE;
		callback(&aws_fota_evt);
		break;

	case FOTA_DOWNLOAD_EVT_ERROR:
		LOG_ERR("FOTA_DOWNLOAD_EVT_ERROR");
		(void)update_job_execution(client_internal,
					   job_id_handling,
					   sizeof(job_id_handling),
					   AWS_JOBS_FAILED,
					   "");

		aws_fota_evt.id = AWS_FOTA_EVT_ERROR;

		callback(&aws_fota_evt);
		reset_library();

		/* If the FOTA download fails it might be due to the image being deleted.
		 * Try to get the next job if any exist.
		 */
		(void)aws_jobs_get_job_execution(client_internal, "$next", get_topic);
		break;

	case FOTA_DOWNLOAD_EVT_PROGRESS:
		LOG_DBG("FOTA_DOWNLOAD_EVT_PROGRESS");

		/* Only if CONFIG_FOTA_DOWNLOAD_PROGRESS_EVT is enabled */
		download_progress = evt->progress;
		aws_fota_evt.id = AWS_FOTA_EVT_DL_PROGRESS;
		aws_fota_evt.dl.progress = download_progress;
		callback(&aws_fota_evt);
		break;

	case FOTA_DOWNLOAD_EVT_SUSPENDED:
		// Set Internal State To Suspended...
		LOG_INF("FOTA_DOWNLOAD_EVT_SUSPENDED, JOB ID: %s - NUM: %d", job_id_handling, execution_version_number);
		internal_state_set(AWS_FOTA_STATE_SUSPENDED);
		// Puble the suspend up...
		aws_fota_evt.id = AWS_FOTA_EVT_SUSPEND;
		callback(&aws_fota_evt);
		break;
	case FOTA_DOWNLOAD_EVT_RESUMED:
		// Set Internal State To Suspended...
		LOG_INF("FOTA_DOWNLOAD_EVT_RESUMED, JOB ID: %s - NUM: %d", job_id_handling, execution_version_number);
		// Bubble the suspend up...
		aws_fota_evt.id = AWS_FOTA_EVT_RESUMED;
		callback(&aws_fota_evt);
		break;

	default:
		LOG_WRN("Unhandled FOTA event ID: %d", evt->id);
		break;
	}
}

int aws_fota_init(struct mqtt_client *const client,
		  aws_fota_callback_t evt_handler)
{
	int err;

	if (internal_state != AWS_FOTA_STATE_UNINIT) {
		LOG_WRN("AWS FOTA library has already been initialized");
		return -EPERM;
	}

	if (client == NULL || evt_handler == NULL) {
		return -EINVAL;
	}

	/* Store client to make it available in event handlers. */
	client_internal = client;
	callback = evt_handler;

	err = fota_download_init(http_fota_handler);
	if (err != 0) {
		LOG_ERR("fota_download_init error %d", err);
		return err;
	}

	internal_state_set(AWS_FOTA_STATE_INIT);
	return 0;
}

int aws_fota_get_job_id(uint8_t *const job_id_buf, size_t buf_size)
{
	if ((job_id_buf == NULL) || (buf_size == 0)) {
		return -EINVAL;
	}
	return snprintf(job_id_buf, buf_size, "%s", (char *)job_id_handling);
}

enum internal_state_t get_fota_internal_state(void)
{
	return internal_state;
}
