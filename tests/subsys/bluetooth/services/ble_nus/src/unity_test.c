/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */
#include <errno.h>
#include <unity.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <bluetooth/services/ble_nus.h>
#include "ble.h"
#include "ble_gap.h"
#include "ble_gatt.h"
#include "ble_gatts.h"
#include "ble_types.h"
#include "cmock_ble_gatts.h"
#include "cmock_ble.h"
#include <cmock_nrf_sdh_ble.h>
#include "nrf_error.h"

BLE_NUS_DEF(ble_nus);
bool evt_handler_called;

static void ble_nus_evt_handler_on_connect(const struct ble_nus_evt *evt)
{
	TEST_ASSERT_EQUAL(BLE_NUS_EVT_COMM_STARTED, evt->type);
	TEST_ASSERT_TRUE(evt->link_ctx->is_notification_enabled);
	evt_handler_called = true;
}

static void ble_nus_evt_handler_on_connect_null_ctx(const struct ble_nus_evt *evt)
{
	TEST_ASSERT_EQUAL(BLE_NUS_EVT_COMM_STARTED, evt->type);
	TEST_ASSERT_NULL(evt->link_ctx);
	evt_handler_called = true;
}

static void ble_nus_evt_handler_on_write(const struct ble_nus_evt *evt)
{
	TEST_ASSERT_EQUAL(BLE_NUS_EVT_COMM_STARTED, evt->type);
	TEST_ASSERT_TRUE(evt->link_ctx->is_notification_enabled);
	evt_handler_called = true;
}

void test_ble_nus_init_efault(void)
{
	int ret;
	struct ble_nus_config nus_cfg = {0};

	ret = ble_nus_init(NULL, &nus_cfg);
	TEST_ASSERT_EQUAL(-EFAULT, ret);

	ret = ble_nus_init(&ble_nus, NULL);
	TEST_ASSERT_EQUAL(-EFAULT, ret);
}

void test_ble_nus_init_einval(void)
{
	int ret;
	struct ble_nus_config nus_cfg = {0};

	__cmock_sd_ble_uuid_vs_add_ExpectAnyArgsAndReturn(NRF_ERROR_INVALID_PARAM);
	ret = ble_nus_init(&ble_nus, &nus_cfg);
	TEST_ASSERT_EQUAL(-EINVAL, ret);

	__cmock_sd_ble_uuid_vs_add_ExpectAnyArgsAndReturn(NRF_SUCCESS);
	__cmock_sd_ble_gatts_service_add_ExpectAnyArgsAndReturn(NRF_ERROR_INVALID_PARAM);
	ret = ble_nus_init(&ble_nus, &nus_cfg);
	TEST_ASSERT_EQUAL(-EINVAL, ret);

	__cmock_sd_ble_uuid_vs_add_ExpectAnyArgsAndReturn(NRF_SUCCESS);
	__cmock_sd_ble_gatts_service_add_ExpectAnyArgsAndReturn(NRF_SUCCESS);
	__cmock_sd_ble_gatts_characteristic_add_ExpectAnyArgsAndReturn(
		NRF_ERROR_INVALID_PARAM);
	ret = ble_nus_init(&ble_nus, &nus_cfg);
	TEST_ASSERT_EQUAL(-EINVAL, ret);

	__cmock_sd_ble_uuid_vs_add_ExpectAnyArgsAndReturn(NRF_SUCCESS);
	__cmock_sd_ble_gatts_service_add_ExpectAnyArgsAndReturn(NRF_SUCCESS);
	__cmock_sd_ble_gatts_characteristic_add_ExpectAnyArgsAndReturn(NRF_SUCCESS);
	__cmock_sd_ble_gatts_characteristic_add_ExpectAnyArgsAndReturn(
		NRF_ERROR_INVALID_PARAM);
	ret = ble_nus_init(&ble_nus, &nus_cfg);
	TEST_ASSERT_EQUAL(-EINVAL, ret);
}

static uint32_t stub_sd_ble_gatts_service_add(uint8_t type,
					      ble_uuid_t const *p_uuid,
					      uint16_t *p_handle,
					      int calls)
{
	ble_uuid_t expected_uuid = {
		.type = 123,
		.uuid = BLE_UUID_NUS_SERVICE,
	};
	uint16_t expected_conn_handle = BLE_CONN_HANDLE_INVALID;

	TEST_ASSERT_EQUAL(BLE_GATTS_SRVC_TYPE_PRIMARY, type);
	TEST_ASSERT_EQUAL(expected_uuid.type, p_uuid->type);
	TEST_ASSERT_EQUAL(expected_uuid.uuid, p_uuid->uuid);
	TEST_ASSERT_EQUAL(expected_conn_handle, *p_handle);

	return NRF_SUCCESS;
}

static uint32_t stub_sd_ble_gatts_characteristic_add(uint16_t service_handle,
						     const ble_gatts_char_md_t *p_char_md,
						     const ble_gatts_attr_t *p_attr_char_value,
						     ble_gatts_char_handles_t *p_handles,
						     int calls)
{
	ble_uuid_t expected_char_uuid = { .type = 123 };

	TEST_ASSERT_EQUAL(expected_char_uuid.type, p_attr_char_value->p_uuid->type);

	p_handles->value_handle = 0x100;
	p_handles->cccd_handle = 0x101;

	return NRF_SUCCESS;
}

static uint32_t stub_sd_ble_gatts_value_get(uint16_t conn_handle,
					    uint16_t handle,
					    ble_gatts_value_t *p_value,
					    int calls)
{
	TEST_ASSERT_EQUAL(0x1234, conn_handle);
	TEST_ASSERT_EQUAL(0x101, handle);

	*p_value->p_value = BLE_GATT_HVX_NOTIFICATION;

	return NRF_SUCCESS;
}

void test_ble_nus_init_success(void)
{
	int ret;
	struct ble_nus_config nus_cfg = {0};
	uint8_t expected_uuid_type = 123;

	__cmock_sd_ble_uuid_vs_add_ExpectAnyArgsAndReturn(NRF_SUCCESS);
	__cmock_sd_ble_uuid_vs_add_ReturnThruPtr_p_uuid_type(&expected_uuid_type);

	__cmock_sd_ble_gatts_service_add_Stub(stub_sd_ble_gatts_service_add);
	__cmock_sd_ble_gatts_characteristic_add_Stub(stub_sd_ble_gatts_characteristic_add);

	ret = ble_nus_init(&ble_nus, &nus_cfg);
}

void test_ble_nus_on_ble_evt_gap_evt_do_nothing(void)
{
	ble_evt_t const ble_evt = {};
	struct ble_nus nus_ctx = {};
	ble_evt_t empty_ble_evt = {};
	struct ble_nus empty_nus_ctx = {};

	ble_nus_on_ble_evt(NULL, &nus_ctx);
	ble_nus_on_ble_evt(&ble_evt, NULL);
	ble_nus_on_ble_evt(&ble_evt, &nus_ctx);

	TEST_ASSERT_EQUAL_MEMORY(&empty_ble_evt, &ble_evt, sizeof(ble_evt_t));
	TEST_ASSERT_EQUAL_MEMORY(&empty_nus_ctx, &nus_ctx, sizeof(struct ble_nus));
}

void init_nus(struct ble_nus_config *nus_cfg)
{
	int ret;
	uint8_t expected_uuid_type = 123;

	__cmock_sd_ble_uuid_vs_add_ExpectAnyArgsAndReturn(NRF_SUCCESS);
	__cmock_sd_ble_uuid_vs_add_ReturnThruPtr_p_uuid_type(&expected_uuid_type);
	__cmock_sd_ble_gatts_service_add_Stub(stub_sd_ble_gatts_service_add);
	__cmock_sd_ble_gatts_characteristic_add_Stub(stub_sd_ble_gatts_characteristic_add);

	ret = ble_nus_init(&ble_nus, nus_cfg);
	TEST_ASSERT_EQUAL(0, ret);
	TEST_ASSERT_EQUAL_PTR(nus_cfg->evt_handler, ble_nus.evt_handler);

}

void test_ble_nus_on_ble_evt_gap_evt_on_connect(void)
{
	ble_evt_t const ble_evt = {
		.evt.gap_evt.conn_handle = 0x1234,
		.header.evt_id = BLE_GAP_EVT_CONNECTED
	};
	struct ble_nus_config nus_cfg = {
		.evt_handler = ble_nus_evt_handler_on_connect,
	};

	init_nus(&nus_cfg);

	__cmock_sd_ble_gatts_value_get_Stub(stub_sd_ble_gatts_value_get);
	__cmock_nrf_sdh_ble_idx_get_ExpectAndReturn(0x1234, 0);
	ble_nus_on_ble_evt(&ble_evt, &ble_nus);

	TEST_ASSERT_TRUE(evt_handler_called);
}

void test_ble_nus_on_ble_evt_gap_evt_on_connect_null_ctx(void)
{
	ble_evt_t const ble_evt = {
		.evt.gap_evt.conn_handle = 0x1234,
		.header.evt_id = BLE_GAP_EVT_CONNECTED
	};
	struct ble_nus_config nus_cfg = {
		.evt_handler = ble_nus_evt_handler_on_connect_null_ctx,
	};

	init_nus(&nus_cfg);

	__cmock_sd_ble_gatts_value_get_Stub(stub_sd_ble_gatts_value_get);
	__cmock_nrf_sdh_ble_idx_get_ExpectAndReturn(0x1234, -1);
	ble_nus_on_ble_evt(&ble_evt, &ble_nus);

	TEST_ASSERT_TRUE(evt_handler_called);
}

void test_ble_nus_on_ble_evt_gap_evt_on_write(void)
{
	ble_evt_t const ble_evt = {
		.header.evt_id = BLE_GATTS_EVT_WRITE,
		.evt.gatts_evt = {
			.conn_handle = 0x1234,
			.params.write = {
				.handle = 0x101,
				.len = 2,
			},
		},
	};
	struct ble_nus_config nus_cfg = {
		.evt_handler = ble_nus_evt_handler_on_write,
	};
	uint16_t *const data_notif_enable = (uint16_t *)ble_evt.evt.gatts_evt.params.write.data;

	init_nus(&nus_cfg);

	*data_notif_enable = BLE_GATT_HVX_NOTIFICATION;
	__cmock_nrf_sdh_ble_idx_get_ExpectAndReturn(0x1234, 0);
	ble_nus_on_ble_evt(&ble_evt, &ble_nus);

	TEST_ASSERT_TRUE(evt_handler_called);
}

void setUp(void)
{
	memset(&ble_nus, 0, sizeof(ble_nus));
	evt_handler_called = false;
}

void tearDown(void)
{
}

extern int unity_main(void);

int main(void)
{
	return unity_main();
}
