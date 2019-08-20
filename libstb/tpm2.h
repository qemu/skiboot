/* Copyright 2013-2016 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __TPM2_H
#define __TPM2_H

#include <device.h>

struct tpm_dev {

	/* TPM bus id */
	int bus_id;

	/* TPM address in the bus */
	int i2c_addr;
};

struct tpm_driver {

	/* Driver name */
	const char* name;

	/* Transmit the TPM command stored in buf to the tpm device */
	int (*transmit)(struct tpm_dev *dev, uint8_t* buf, size_t cmdlen,
			size_t *buflen);

	int (*send)(struct tpm_dev *dev, const uint8_t *buf, uint32_t len);

	int (*receive)(struct tpm_dev *dev, uint8_t *buf, uint32_t *len);
};

void tpm2_register(struct tpm_dev *dev, struct tpm_driver *driver);
struct tpm_dev* tpm2_get_device(void);
struct tpm_driver* tpm2_get_driver(void);

#endif /* __TPM2_H */
