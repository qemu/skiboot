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

#include <device.h>
#include <libstb/tpm2.h>

static struct tpm_dev *tpm_device;
static struct tpm_driver *tpm_driver;

void tpm2_register(struct tpm_dev *dev, struct tpm_driver *driver)
{
	tpm_device = dev;
	tpm_driver = driver;
}


struct tpm_dev* tpm2_get_device(void)
{
	return tpm_device;
}

struct tpm_driver* tpm2_get_driver(void)
{
	return tpm_driver;
}
