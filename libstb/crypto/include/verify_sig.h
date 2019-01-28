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

#ifndef VERIFY_SIG_H
#define VERIFY_SIG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/asn1.h>
#include <mbedtls/config.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/rsa.h>
#include <mbedtls/pk.h>
#include <mbedtls/md.h>

int verify_buf(unsigned char *cert_buf, int certlen, unsigned char *data_buf,
	       int datalen, unsigned char *sig_buf, int siglen);

#endif
