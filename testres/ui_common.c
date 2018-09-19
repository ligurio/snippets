/*
 * Copyright © 2018 Sergey Bronnikov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef PARSE_COMMON_H
#define PARSE_COMMON_H
#include "parse_common.h"
#endif /* PARSE_COMMON_H */

const char *
format_string(enum test_format format)
{

	switch (format) {
	case FORMAT_TAP13:
		return "FORMAT_TAP13";
	case FORMAT_JUNIT:
		return "FORMAT_JUNIT";
	case FORMAT_SUBUNIT_V1:
		return "FORMAT_SUBUNIT_V1";
	case FORMAT_SUBUNIT_V2:
		return "FORMAT_SUBUNIT_V2";
	case FORMAT_UNKNOWN:
		return "FORMAT_UNKNOWN";

	default:
		return "FORMAT_UNKNOWN";
	}
}

const char *
status_string(enum test_status status)
{
	switch (status) {
	case STATUS_OK:
		return "STATUS_OK";
	case STATUS_NOTOK:
		return "STATUS_NOTOK";
	case STATUS_MISSING:
		return "STATUS_MISSING";
	case STATUS_TODO:
		return "STATUS_TODO";
	case STATUS_SKIP:
		return "STATUS_SKIP";
	case STATUS_UNDEFINED:
		return "STATUS_UNDEFINED";
	case STATUS_ENUMERATION:
		return "STATUS_ENUMERATION";
	case STATUS_INPROGRESS:
		return "STATUS_INPROGRESS";
	case STATUS_SUCCESS:
		return "STATUS_SUCCESS";
	case STATUS_UXSUCCESS:
		return "STATUS_UXSUCCESS";
	case STATUS_SKIPPED:
		return "STATUS_SKIPPED";
	case STATUS_FAILED:
		return "STATUS_FAILED";
	case STATUS_XFAILURE:
		return "STATUS_XFAILURE";
	case STATUS_ERROR:
		return "STATUS_ERROR";
	case STATUS_FAILURE:
		return "STATUS_FAILURE";
	case STATUS_PASS:
		return "STATUS_PASS";

	default:
		return "STATUS_UNKNOWN";
	}
}

