/*
 * Copyright 2016 iXsystems, Inc.
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted providing that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <jansson.h>
#include <dispatcher.h>
#include "includes.h"
#include "winbindd.h"
#include "idmap.h"
#include "idmap_rw.h"
#include "../libcli/security/dom_sid.h"

static int
call_dispatcher(const char *method, json_t *args, json_t **result)
{
	connection_t *conn;
	int err, rpc_err;

	conn = dispatcher_open("unix:///var/run/dscached.sock");
	if (conn == NULL) {
		DEBUG(0, ("Cannot open unix domain socket connection.\n"));
		return (-1);
	}

	err = dispatcher_call_sync(conn, method, args, result);

	if (err == RPC_CALL_ERROR) {
		/* Handle the ENOENT case gracefully */
		rpc_err = json_integer_value(json_object_get(*result, "code"));
		if (rpc_err == ENOENT) {
			*result = json_null();
			dispatcher_close(conn);
			return (0);
		}

		DEBUG(0, ("RPC %s error: <%d> %s\n", method, rpc_err,
		    json_string_value(json_object_get(*result, "message"))));
	}

	if (err != RPC_CALL_DONE) {
		DEBUG(0, ("Cannot call %s: %d.\n", method, err));
		dispatcher_close(conn);
		return (-1);
	}

	json_incref(*result);
	dispatcher_close(conn);
	return (0);
}


static NTSTATUS
idmap_freenas_initialize(struct idmap_domain *dom)
{
	return (NT_STATUS_OK);
}

NTSTATUS
idmap_freenas_unixids_to_sids(struct idmap_domain *dom, struct id_map **ids)
{
	json_t *uids = json_array();
	json_t *result;
	json_t *value;
	size_t i, index;
	int err;

	for (i = 0; ids[i]; i++)
		ids[i]->status = ID_UNKNOWN;

	for (i = 0; ids[i]; i++) {
		switch (ids[i]->xid.type) {
		case ID_TYPE_UID:
			json_array_append(uids, json_pack("[si]", "UID",
			    ids[i]->xid.id));
			break;

		case ID_TYPE_GID:
			json_array_append(uids, json_pack("[si]", "GID",
			    ids[i]->xid.id));
			break;

		default:
			DBG_WARNING("Unknown id type: %d\n", ids[i]->xid.type);
			break;
		}
	}

	err = call_dispatcher("dscached.idmap.unixids_to_sids",
	    json_pack("[o]", uids), &result);

	json_array_foreach(result, index, value) {
		dom_sid_parse(json_string_value(value), ids[index]->sid);
		ids[index]->status = ID_MAPPED;
	}

	return (NT_STATUS_OK);
}

NTSTATUS
idmap_freenas_sids_to_unixids(struct idmap_domain *dom, struct id_map **ids)
{
	json_t *sids = json_array();
	json_t *result;
	json_t *value;
	size_t i, index;
	int err;

	for (i = 0; ids[i]; i++)
		ids[i]->status = ID_UNKNOWN;

	for (i = 0; ids[i]; i++) {
		char sid[DOM_SID_STR_BUFLEN];
		dom_sid_string_buf(ids[i]->sid, sid, sizeof(sid));
		json_array_append(sids, json_string(sid));
	}

	err = call_dispatcher("dscached.idmap.sids_to_unixids",
	    json_pack("[o]", sids), &result);

	json_array_foreach(result, index, value) {
		const char *type;
		int id;

		json_unpack(value, "[si]", &type, &id);
		ids[index]->xid.id = id;

		if (strcmp(type, "UID") == 0)
			ids[index]->xid.type = ID_TYPE_UID;
		else if (strcmp(type, "GID") == 0)
			ids[index]->xid.type = ID_TYPE_GID;
		else if (strcmp(type, "BOTH") == 0)
			ids[index]->xid.type = ID_TYPE_BOTH;
		else
			ids[index]->xid.type = ID_TYPE_NOT_SPECIFIED;

		ids[index]->status = ID_MAPPED;
	}

	return (NT_STATUS_OK);
}

NTSTATUS
idmap_freenas_allocate_id(struct idmap_domain * dom, struct unixid * id)
{
	return (NT_STATUS_NOT_IMPLEMENTED);
}

static struct idmap_methods db_methods = {
	.init = idmap_freenas_initialize,
	.unixids_to_sids = idmap_freenas_unixids_to_sids,
	.sids_to_unixids = idmap_freenas_sids_to_unixids,
	.allocate_id = idmap_freenas_allocate_id
};

NTSTATUS idmap_freenas_init(void)
{
	DEBUG(10, ("calling idmap_freenas_init\n"));

	return (smb_register_idmap(SMB_IDMAP_INTERFACE_VERSION, "freenas",
	    &db_methods));
}
