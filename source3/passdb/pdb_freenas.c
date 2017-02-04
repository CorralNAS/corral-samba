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
#include "passdb.h"
#include "system/passwd.h"
#include "system/filesys.h"
#include "../librpc/gen_ndr/samr.h"
#include "../libcli/security/security.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_PASSDB

struct freenas_search_state
{
	bool (*callback)(json_t *, struct samr_displayentry *, TALLOC_CTX *);
	connection_t *conn;
	rpc_call_t *call;
	json_t *users;
	size_t position;
};

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

static rpc_call_t *
call_dispatcher_stream(const char *method, json_t *args, json_t **result,
    connection_t **connp)
{
	struct timespec ts;
	connection_t *conn;
	rpc_call_t *call;

	conn = dispatcher_open("unix:///var/run/dscached.sock");
	if (conn == NULL)
		return (NULL);

	call = dispatcher_call_sync_ex(conn, method, args);
	if (call == NULL) {
		dispatcher_close(conn);
		return (NULL);
	}

	*result = rpc_call_result(call);
	*connp = conn;
	return (call);
}

static bool
build_sam_account(struct samu *sam_pass, const json_t *user)
{
	struct passwd *pwd;
	struct tm *last_set_time;
	const char *str;
	uint8_t nthash[NT_HASH_LEN];
	uint8_t lmhash[LM_HASH_LEN];
	int i;

	if (user == NULL) {
		DEBUG(5,("build_sam_account: user is NULL\n"));
		return (false);
	}

	pwd = malloc(sizeof(struct passwd));
	pwd->pw_uid = json_integer_value(json_object_get(user, "uid"));
	pwd->pw_name = json_string_value(json_object_get(user, "username"));
	pwd->pw_gecos = json_string_value(json_object_get(user, "full_name"));
	pwd->pw_passwd = json_string_value(json_object_get(user, "unixhash"));
	pwd->pw_shell = json_string_value(json_object_get(user, "shell"));
	pwd->pw_dir = json_string_value(json_object_get(user, "home"));

	if (pwd->pw_passwd == NULL)
		pwd->pw_passwd = "*";

	if (!NT_STATUS_IS_OK(samu_set_unix(sam_pass, pwd))) {
		free(pwd);
		return (false);
	}

	free(pwd);

	str = json_string_value(json_object_get(user, "nthash"));
	if (str) {
		for (i = 0; i < NT_HASH_LEN; i++)
			sscanf(str + 2 * i, "%02X", &nthash[i]);

		if (!pdb_set_nt_passwd(sam_pass, nthash, PDB_SET))
			return (false);
	}

	str = json_string_value(json_object_get(user, "lmhash"));
	if (str) {
		for (i = 0; i < LM_HASH_LEN; i++)
			sscanf(str + 2 * i, "%02X", &lmhash[i]);

		if (!pdb_set_lanman_passwd(sam_pass, lmhash, PDB_SET))
			return (false);
	}

	last_set_time = rpc_json_to_timestamp(json_object_get(user,
	    "password_changed_at"));
	if (last_set_time != NULL) {
		pdb_set_pass_last_set_time(sam_pass, mktime(last_set_time),
		    PDB_SET);
		free(last_set_time);
	}

	pdb_set_acct_ctrl(sam_pass, ACB_NORMAL, PDB_SET);
	return (true);
}

static bool
build_group(GROUP_MAP *map, const json_t *group)
{
	if (group == NULL) {
		DEBUG(5,("build_group: group is NULL\n"));
		return (false);
	}

	map->gid = json_integer_value(json_object_get(group, "gid"));
	map->nt_name = talloc_strdup(map, json_string_value(
	    json_object_get(group, "name")));
	map->sid_name_use = SID_NAME_DOM_GRP;
	sid_compose(&map->sid, get_global_sam_sid(),
	    algorithmic_pdb_gid_to_group_rid(map->gid));

	return (true);
}

static NTSTATUS
freenas_getsampwnam(struct pdb_methods *methods, struct samu *sam_acct,
    const char *username)
{
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	struct smb_passwd *smb_pw;
	json_t *result;
	int ret;

	DEBUG(10, ("getsampwnam (freenas): search by name: %s\n", username));

	ret = call_dispatcher("dscached.account.getpwnam",
	    json_pack("[sb]", username, true), &result);

	if (ret != 0) {
		DEBUG(0, ("Unable to connect to dscached service.\n"));
		return (nt_status);
	}

	if (json_is_null(result))
		return (nt_status);

	DEBUG(10, ("getsampwnam (freenas): found by name: %s\n", username));

	/* now build the struct samu */
	if (!build_sam_account(sam_acct, result))
		return (nt_status);

	/* success */
	return (NT_STATUS_OK);
}

static NTSTATUS
freenas_getsampwsid(struct pdb_methods *methods, struct samu *sam_acct,
    const struct dom_sid *sid)
{
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	struct smb_passwd *smb_pw;
	json_t *result;
	uint32_t rid;
	int ret;

	DEBUG(10, ("freenas_getsampwrid: search by sid: %s\n",
	    sid_string_dbg(sid)));

	if (!sid_peek_check_rid(get_global_sam_sid(), sid, &rid))
		return (NT_STATUS_UNSUCCESSFUL);

	if (!algorithmic_pdb_rid_is_user(rid))
		return (NT_STATUS_NO_SUCH_USER);

	/* More special case 'guest account' hacks... */
	if (rid == DOMAIN_RID_GUEST) {
		const char *guest_account = lp_guest_account();
		if (!(guest_account && *guest_account)) {
			DEBUG(1, ("Guest account not specfied!\n"));
			return (nt_status);
		}

		return (freenas_getsampwnam(methods, sam_acct, guest_account));
	}

	ret = call_dispatcher("dscached.account.getpwuid",
	    json_pack("[ib]", algorithmic_pdb_user_rid_to_uid(rid), true),
	    &result);

	if (ret != 0) {
		DEBUG(0, ("Unable to connect to dscached service.\n"));
		return (nt_status);
	}

	if (json_is_null(result))
		return (NT_STATUS_NO_SUCH_USER);

	DEBUG(10, ("getsampwsid (freenas): found by sid: %s\n",
	    sid_string_dbg(sid)));

	/* now build the struct samu */
	if (!build_sam_account(sam_acct, result))
		return (nt_status);

	/* build_sam_account might change the SID on us, if the name was for
	 * the guest account
	 */
	if (NT_STATUS_IS_OK(nt_status) &&
	    !dom_sid_equal(pdb_get_user_sid(sam_acct), sid)) {
		DEBUG(1, ("looking for user with sid %s instead returned %s "
		    "for account %s!?!\n", sid_string_dbg(sid),
		    sid_string_dbg(pdb_get_user_sid(sam_acct)),
		    pdb_get_username(sam_acct)));

		return (NT_STATUS_NO_SUCH_USER);
	}

	return (NT_STATUS_OK);
}

static NTSTATUS
freenas_getgrnam(struct pdb_methods *methods, GROUP_MAP *map, const char *name)
{
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	struct smb_passwd *smb_pw;
	json_t *result;
	int ret;

	DEBUG(10, ("getgrnam (freenas): search by name: %s\n", name));

	ret = call_dispatcher("dscached.group.getgrnam",
	    json_pack("[sb]", name, true),
	    &result);

	if (ret != 0) {
		DEBUG(0, ("Unable to connect to dscached service.\n"));
		return (nt_status);
	}

	if (json_is_null(result))
		return (nt_status);

	DEBUG(10, ("getgrnam (freenas): found by name: %s\n", name));

	map->methods = methods;
	if (!build_group(map, result))
		return (nt_status);

	/* success */
	return (NT_STATUS_OK);
}

static NTSTATUS
freenas_getgrgid(struct pdb_methods *methods, GROUP_MAP *map, gid_t gid)
{
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	struct smb_passwd *smb_pw;
	json_t *result;
	int ret;

	DEBUG(10, ("getgrgid (freenas): search by gid: %d\n", gid));

	ret = call_dispatcher("dscached.group.getgrgid",
	    json_pack("[ib]", gid, true),
	    &result);

	if (ret != 0) {
		DEBUG(0, ("Unable to connect to dscached service.\n"));
		return (nt_status);
	}

	if (json_is_null(result))
		return (nt_status);

	DEBUG(10, ("getgrgid (freenas): found by gid: %d\n", gid));

	map->methods = methods;
	if (!build_group(map, result))
		return (nt_status);

	/* success */
	return (NT_STATUS_OK);
}

static NTSTATUS
freenas_getgrsid(struct pdb_methods *methods, GROUP_MAP *map,
    struct dom_sid sid)
{
	uint32_t rid;

	if (!sid_peek_check_rid(get_global_sam_sid(), &sid, &rid))
		return (NT_STATUS_UNSUCCESSFUL);

	if (algorithmic_pdb_rid_is_user(rid))
		return (NT_STATUS_NO_SUCH_GROUP);

	return freenas_getgrgid(methods, map, pdb_group_rid_to_gid(rid));
}

static uint32_t
freenas_capabilities(struct pdb_methods *methods)
{
	return (0);
}

static bool
freenas_convert_user(json_t *user, struct samr_displayentry *entry,
    TALLOC_CTX *ctx)
{

	entry->rid = algorithmic_pdb_uid_to_user_rid(json_integer_value(
	    json_object_get(user, "uid")));
	entry->acct_flags = ACB_NORMAL;
	entry->account_name = talloc_strdup(ctx, json_string_value(
	    json_object_get(user, "username")));
	entry->fullname = talloc_strdup(ctx, json_string_value(
	    json_object_get(user, "full_name")));
	entry->description = talloc_strdup(ctx, "description");

	return (true);
}

static bool
freenas_convert_group(json_t *group, struct samr_displayentry *entry,
    TALLOC_CTX *ctx)
{
	const char *name;

	name = json_string_value(json_object_get(group, "name"));

	if (getpwnam(name) != NULL)
		return (false);

	entry->rid = algorithmic_pdb_gid_to_group_rid(json_integer_value(
	    json_object_get(group, "gid")));
	entry->account_name = talloc_strdup(ctx, name);
	entry->fullname = talloc_strdup(ctx, name);
	entry->description = talloc_strdup(ctx, "description");

	return (true);
}

static void
freenas_search_end(struct pdb_search *search)
{
	struct freenas_search_state *state = talloc_get_type_abort(
	    search->private_data, struct freenas_search_state);
	json_decref(state->users);
	TALLOC_FREE(state);
}

static bool
freenas_search_next_entry(struct pdb_search *search,
    struct samr_displayentry *entry)
{
	struct freenas_search_state *state = talloc_get_type_abort(
	    search->private_data, struct freenas_search_state);
	json_t *item;

repeat:
	if (state->position >= json_array_size(state->users)) {
		if (rpc_call_continue(state->call, true) != RPC_CALL_MORE_AVAILABLE) {
			rpc_call_free(state->call);
			dispatcher_close(state->conn);
			return (false);
		}

		state->users = rpc_call_result(state->call);
		state->position = 0;
	}

	item = json_array_get(state->users, state->position);
	entry->idx = state->position;

	if (!state->callback(item, entry, search)) {
		state->position++;
		goto repeat;
	}

	if (entry->account_name == NULL) {
		DEBUG(0, ("talloc_strdup failed\n"));
		return (false);
	}

	state->position++;
	return (true);
}

static bool
freenas_search_users(struct pdb_methods *methods, struct pdb_search *search,
    uint32_t acct_flags)
{
	struct freenas_search_state *search_state;
	json_t *result;
	rpc_call_t *call;
	connection_t *conn;
	int ret;

	call = call_dispatcher_stream("dscached.account.query",
	    json_pack("[[][]b]", true),
	    &result, &conn);

	if (call == NULL) {
		DEBUG(10, ("Unable to contact dscached service.\n"));
		return (false);
	}

	search_state = talloc_zero(search, struct freenas_search_state);
	if (search_state == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return (false);
	}

	search_state->conn = conn;
	search_state->call = call;
	search_state->users = result;
	search_state->position = 0;
	search_state->callback = freenas_convert_user;
	search->private_data = search_state;
	search->next_entry = freenas_search_next_entry;
	search->search_end = freenas_search_end;
	return (true);
}

static bool
freenas_search_groups(struct pdb_methods *methods, struct pdb_search *search)
{
	struct freenas_search_state *search_state;
	json_t *result;
	rpc_call_t *call;
	connection_t *conn;
	int ret;

	call = call_dispatcher_stream("dscached.group.query",
	    json_pack("[[][]b]", true),
	    &result, &conn);

	if (call == NULL) {
		DEBUG(10, ("Unable to contact dscached service.\n"));
		return (false);
	}

	search_state = talloc_zero(search, struct freenas_search_state);
	if (search_state == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return (false);
	}

	search_state->conn = conn;
	search_state->call = call;
	search_state->users = result;
	search_state->position = 0;
	search_state->callback = freenas_convert_group;
	search->private_data = search_state;
	search->next_entry = freenas_search_next_entry;
	search->search_end = freenas_search_end;
	return (true);
}

static NTSTATUS
freenas_enum_group_memberships(struct pdb_methods *methods, TALLOC_CTX *mem_ctx,
    struct samu *user, struct dom_sid **pp_sids, gid_t **pp_gids,
    uint32_t *p_num_groups)
{
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	json_t *result;
	json_t *item;
	size_t index;
	int ret;
	uint32_t p_num_gids = 0, p_num_sids = 0;

	*pp_gids = NULL;
	*pp_sids = NULL;
	*p_num_groups = 0;

	DEBUG(10, ("enum_group_membership (freenas): search by name: %s\n",
	    user->username));

	ret = call_dispatcher("dscached.account.getgroupmembership",
	    json_pack("[sb]", user->username, true), &result);

	if (ret != 0) {
		DEBUG(0, ("Unable to connect to dscached service.\n"));
		return (nt_status);
	}

	if (json_is_null(result) || !json_is_array(result))
		return (NT_STATUS_OK);

	DEBUG(10, ("enum_group_membership (freenas): found by name: %s\n",
	    user->username));

	json_array_foreach(result, index, item) {
		struct dom_sid sid;
		int gid;

		gid = json_integer_value(item);
		sid_compose(&sid, get_global_sam_sid(),
		    algorithmic_pdb_gid_to_group_rid(gid));

		add_gid_to_array_unique(mem_ctx, gid, pp_gids, &p_num_gids);
		add_sid_to_array_unique(mem_ctx, &sid, pp_sids, &p_num_sids);
	}

	*p_num_groups = p_num_gids;

	/* success */
	return (NT_STATUS_OK);
}

static NTSTATUS
pdb_init_freenas(struct pdb_methods **pdb_method, const char *location)
{
	NTSTATUS nt_status;

	if (!NT_STATUS_IS_OK(nt_status = make_pdb_method(pdb_method)))
		return nt_status;

	(*pdb_method)->name = "freenas";
	(*pdb_method)->getsampwnam = freenas_getsampwnam;
	(*pdb_method)->getsampwsid = freenas_getsampwsid;
	(*pdb_method)->getgrnam = freenas_getgrnam;
	(*pdb_method)->getgrgid = freenas_getgrgid;
	(*pdb_method)->getgrsid = freenas_getgrsid;
	(*pdb_method)->search_users = freenas_search_users;
	(*pdb_method)->search_groups = freenas_search_groups;
	(*pdb_method)->enum_group_memberships = freenas_enum_group_memberships;
	(*pdb_method)->capabilities = freenas_capabilities;
	(*pdb_method)->private_data = NULL;

	return (NT_STATUS_OK);
}

NTSTATUS
pdb_freenas_init(void)
{
	return (smb_register_passdb(PASSDB_INTERFACE_VERSION, "freenas",
	    pdb_init_freenas));
}
