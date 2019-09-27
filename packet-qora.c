#include "config.h"

#include <epan/address.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/wmem/wmem.h>
#include <wsutil/nstime.h>

#define QORA_PORT 9084

// static const int MAGIC_OFFSET = 0;
// static const int TYPE_OFFSET = 4;
static const int FLAGS_OFFSET = 8;
// static const int MESSAGE_ID_OFFSET = 9;
// Offsets when message has an ID
static const int ID_DATA_SIZE_OFFSET = 13;
// static const int ID_DATA_CHECKSUM_OFFSET = 17;
// static const int ID_DATA_OFFSET = 21;
// Offsets when message has NO ID
static const int IDLESS_DATA_SIZE_OFFSET = 9;
// static const int IDLESS_DATA_CHECKSUM_OFFSET = 13;
// static const int IDLESS_DATA_OFFSET = 17;

static const int FLAGS_HAS_ID = 1;

static const value_string message_type_names[] = {
	{ 1, "GET_PEERS" },
	{ 2, "PEERS" },
	{ 3, "HEIGHT" },
	{ 4, "GET_SIGNATURES" },
	{ 5, "SIGNATURES" },
	{ 6, "GET_BLOCK" },
	{ 7, "BLOCK" },
	{ 8, "TRANSACTION" },
	{ 9, "PING" },
	{ 10, "VERSION" },
	{ 11, "PEER_ID" },
	{ 12, "PROOF" },
	{ 13, "PEERS_V2" },
	{ 14, "GET_BLOCK_SUMMARIES" },
	{ 15, "BLOCK_SUMMARIES" },
	{ 16, "GET_SIGNATURES_V2" },
	{ 17, "PEER_VERIFY" },
	{ 18, "VERIFICATION_CODES" },
	{ 19, "HEIGHT_V2" },
	{ 20, "GET_TRANSACTION" },
	{ 21, "GET_UNCONFIRMED_TRANSACTIONS" },
	{ 22, "TRANSACTION_SIGNATURES" },
	{ 23, "GET_ARBITRARY_DATA" },
	{ 24, "ARBITRARY_DATA" },
	{ 25, "GET_ONLINE_ACCOUNTS" },
	{ 26, "ONLINE_ACCOUNTS" },
	{ 0, NULL }
};

static const value_string transaction_type_names[] = {
	{ 1, "GENESIS" },
	{ 2, "PAYMENT" },
	{ 3, "REGISTER_NAME" },
	{ 4, "UPDATE_NAME" },
	{ 5, "SELL_NAME" },
	{ 6, "CANCEL_SELL_NAME" },
	{ 7, "BUY_NAME" },
	{ 8, "CREATE_POLL" },
	{ 9, "VOTE_ON_POLL" },
	{ 10, "ARBITRARY" },
	{ 11, "ISSUE_ASSET" },
	{ 12, "TRANSFER_ASSET" },
	{ 13, "CREATE_ASSET_ORDER" },
	{ 14, "CANCEL_ASSET_ORDER" },
	{ 15, "MULTI_PAYMENT" },
	{ 16, "DEPLOY_AT" },
	{ 17, "MESSAGE" },
	{ 18, "DELEGATION" },
	{ 19, "SUPERNODE" },
	{ 20, "AIRDROP" },
	{ 21, "AT" },
	{ 22, "CREATE_GROUP" },
	{ 23, "UPDATE_GROUP" },
	{ 24, "ADD_GROUP_ADMIN" },
	{ 25, "REMOVE_GROUP_ADMIN" },
	{ 26, "GROUP_BAN" },
	{ 27, "CANCEL_GROUP_BAN" },
	{ 28, "GROUP_KICK" },
	{ 29, "GROUP_INVITE" },
	{ 30, "CANCEL_GROUP_INVITE" },
	{ 31, "JOIN_GROUP" },
	{ 32, "LEAVE_GROUP" },
	{ 33, "GROUP_APPROVAL" },
	{ 34, "SET_GROUP" },
	{ 35, "UPDATE_ASSET" },
	{ 36, "ACCOUNT_FLAGS" },
	{ 37, "ENABLE_FORGING" },
	{ 38, "PROXY_FORGING" },
	{ 0, NULL }
};

static const value_string net_names[] = {
	{ 0x514f5254, "QORTAL mainnet" },
	{ 0x716f7254, "QORTAL testnet" },
	{ 0, NULL }
};


typedef struct {
	guint32 req_frame;
	address req_src;
	guint32 req_srcport;
	guint32 rep_frame;
	nstime_t req_time;
	nstime_t rep_delta;
} qora_message_pair_t;

typedef struct {
	wmem_map_t *pairs_by_id;
} qora_conv_info_t;

static int proto_qora = -1;
static int msg_peers = -1;
static int msg_height = -1;
static int msg_signatures = -1;
static int msg_get_block = -1;
static int msg_block = -1;
static int msg_transaction = -1;
static int msg_version = -1;
static int msg_peer_id = -1;
static int msg_proof = -1;
static int msg_peers_v2 = -1;
static int msg_get_block_summaries = -1;
static int msg_block_summaries = -1;
static int msg_get_signatures_v2 = -1;
static int msg_height_v2 = -1;
static int msg_get_transaction = -1;
static int msg_transaction_signatures = -1;
static int msg_get_online_accounts = -1;
static int msg_online_accounts = -1;

static gint ett_qora = -1;
static gint ett_qora_sub = -1;

static int hf_magic = -1;
static int hf_message_type = -1;
static int hf_message_flags = -1;
static int hf_flags_has_id = -1;
static int hf_message_id = -1;
static int hf_data_size = -1;
static int hf_data_checksum = -1;
static int hf_data = -1;
static int hf_message_request_link = -1;
static int hf_message_reply_link = -1;
static int hf_message_reply_time = -1;

static int hf_build_version = -1;
static int hf_peer_address = -1;
static int hf_peer_address_ipv4 = -1;
static int hf_height = -1;
static int hf_version = -1;
static int hf_block_sig = -1;
static int hf_block_ref = -1;
static int hf_transaction_type = -1;
static int hf_transaction_sig = -1;
static int hf_transaction_ref = -1;
static int hf_timestamp = -1;
static int hf_public_key = -1;
static int hf_number_entries = -1;
static int hf_transaction_count = -1;
static int hf_tx_group_id = -1;
static int hf_peer_id = -1;
static int hf_proof_salt = -1;
static int hf_proof_nonce = -1;
static int hf_entry_index = -1;
static int hf_at_bytes = -1;
static int hf_generator_sig = -1;
static int hf_transactions_sig = -1;
static int hf_generic_sig = -1;
static int hf_big_decimal = -1;
static int hf_online_accounts_bytes = -1;
static int hf_online_accounts_count = -1;
static int hf_online_accounts_timestamp = -1;
static int hf_online_accounts_signatures_count = -1;

static expert_field ei_qora_late_reply = EI_INIT;
static expert_field ei_qora_missing_reply = EI_INIT;


static guint subdissect_transaction(tvbuff_t *tvb, gint *offset, packet_info *pinfo _U_, proto_tree *sub_tree, void *data _U_, guint block_version) {
	guint tx_type;
	proto_tree_add_item_ret_uint(sub_tree, hf_transaction_type, tvb, *offset, 4, ENC_BIG_ENDIAN, &tx_type);
	*offset += 4;

	proto_tree_add_item(sub_tree, hf_timestamp, tvb, *offset, 8, ENC_TIME_MSECS);
	*offset += 8;

	if (block_version >= 4) {
		proto_tree_add_item(sub_tree, hf_tx_group_id, tvb, *offset, 4, ENC_BIG_ENDIAN);
		*offset += 4;
	}

	proto_tree_add_item(sub_tree, hf_transaction_ref, tvb, *offset, 64, ENC_NA);
	*offset += 64;

	proto_tree_add_item(sub_tree, hf_public_key, tvb, *offset, 32, ENC_NA);
	*offset += 32;

	return tx_type;
}

static void subdissect_block(tvbuff_t *tvb, gint *offset, packet_info *pinfo, proto_tree *sub_tree, void *data _U_) {
	guint32 magic = tvb_get_guint32(tvb, 0, ENC_BIG_ENDIAN);
	const gchar *net_name = try_val_to_str(magic, net_names);
	char is_qortal = net_name != NULL && strstr(net_name, "QORTAL") != NULL;

	guint height;
	proto_tree_add_item_ret_uint(sub_tree, hf_height, tvb, *offset, 4, ENC_BIG_ENDIAN, &height);
	col_append_fstr(pinfo->cinfo, COL_INFO, "block_height=%d ", height);
	*offset += 4;

	guint block_version;
	proto_tree_add_item_ret_uint(sub_tree, hf_version, tvb, *offset, 4, ENC_BIG_ENDIAN, &block_version);
	*offset += 4;

	proto_tree_add_item(sub_tree, hf_timestamp, tvb, *offset, 8, ENC_TIME_MSECS);
	*offset += 8;

	proto_tree_add_item(sub_tree, hf_block_ref, tvb, *offset, 128, ENC_NA);
	*offset += 128;

	// generatingBalance?
	if (!is_qortal) {
		proto_tree_add_item(sub_tree, hf_big_decimal, tvb, *offset, 8, ENC_BIG_ENDIAN);
		*offset += 8;
	}

	proto_tree_add_item(sub_tree, hf_public_key, tvb, *offset, 32, ENC_NA);
	*offset += 32;

	// txSig
	proto_tree_add_item(sub_tree, hf_transactions_sig, tvb, *offset, 64, ENC_NA);
	*offset += 64;

	// genSig
	proto_tree_add_item(sub_tree, hf_generator_sig, tvb, *offset, 64, ENC_NA);
	*offset += 64;

	if (block_version >= 2) {
		guint at_bytes_length;
		proto_tree_add_item_ret_length(sub_tree, hf_at_bytes, tvb, *offset, 4, ENC_BIG_ENDIAN | ENC_NA, &at_bytes_length);
		*offset += at_bytes_length;

		if (block_version < 4) {
			// AT fees
			*offset += 8;
		}
	}

	guint transaction_count;
	proto_item *transaction_count_ti = proto_tree_add_item_ret_uint(sub_tree, hf_transaction_count, tvb, *offset, 4, ENC_BIG_ENDIAN, &transaction_count);
	col_append_fstr(pinfo->cinfo, COL_INFO, "transaction_count=%d ", transaction_count);
	*offset += 4;

	proto_tree *tx_tree = proto_item_add_subtree(transaction_count_ti, ett_qora_sub);
	for (guint i = 0; i < transaction_count; ++i) {
		proto_item *entry_index_ti = proto_tree_add_uint(tx_tree, hf_entry_index, tvb, *offset, 0, i);
		proto_tree *entry_tree = proto_item_add_subtree(entry_index_ti, ett_qora_sub);

		guint tx_length = tvb_get_guint32(tvb, *offset, ENC_BIG_ENDIAN);
		*offset += 4;

		guint pre_tx_offset = *offset;
		subdissect_transaction(tvb, offset, pinfo, entry_tree, data, block_version);
		*offset = pre_tx_offset + tx_length;
	}

	if (block_version >= 4 && tvb_reported_length(tvb) > (guint) *offset) {
		// Online accounts
		proto_tree_add_item(sub_tree, hf_online_accounts_count, tvb, *offset, 4, ENC_BIG_ENDIAN);
		*offset += 4;

		guint online_accounts_length;
		proto_tree_add_item_ret_length(sub_tree, hf_online_accounts_bytes, tvb, *offset, 4, ENC_BIG_ENDIAN | ENC_NA, &online_accounts_length);
		*offset += online_accounts_length;

		// Online accounts signatures
		guint online_accounts_signatures_count;
		proto_item *online_accounts_signatures_count_ti = proto_tree_add_item_ret_uint(sub_tree, hf_online_accounts_signatures_count, tvb, *offset, 4, ENC_BIG_ENDIAN, &online_accounts_signatures_count);
		*offset += 4;

		if (online_accounts_signatures_count > 0) {
			proto_tree *ts_sig_tree = proto_item_add_subtree(online_accounts_signatures_count_ti, ett_qora_sub);

			// Online accounts timestamp only present if there are actual signatures
			proto_tree_add_item(ts_sig_tree, hf_online_accounts_timestamp, tvb, *offset, 8, ENC_TIME_MSECS);
			*offset += 8;

			for (guint i = 0; i < online_accounts_signatures_count; ++i) {
				proto_tree_add_item(ts_sig_tree, hf_generic_sig, tvb, *offset, 64, ENC_NA);
				*offset += 64;
			}
		}
	}
}

static void dissect_peers(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree, void *data _U_) {
	proto_item *ti = proto_tree_add_item(tree, msg_peers, tvb, offset, -1, ENC_NA);
	proto_tree *sub_tree = proto_item_add_subtree(ti, ett_qora_sub);

	guint number_entries;
	proto_item *number_entries_ti = proto_tree_add_item_ret_uint(sub_tree, hf_number_entries, tvb, offset, 4, ENC_BIG_ENDIAN, &number_entries);
	col_append_fstr(pinfo->cinfo, COL_INFO, "num_entries=%d ", number_entries);
	offset += 4;

	proto_tree *peers_tree = proto_item_add_subtree(number_entries_ti, ett_qora_sub);
	for (guint i = 0; i < number_entries; ++i) {
		proto_tree_add_item(peers_tree, hf_peer_address_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}
}

static void dissect_height(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree, void *data _U_) {
	proto_item *ti = proto_tree_add_item(tree, msg_height, tvb, offset, -1, ENC_NA);
	proto_tree *sub_tree = proto_item_add_subtree(ti, ett_qora_sub);

	guint height;
	proto_tree_add_item_ret_uint(sub_tree, hf_height, tvb, offset, 4, ENC_BIG_ENDIAN, &height);

	col_append_fstr(pinfo->cinfo, COL_INFO, "block_height=%d ", height);
}

static void dissect_signatures(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree, void *data _U_) {
	proto_item *ti = proto_tree_add_item(tree, msg_signatures, tvb, offset, -1, ENC_NA);
	proto_tree *sub_tree = proto_item_add_subtree(ti, ett_qora_sub);

	guint number_entries;
	proto_item *number_entries_ti = proto_tree_add_item_ret_uint(sub_tree, hf_number_entries, tvb, offset, 4, ENC_BIG_ENDIAN, &number_entries);
	col_append_fstr(pinfo->cinfo, COL_INFO, "num_entries=%d ", number_entries);
	offset += 4;

	proto_tree *sigs_tree = proto_item_add_subtree(number_entries_ti, ett_qora_sub);
	for (guint i = 0; i < number_entries; ++i) {
		proto_tree_add_item(sigs_tree, hf_block_sig, tvb, offset, 128, ENC_NA);
		offset += 128;
	}
}

static void dissect_get_block(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_, proto_tree *tree, void *data _U_) {
	proto_item *ti = proto_tree_add_item(tree, msg_get_block, tvb, offset, -1, ENC_NA);
	proto_tree *sub_tree = proto_item_add_subtree(ti, ett_qora_sub);

	proto_tree_add_item(sub_tree, hf_block_sig, tvb, offset, 128, ENC_NA);
}

static void dissect_block(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_, proto_tree *tree, void *data _U_) {
	proto_item *ti = proto_tree_add_item(tree, msg_block, tvb, offset, -1, ENC_NA);
	proto_tree *sub_tree = proto_item_add_subtree(ti, ett_qora_sub);

	subdissect_block(tvb, &offset, pinfo, sub_tree, data);
}

static void dissect_transaction(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree, void *data _U_) {
	proto_item *ti = proto_tree_add_item(tree, msg_transaction, tvb, offset, -1, ENC_NA);
	proto_tree *sub_tree = proto_item_add_subtree(ti, ett_qora_sub);

	guint tx_type;
	proto_tree_add_item_ret_uint(sub_tree, hf_transaction_type, tvb, offset, 4, ENC_BIG_ENDIAN, &tx_type);
	col_append_fstr(pinfo->cinfo, COL_INFO, "tx_type=%s ", val_to_str(tx_type, transaction_type_names, "tx_type=%d"));
	offset += 4;

	proto_tree_add_item(sub_tree, hf_timestamp, tvb, offset, 8, ENC_TIME_MSECS);
}

static void dissect_version(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree, void *data _U_) {
	proto_item *ti = proto_tree_add_item(tree, msg_version, tvb, offset, -1, ENC_NA);
	proto_tree *sub_tree = proto_item_add_subtree(ti, ett_qora_sub);

	proto_tree_add_item(sub_tree, hf_timestamp, tvb, offset, 8, ENC_TIME_SECS);
	offset += 8;

	const guint8 *stringval;
	proto_tree_add_item_ret_string(sub_tree, hf_build_version, tvb, offset, 4, ENC_BIG_ENDIAN | ENC_UTF_8,
			wmem_packet_scope(), &stringval);
	col_append_fstr(pinfo->cinfo, COL_INFO, "version=%s ", stringval);
}

static void dissect_peer_id(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_, proto_tree *tree, void *data _U_) {
	proto_item *ti = proto_tree_add_item(tree, msg_peer_id, tvb, offset, -1, ENC_NA);
	proto_tree *sub_tree = proto_item_add_subtree(ti, ett_qora_sub);

	proto_tree_add_item(sub_tree, hf_peer_id, tvb, offset, 128, ENC_NA);
	offset += 128;
}

static void dissect_proof(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_, proto_tree *tree, void *data _U_) {
	proto_item *ti = proto_tree_add_item(tree, msg_proof, tvb, offset, -1, ENC_NA);
	proto_tree *sub_tree = proto_item_add_subtree(ti, ett_qora_sub);

	proto_tree_add_item(sub_tree, hf_timestamp, tvb, offset, 8, ENC_TIME_MSECS);
	offset += 8;

	proto_tree_add_item(sub_tree, hf_proof_salt, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	proto_tree_add_item(sub_tree, hf_proof_nonce, tvb, offset, 8, ENC_BIG_ENDIAN);
}

static void dissect_peers_v2(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree, void *data _U_) {
	proto_item *ti = proto_tree_add_item(tree, msg_peers_v2, tvb, offset, -1, ENC_NA);
	proto_tree *sub_tree = proto_item_add_subtree(ti, ett_qora_sub);

	guint number_entries;
	proto_item *number_entries_ti = proto_tree_add_item_ret_uint(sub_tree, hf_number_entries, tvb, offset, 4, ENC_BIG_ENDIAN, &number_entries);
	col_append_fstr(pinfo->cinfo, COL_INFO, "num_entries=%d ", number_entries);
	offset += 4;

	proto_tree *peers_tree = proto_item_add_subtree(number_entries_ti, ett_qora_sub);
	for (guint i = 0; i < number_entries; ++i) {
		guint len;
		proto_tree_add_item_ret_length(peers_tree, hf_peer_address, tvb, offset, 1, ENC_BIG_ENDIAN | ENC_UTF_8, &len);
		offset += len;
	}
}

static void dissect_get_block_summaries(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree, void *data _U_) {
	proto_item *ti = proto_tree_add_item(tree, msg_get_block_summaries, tvb, offset, -1, ENC_NA);
	proto_tree *sub_tree = proto_item_add_subtree(ti, ett_qora_sub);

	proto_tree_add_item(sub_tree, hf_block_sig, tvb, offset, 128, ENC_NA);
	offset += 128;

	guint number_entries;
	proto_tree_add_item_ret_uint(sub_tree, hf_number_entries, tvb, offset, 4, ENC_BIG_ENDIAN, &number_entries);
	col_append_fstr(pinfo->cinfo, COL_INFO, "num_entries=%d ", number_entries);
}

static void dissect_block_summaries(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree, void *data _U_) {
	proto_item *ti = proto_tree_add_item(tree, msg_block_summaries, tvb, offset, -1, ENC_NA);
	proto_tree *sub_tree = proto_item_add_subtree(ti, ett_qora_sub);

	guint number_entries;
	proto_tree_add_item_ret_uint(sub_tree, hf_number_entries, tvb, offset, 4, ENC_BIG_ENDIAN, &number_entries);
	col_append_fstr(pinfo->cinfo, COL_INFO, "num_entries=%d ", number_entries);
	offset += 4;

	// Try to determine if block summaries include online accounts count based on reported buffer length
	guint buffer_remaining = tvb_reported_length(tvb) - offset;
	char includesOnlineAccountsCount = buffer_remaining >= number_entries * (4 + 64 + 32 + 4); // Note extra 4 bytes

	for (guint i = 0; i < number_entries; ++i) {
		proto_item *entry_index_ti = proto_tree_add_uint(sub_tree, hf_entry_index, tvb, offset, 0, i);
		proto_tree *entry_tree = proto_item_add_subtree(entry_index_ti, ett_qora_sub);

		proto_tree_add_item(entry_tree, hf_height, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		proto_tree_add_item(entry_tree, hf_block_sig, tvb, offset, 64, ENC_NA);
		offset += 128;

		proto_tree_add_item(entry_tree, hf_public_key, tvb, offset, 32, ENC_NA);
		offset += 32;

		if (includesOnlineAccountsCount) {
			proto_tree_add_item(entry_tree, hf_online_accounts_count, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}
	}
}

static void dissect_get_signatures_v2(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_, proto_tree *tree, void *data _U_) {
	proto_item *ti = proto_tree_add_item(tree, msg_get_signatures_v2, tvb, offset, -1, ENC_NA);
	proto_tree *sub_tree = proto_item_add_subtree(ti, ett_qora_sub);

	proto_tree_add_item(sub_tree, hf_block_sig, tvb, offset, 128, ENC_NA);
	offset += 128;

	proto_tree_add_item(sub_tree, hf_number_entries, tvb, offset, 4, ENC_BIG_ENDIAN);
}

static void dissect_height_v2(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree, void *data _U_) {
	proto_item *ti = proto_tree_add_item(tree, msg_height_v2, tvb, offset, -1, ENC_NA);
	proto_tree *sub_tree = proto_item_add_subtree(ti, ett_qora_sub);

	guint height;
	proto_tree_add_item_ret_uint(sub_tree, hf_height, tvb, offset, 4, ENC_BIG_ENDIAN, &height);
	offset += 4;

	proto_tree_add_item(sub_tree, hf_block_sig, tvb, offset, 128, ENC_NA);
	offset += 128;

	proto_tree_add_item(sub_tree, hf_timestamp, tvb, offset, 8, ENC_TIME_MSECS);
	offset += 8;

	proto_tree_add_item(sub_tree, hf_public_key, tvb, offset, 32, ENC_NA);
	offset += 32;

	col_append_fstr(pinfo->cinfo, COL_INFO, "block_height=%d ", height);
}

static void dissect_get_transaction(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_, proto_tree *tree, void *data _U_) {
	proto_item *ti = proto_tree_add_item(tree, msg_get_transaction, tvb, offset, -1, ENC_NA);
	proto_tree *sub_tree = proto_item_add_subtree(ti, ett_qora_sub);

	proto_tree_add_item(sub_tree, hf_transaction_sig, tvb, offset, 64, ENC_NA);
}

static void dissect_transaction_signatures(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree, void *data _U_) {
	proto_item *ti = proto_tree_add_item(tree, msg_transaction_signatures, tvb, offset, -1, ENC_NA);
	proto_tree *sub_tree = proto_item_add_subtree(ti, ett_qora_sub);

	guint number_entries;
	proto_item *number_entries_ti = proto_tree_add_item_ret_uint(sub_tree, hf_number_entries, tvb, offset, 4, ENC_BIG_ENDIAN, &number_entries);
	col_append_fstr(pinfo->cinfo, COL_INFO, "num_entries=%d ", number_entries);
	offset += 4;

	proto_tree *sigs_tree = proto_item_add_subtree(number_entries_ti, ett_qora_sub);
	for (guint i = 0; i < number_entries; ++i) {
		proto_tree_add_item(sigs_tree, hf_transaction_sig, tvb, offset, 64, ENC_NA);
		offset += 64;
	}
}

static void dissect_get_online_accounts(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree, void *data _U_) {
	proto_item *ti = proto_tree_add_item(tree, msg_get_online_accounts, tvb, offset, -1, ENC_NA);
	proto_tree *sub_tree = proto_item_add_subtree(ti, ett_qora_sub);

	guint number_entries;
	proto_item *number_entries_ti = proto_tree_add_item_ret_uint(sub_tree, hf_number_entries, tvb, offset, 4, ENC_BIG_ENDIAN, &number_entries);
	col_append_fstr(pinfo->cinfo, COL_INFO, "num_entries=%d ", number_entries);
	offset += 4;

	proto_tree *keys_tree = proto_item_add_subtree(number_entries_ti, ett_qora_sub);
	for (guint i = 0; i < number_entries; ++i) {
		proto_item *entry_index_ti = proto_tree_add_uint(keys_tree, hf_entry_index, tvb, offset, 0, i);
		proto_tree *entry_tree = proto_item_add_subtree(entry_index_ti, ett_qora_sub);

		proto_tree_add_item(entry_tree, hf_timestamp, tvb, offset, 8, ENC_TIME_MSECS);
		offset += 8;

		proto_tree_add_item(entry_tree, hf_public_key, tvb, offset, 32, ENC_NA);
		offset += 32;
	}
}

static void dissect_online_accounts(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree, void *data _U_) {
	proto_item *ti = proto_tree_add_item(tree, msg_online_accounts, tvb, offset, -1, ENC_NA);
	proto_tree *sub_tree = proto_item_add_subtree(ti, ett_qora_sub);

	guint number_entries;
	proto_item *number_entries_ti = proto_tree_add_item_ret_uint(sub_tree, hf_number_entries, tvb, offset, 4, ENC_BIG_ENDIAN, &number_entries);
	col_append_fstr(pinfo->cinfo, COL_INFO, "num_entries=%d ", number_entries);
	offset += 4;

	proto_tree *accounts_tree = proto_item_add_subtree(number_entries_ti, ett_qora_sub);
	for (guint i = 0; i < number_entries; ++i) {
		proto_item *entry_index_ti = proto_tree_add_uint(accounts_tree, hf_entry_index, tvb, offset, 0, i);
		proto_tree *entry_tree = proto_item_add_subtree(entry_index_ti, ett_qora_sub);

		proto_tree_add_item(entry_tree, hf_timestamp, tvb, offset, 8, ENC_TIME_MSECS);
		offset += 8;

		proto_tree_add_item(entry_tree, hf_generic_sig, tvb, offset, 64, ENC_NA);
		offset += 64;

		proto_tree_add_item(entry_tree, hf_public_key, tvb, offset, 32, ENC_NA);
		offset += 32;
	}
}

static int dissect_qora_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
	gint offset = 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "qora");
	col_clear(pinfo->cinfo, COL_INFO);

	proto_item *ti = proto_tree_add_item(tree, proto_qora, tvb, 0, -1, ENC_NA);
	proto_tree *qora_tree = proto_item_add_subtree(ti, ett_qora);

	proto_tree_add_item(qora_tree, hf_magic, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	guint message_type;
	proto_tree_add_item_ret_uint(qora_tree, hf_message_type, tvb, offset, 4, ENC_BIG_ENDIAN, &message_type);
	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(message_type, message_type_names, "[type %d]"));
	offset += 4;

	proto_tree_add_item(qora_tree, hf_message_flags, tvb, offset, 1, ENC_BIG_ENDIAN);

	gboolean has_id;
	proto_tree_add_item_ret_boolean(qora_tree, hf_flags_has_id, tvb, offset, 1, ENC_BIG_ENDIAN, &has_id);
	offset += 1;

	if (has_id) {
		gint32 message_id;
		proto_tree_add_item_ret_int(qora_tree, hf_message_id, tvb, offset, 4, ENC_BIG_ENDIAN, &message_id);
		col_append_fstr(pinfo->cinfo, COL_INFO, "[ID %d] ", message_id);
		offset += 4;

		// Track request/response in conversation
		conversation_t *conversation = find_or_create_conversation(pinfo);

		qora_conv_info_t *qora_conv_info = (qora_conv_info_t *) conversation_get_proto_data(conversation, proto_qora);
		if (!qora_conv_info) {
			// Initialize conversation data for qora proto
			qora_conv_info = wmem_new(wmem_file_scope(), qora_conv_info_t);
			qora_conv_info->pairs_by_id = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);

			conversation_add_proto_data(conversation, proto_qora, qora_conv_info);
		}

		qora_message_pair_t *qora_message_pair = (qora_message_pair_t *) wmem_map_lookup(qora_conv_info->pairs_by_id, GINT_TO_POINTER(message_id));

		if (!PINFO_FD_VISITED(pinfo)) {
			// First time dissecting this packet
			if (!qora_message_pair) {
				// Should be request
				qora_message_pair = wmem_new(wmem_file_scope(), qora_message_pair_t);

				qora_message_pair->req_frame = pinfo->num;
				copy_address_wmem(wmem_file_scope(), &qora_message_pair->req_src, &pinfo->src);
				qora_message_pair->req_srcport = pinfo->srcport;
				qora_message_pair->rep_frame = 0;
				qora_message_pair->req_time = pinfo->fd->abs_ts;
				nstime_set_unset(&qora_message_pair->rep_delta);

				wmem_map_insert(qora_conv_info->pairs_by_id, GINT_TO_POINTER(message_id), (void *) qora_message_pair);
			} else if (!qora_message_pair->rep_frame) {
				// No existing reply

				// Check not same direction (e.g. retransmission)
				if (pinfo->srcport != qora_message_pair->req_srcport || !addresses_data_equal(&pinfo->src, &qora_message_pair->req_src)) {
					// Should be reply
					qora_message_pair->rep_frame = pinfo->num;
					nstime_delta(&qora_message_pair->rep_delta, &pinfo->fd->abs_ts, &qora_message_pair->req_time);
				}
			}
		}

		// Add info to protocol tree
		if (qora_message_pair->req_frame == pinfo->num) {
			// Request

			// Show link to reply if we have one
			if (qora_message_pair->rep_frame) {
				proto_item *message_pair_it = proto_tree_add_uint(qora_tree, hf_message_reply_link, tvb, 0, 0, qora_message_pair->rep_frame);
				PROTO_ITEM_SET_GENERATED(message_pair_it);
			}
		} else {
			// Reply

			// Show link to request and timing info
			proto_item *message_pair_it = proto_tree_add_uint(qora_tree, hf_message_request_link, tvb, 0, 0, qora_message_pair->req_frame);
			PROTO_ITEM_SET_GENERATED(message_pair_it);
		}

		if (!nstime_is_unset(&qora_message_pair->rep_delta)) {
			proto_item *message_pair_it = proto_tree_add_time(qora_tree, hf_message_reply_time, tvb, 0, 0, &qora_message_pair->rep_delta);
			PROTO_ITEM_SET_GENERATED(message_pair_it);

			// If response is over 5 seconds then mark as "late"
			if (qora_message_pair->rep_delta.secs > 5)
				expert_add_info(pinfo, message_pair_it, &ei_qora_late_reply);
		}
	}

	guint32 data_size;
	proto_tree_add_item_ret_uint(qora_tree, hf_data_size, tvb, offset, 4, ENC_BIG_ENDIAN, &data_size);
	offset += 4;

	if (data_size > 0) {
		proto_tree_add_item(qora_tree, hf_data_checksum, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		switch (message_type) {
			case 2: // PEERS
				dissect_peers(tvb, offset, pinfo, tree, data);
				break;

			case 3: // HEIGHT
				dissect_height(tvb, offset, pinfo, tree, data);
				break;

			case 5: // SIGNATURES
				dissect_signatures(tvb, offset, pinfo, tree, data);
				break;

			case 6: // GET_BLOCK
				dissect_get_block(tvb, offset, pinfo, tree, data);
				break;

			case 7: // BLOCK
				dissect_block(tvb, offset, pinfo, tree, data);
				break;

			case 8: // TRANSACTION
				dissect_transaction(tvb, offset, pinfo, tree, data);
				break;

			case 10: // VERSION
				dissect_version(tvb, offset, pinfo, tree, data);
				break;

			case 11: // PEER_ID
				dissect_peer_id(tvb, offset, pinfo, tree, data);
				break;

			case 12: // PROOF
				dissect_proof(tvb, offset, pinfo, tree, data);
				break;

			case 13: // PEERS_V2
				dissect_peers_v2(tvb, offset, pinfo, tree, data);
				break;

			case 14: // GET_BLOCK_SUMMARIES
				dissect_get_block_summaries(tvb, offset, pinfo, tree, data);
				break;

			case 15: // BLOCK_SUMMARIES
				dissect_block_summaries(tvb, offset, pinfo, tree, data);
				break;

			case 16: // GET_SIGNATURES_V2
				dissect_get_signatures_v2(tvb, offset, pinfo, tree, data);
				break;

			case 19: // HEIGHT_V2
				dissect_height_v2(tvb, offset, pinfo, tree, data);
				break;

			case 20: // GET_TRANSACTION
				dissect_get_transaction(tvb, offset, pinfo, tree, data);
				break;

			case 22: // TRANSACTION_SIGNATURES
				dissect_transaction_signatures(tvb, offset, pinfo, tree, data);
				break;

			case 25: // GET_ONLINE_ACCOUNTS
				dissect_get_online_accounts(tvb, offset, pinfo, tree, data);
				break;

			case 26: // ONLINE_ACCOUNTS
				dissect_online_accounts(tvb, offset, pinfo, tree, data);
				break;

			default:
				proto_tree_add_item(qora_tree, hf_data, tvb, offset, -1, ENC_NA);
		}
	}

	col_set_fence(pinfo->cinfo, COL_INFO);

	return tvb_captured_length(tvb);
}

static guint get_qora_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_) {
	guint8 flags = tvb_get_guint8(tvb, offset + FLAGS_OFFSET);
	gboolean has_id = flags & FLAGS_HAS_ID;

	int data_size_offset = has_id ? ID_DATA_SIZE_OFFSET : IDLESS_DATA_SIZE_OFFSET;

	if (offset + data_size_offset + 4 > (int) tvb_reported_length(tvb))
		return 0;

	guint32 data_size = tvb_get_ntohl(tvb, offset + data_size_offset);

	guint message_length = data_size_offset + 4;

	if (data_size == 0)
		return message_length;

	return message_length + 4 /*data checksum*/ + data_size;
}

static int dissect_qora(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {
	tcp_dissect_pdus(tvb, pinfo, tree, TRUE, IDLESS_DATA_SIZE_OFFSET + 4,
		get_qora_message_len, dissect_qora_message, data);

	return tvb_captured_length(tvb);
}

static void fmt_big_decimal(gchar *s, guint64 unscaled_value) {
	guint64 int_portion = unscaled_value / 1e8;
	guint64 fixed_portion = unscaled_value - int_portion;
	g_snprintf(s, ITEM_LABEL_LENGTH, "%ld.%08ld", int_portion, fixed_portion);
}

void proto_register_qora(void) {
	static hf_register_info hf[] = {
		// Header fields common to all messages
		{
			&hf_magic, {
				"MAGIC",
				"qora.magic",
				FT_UINT32, BASE_HEX,
				VALS(net_names), 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_message_type, {
				"Message type",
				"qora.type",
				FT_UINT32, BASE_DEC,
				VALS(message_type_names), 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_message_flags, {
				"Message flags",
				"qora.flags",
				FT_UINT8, BASE_HEX,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_flags_has_id, {
				"Has message ID?",
				"qora.has_id",
				FT_BOOLEAN, 8,
				NULL, 0x1,
				NULL, HFILL
			}
		},
		{
			&hf_message_id, {
				"Message ID",
				"qora.message_id",
				FT_INT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_data_size, {
				"Data size",
				"qora.data_size",
				FT_UINT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_data_checksum, {
				"Data checksum",
				"qora.data_checksum",
				FT_UINT32, BASE_HEX,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_data, {
				"Data",
				"qora.data",
				FT_BYTES, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_message_request_link, {
				"Request Link",
				"qora.request_link",
				FT_FRAMENUM, BASE_NONE,
				FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_message_reply_link, {
				"Reply Link",
				"qora.reply_link",
				FT_FRAMENUM, BASE_NONE,
				FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_message_reply_time, {
				"Reply Time",
				"qora.reply_time",
				FT_RELATIVE_TIME, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},

		// Header fields specific to various message types
		{
			&hf_height, {
				"Block height",
				"qora.block_height",
				FT_UINT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_version, {
				"Block/Transaction version",
				"qora.version",
				FT_UINT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_block_sig, {
				"Block signature",
				"qora.block_sig",
				FT_BYTES, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_block_ref, {
				"Block reference",
				"qora.block_ref",
				FT_BYTES, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_transaction_type, {
				"Transaction type",
				"qora.tx_type",
				FT_UINT32, BASE_DEC,
				VALS(transaction_type_names), 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_transaction_sig, {
				"Transaction signature",
				"qora.tx_sig",
				FT_BYTES, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_transaction_ref, {
				"Transaction reference",
				"qora.tx_ref",
				FT_BYTES, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_timestamp, {
				"Timestamp",
				"qora.timestamp",
				FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_public_key, {
				"Public key",
				"qora.public_key",
				FT_BYTES, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_number_entries, {
				"Number of entries",
				"qora.num_entries",
				FT_UINT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_transaction_count, {
				"Transaction count",
				"qora.transaction_count",
				FT_UINT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_tx_group_id, {
				"Transaction group ID",
				"qora.tx_group_id",
				FT_UINT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_build_version, {
				"Build version",
				"qora.build_version",
				FT_UINT_STRING, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_peer_address, {
				"Peer address",
				"qora.peer_address",
				FT_UINT_STRING, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_peer_address_ipv4, {
				"Peer address (IPv4 only)",
				"qora.peer_address_ipv4",
				FT_IPv4, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_peer_id, {
				"Peer id",
				"qora.peer_id",
				FT_BYTES, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_proof_salt, {
				"Proof salt",
				"qora.proof_salt",
				FT_UINT64, BASE_HEX,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_proof_nonce, {
				"Proof nonce",
				"qora.proof_nonce",
				FT_UINT64, BASE_HEX,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_entry_index, {
				"Entry",
				"qora.entry_index",
				FT_UINT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_at_bytes, {
				"AT bytes",
				"qora.at_bytes",
				FT_UINT_BYTES, BASE_NONE | BASE_ALLOW_ZERO,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_generator_sig, {
				"Generator signature",
				"qora.generator_sig",
				FT_BYTES, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_transactions_sig, {
				"Transactions signature",
				"qora.transactions_sig",
				FT_BYTES, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_generic_sig, {
				"Signature",
				"qora.sig",
				FT_BYTES, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_big_decimal, {
				"BigDecimal",
				"qora.big_decimal",
				FT_UINT64, BASE_CUSTOM,
				fmt_big_decimal, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_online_accounts_bytes, {
				"Online accounts bytes",
				"qora.online_accounts_bytes",
				FT_UINT_BYTES, BASE_NONE | BASE_ALLOW_ZERO,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_online_accounts_count, {
				"Online accounts count",
				"qora.online_accounts_count",
				FT_UINT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_online_accounts_timestamp, {
				"Online accounts timestamp",
				"qora.online_accounts_timestamp",
				FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_online_accounts_signatures_count, {
				"Online accounts signatures count",
				"qora.online_accounts_signatures_count",
				FT_UINT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},

		// Message types
		{
			&msg_peers, {
				"PEERS",
				"qora.msg.peers",
				FT_NONE, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&msg_height, {
				"HEIGHT",
				"qora.msg.height",
				FT_NONE, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&msg_signatures, {
				"SIGNATURES",
				"qora.msg.signatures",
				FT_NONE, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&msg_get_block, {
				"GET_BLOCK",
				"qora.msg.get_block",
				FT_NONE, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&msg_block, {
				"BLOCK",
				"qora.msg.block",
				FT_NONE, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&msg_transaction, {
				"TRANSACTION",
				"qora.msg.transaction",
				FT_NONE, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&msg_version, {
				"VERSION",
				"qora.msg.version",
				FT_NONE, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&msg_peer_id, {
				"PEER_ID",
				"qora.msg.peer_id",
				FT_NONE, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&msg_proof, {
				"PROOF",
				"qora.msg.proof",
				FT_NONE, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&msg_peers_v2, {
				"PEERS_V2",
				"qora.msg.peers_v2",
				FT_NONE, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&msg_get_block_summaries, {
				"GET_BLOCK_SUMMARIES",
				"qora.msg.get_block_summaries",
				FT_NONE, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&msg_block_summaries, {
				"BLOCK_SUMMARIES",
				"qora.msg.block_summaries",
				FT_NONE, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&msg_get_signatures_v2, {
				"GET_SIGNATURES_V2",
				"qora.msg.get_signatures_v2",
				FT_NONE, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&msg_height_v2, {
				"HEIGHT_V2",
				"qora.msg.height_v2",
				FT_NONE, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&msg_get_transaction, {
				"GET_TRANSACTION",
				"qora.msg.get_transaction",
				FT_NONE, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&msg_transaction_signatures, {
				"TRANSACTION_SIGNATURES",
				"qora.msg.transaction_signatures",
				FT_NONE, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&msg_get_online_accounts, {
				"GET_ONLINE_ACCOUNTS",
				"qora.msg.get_online_accounts",
				FT_NONE, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&msg_online_accounts, {
				"ONLINE_ACCOUNTS",
				"qora.msg.online_accounts",
				FT_NONE, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		}
	};

	static gint *ett[] = {
		&ett_qora,
		&ett_qora_sub
	};

	static ei_register_info ei[] = {
			{ &ei_qora_late_reply, { "qora.late_reply", PI_SEQUENCE, PI_WARN, "Late Reply", EXPFILL }},
			{ &ei_qora_missing_reply, { "qora.missing_reply", PI_SEQUENCE, PI_WARN, "Missing Reply", EXPFILL }}
	};

	proto_qora = proto_register_protocol(
		"qora-core P2P protocol",
		"qora-core",
		"qora"
	);

	proto_register_field_array(proto_qora, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_module_t* expert_qora = expert_register_protocol(proto_qora);
	expert_register_field_array(expert_qora, ei, array_length(ei));
}

void proto_reg_handoff_qora(void) {
	static dissector_handle_t qora_handle;

	qora_handle = create_dissector_handle(dissect_qora, proto_qora);
	dissector_add_uint("tcp.port", QORA_PORT, qora_handle);
}

