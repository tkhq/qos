.PHONY: keys
keys: \
	$(KEY_DIR)/lrvick.asc \
	$(KEY_DIR)/jkearney.asc \
	$(KEY_DIR)/zmostov.asc

$(KEY_DIR)/lrvick.asc:
	$(call fetch_pgp_key,6B61ECD76088748C70590D55E90A401336C8AAA9)

$(KEY_DIR)/jkearney.asc:
	$(call fetch_pgp_key,6B61ECD76088748C70590D55E90A401336C8AAA9)

$(KEY_DIR)/zmostov.asc:
	$(call fetch_pgp_key,96C422E04DE5D2EE0F7E9E7DBB0DCA38D405491)
