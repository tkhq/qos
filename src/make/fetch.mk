$(FETCH_DIR)/rust.tar:
	$(call fetch_file,RUST_URL,RUST_HASH)

$(FETCH_DIR)/pcsc.tar:
	$(call fetch_file,PCSC_URL,PCSC_HASH)

$(FETCH_DIR)/openssl.tar:
	$(call fetch_file,OPENSSL_URL,OPENSSL_HASH)

#//// OLD


$(FETCH_DIR)/pcsc:
	$(call git_clone,$@,$(PCSC_REPO),$(PCSC_REF))

$(FETCH_DIR)/openssl:
	$(call git_clone,$@,$(OPENSSL_REPO),$(OPENSSL_REF))

$(FETCH_DIR)/rust:
	$(call git_clone,$@,$(RUST_REPO),$(RUST_REF))
