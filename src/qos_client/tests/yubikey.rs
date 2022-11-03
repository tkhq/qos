// generate encryption key on yubikey

// get the public encryption key

// encrypto to that public key

// get the sender eph key from the encryption envelope

// use the yubikey to compute shared secret with sender eph key

// plug shared secret into p256EncryptPublic::decrypt_with_shared_secret

// confirm the output is correct
