gnutls_crypto_cipher_st *_gnutls_get_crypto_cipher( gnutls_cipher_algorithm_t algo);
gnutls_crypto_digest_st *_gnutls_get_crypto_digest( gnutls_digest_algorithm_t algo);
gnutls_crypto_mac_st *_gnutls_get_crypto_mac( gnutls_mac_algorithm_t algo);
void _gnutls_crypto_deregister(void);
