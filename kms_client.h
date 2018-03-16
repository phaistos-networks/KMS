#pragma once
#include <http_client.h>
#include <switch_security.h>
#include <unordered_map>
#include <base64.h>
#include <network.h>


class KMSClient final
{
      private:
        HTTPClient http_client;
	struct
	{
		Buffer hostname;
		uint16_t port;
	} endpoint;
        iconv_t iconv_handle;
        simple_allocator allocator;
        Buffer base64_repr;
	Buffer auth_token_base64;


      public:
        KMSClient(const str_view32 kms_hostname = {"localhost"}, const str_view32 token={})
        {
		set_kms_endpoint(kms_hostname);
                iconv_handle = iconv_open("utf-8", "iso-8859-7");
		if (token)
			set_auth_token(token);
        }

        ~KMSClient()
        {
                iconv_close(iconv_handle);
        }

	void set_kms_endpoint(const str_view32 kms_hostname);

	void set_auth_token(const str_view32 t)
	{
		auth_token_base64.clear();
		//Base64::Encode(reinterpret_cast<const uint8_t *>(t.data()), t.size(), &auth_token_base64);
		auth_token_base64.append(t);
	}

        // input contains pairs of (object id, WRAPPING key)
	// KMS will assign the wrapping key to that object id
	// See /set_keys
        void set(const std::vector<std::pair<str_view8, str_view8>> &input);

	// KMS will create the wrapping key for the object
	// and will return the wrapping key for each such object
        std::unordered_map<str_view8, str_view8> assign(const std::vector<str_view8> &input);

        // input contains pairs of (object id, wrapped key)
	// KMS will fetch the wrapping key from its persistent secure storage for that object id
	// and then unwrap the provided wrapped key to provide us with the unwrapped key
	// see /unwrap
        std::unordered_map<str_view8, str_view8> unwrap(const std::vector<std::pair<str_view8, str_view8>> &input);

        std::unordered_map<str_view8, str_view8> get_keys(const std::vector<str_view8> &);

	void erase_keys(const std::vector<str_view8> &);



	struct Util
	{
		static void build_iv(const str_view8 objid, uint64_t *iv) 
		{
			iv[0] = FNVHash64(reinterpret_cast<const uint8_t *>(objid.data()), objid.size());
			iv[1] = XXH64(objid.data(), objid.size(), 1151);
		}

		static void build_iv(const str_view8 objid, uint8_t *iv) 
		{
			// this is purely a convention
			// for simplicity reasons, ivs will always be derived from the object id
			build_iv(objid, reinterpret_cast<uint64_t *>(iv));
		}

		// this is handy
		// you can e.g use
		// objdata_enc_proxy enc_proxy("bp/users/54"_su8, key_from_ms);
		// const auto email_ciphertext = enc_proxy.encrypt(row[10])
                struct objdata_enc_proxy
                {
                        uint64_t iv[2];
                        uint8_t key[32];

                        objdata_enc_proxy(const str_view8 objid, const uint8_t obj_data_key[32])
                        {
                                build_iv(objid, iv);
                                memcpy(key, obj_data_key, 32); // AES-256
                        }

                        auto encrypt(const str_view32 plaintext) const
                        {
                                return switch_security::ciphers::aes256{{key, 32}, {reinterpret_cast<const uint8_t *>(iv), 16}}.encrypt(plaintext);
                        }
                };

                struct objdata_dec_proxy
                {
                        uint64_t iv[2];
                        uint8_t key[32];

                        objdata_dec_proxy(const str_view8 objid, const uint8_t obj_data_key[32])
                        {
                                build_iv(objid, iv);
                                memcpy(key, obj_data_key, 32); // AES-256
                        }

                        auto decrypt(const str_view32 ciphertext) const
                        {
                                return ciphertext ? switch_security::ciphers::aes256{{key, 32}, {reinterpret_cast<const uint8_t *>(iv), 16}}.decrypt(ciphertext) : Buffer();
                        }
                };
        };
};
