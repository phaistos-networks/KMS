#include "kms_client.h"

void KMSClient::set_kms_endpoint(const str_view32 e)
{
        endpoint.port = 8282;
        endpoint.hostname.clear();
        if (const auto p = e.Search(':'))
        {
                endpoint.port = e.SuffixFrom(p + 1).as_uint32();
                if (!endpoint.port)
                        throw Switch::data_error("Unexpected endpoint");

                endpoint.hostname.append(e.PrefixUpto(p));
        }
        else
                endpoint.hostname.append(e);

        if (endpoint.hostname.empty())
                throw Switch::data_error("Unexpected endpoint");
}

std::unordered_map<str_view8, str_view8> KMSClient::assign(const std::vector<str_view8> &input)
{
	std::unordered_map<str_view8, str_view8> res;

	if (input.empty())
		return res;

	URL url(_S("https"), 
		endpoint.hostname.data(),
		endpoint.hostname.size(),
		_S("/create_keys"));

	url.SetPort(endpoint.port);

	Print(url, "\n");

	auto req = std::make_unique<HTTPClient::request>("POST", url);
	auto api = req->OwnAPI();
	bool succ{false};

	allocator.reuse();
	api->requestsBuilder = [this, &input](auto req, auto buf) {

		HTTPClient::BuildHTTPRequestMainHeaders(req, buf);
		buf->append("X-Auth: PHAISTOS\r\n"_s32);
		if (!auth_token_base64.empty())
		{
			buf->append("Authorization: KMS "_s32, auth_token_base64.as_s32(), '\n');
		}
		buf->append("Content-Length: "_s32);

		const auto clo = buf->size();
		buf->append("                \r\n\r\n");

		const auto body_offset = buf->size();

		for (const auto &it : input)
			buf->append(it, '\n');

		const auto content_len = buf->size() - body_offset;

		buf->data()[clo + sprintf(buf->data() + clo, "%u", content_len)] = ' ';
	};

	api->faultHandler = [&succ](auto req, const auto fault) {
		SLog("Failed ", unsigned(fault), "\n");
		succ = false;
	};

	api->responseHeadersHandler = [&succ](auto req, auto &headers) {
		if (req->ResponseCode() != 200)
		{
			succ = false;
			SLog("Unexpected response code for ", *req->url, " ", req->ResponseCode(), "\n");
		}
		else
		{
			succ = true;
		}
	};

	api->allContentConsumer = [&succ, &res, this](auto req, const auto &content) {
		if (req->ResponseCode() != 200)
		{
			succ = false;
			return;
		}

		for (const auto line : content.Split('\n'))
		{
			const auto [objid, unwrapped_key_base64] = line.Divided(' ');

			if (objid && unwrapped_key_base64)
			{
				base64_repr.clear();
				Base64::Decode(reinterpret_cast<const uint8_t *>(unwrapped_key_base64.data()), unwrapped_key_base64.size(), &base64_repr);

				const auto unwrapped_key = base64_repr.as_s8();

				res.insert({{allocator.CopyOf(objid.data(), objid.size()), objid.size()},
						{allocator.CopyOf(unwrapped_key.data(), unwrapped_key.size()), unwrapped_key.size()}});
			}
		}
	};

	if (!http_client.Submit(req.get()))
		throw Switch::data_error("Failed to update KMS -- cannot submit URL");
	else
	{
		req.release();
		http_client.Run();

		if (!succ)
			throw Switch::data_error("Failed to update KMS");
	}

	return res;
}

void KMSClient::erase_keys(const std::vector<str_view8> &input)
{
        if (input.empty())
                return;

        URL url(_S("https"),
                endpoint.hostname.data(),
                endpoint.hostname.size(),
                _S("/delete_keys"));

        url.SetPort(endpoint.port);

        auto req = std::make_unique<HTTPClient::request>("POST", url);
        auto api = req->OwnAPI();
        bool succ{false};

        allocator.reuse();
        api->requestsBuilder = [this, &input](auto req, auto buf) {
                HTTPClient::BuildHTTPRequestMainHeaders(req, buf);
                buf->append("X-Auth: PHAISTOS\r\n"_s32);
                if (!auth_token_base64.empty())
                {
                        buf->append("Authorization: KMS "_s32, auth_token_base64.as_s32(), '\n');
                }
                buf->append("Content-Length: "_s32);

                const auto clo = buf->size();
                buf->append("                \r\n\r\n");

                const auto body_offset = buf->size();

                for (const auto &it : input)
                        buf->append(it, '\n');

                const auto content_len = buf->size() - body_offset;

                buf->data()[clo + sprintf(buf->data() + clo, "%u", content_len)] = ' ';
        };

        api->faultHandler = [&succ](auto req, const auto fault) {
                SLog("Unexpected fault ", unsigned(fault), " ", *req->url, "\n");
                succ = false;
        };

        api->responseHeadersHandler = [&succ](auto req, auto &headers) {
                if (req->ResponseCode() != 200)
                {
                        succ = false;
                        SLog("Unexpected response code for ", *req->url, " ", req->ResponseCode(), "\n");
                }
                else
                {
                        succ = true;
                }
        };

        api->allContentConsumer = [&succ](auto req, const auto &content) {
                if (req->ResponseCode() != 200)
                {
                        succ = false;
                        return;
                }
        };

        if (!http_client.Submit(req.get()))
                throw Switch::data_error("Failed to contact KMS -- cannot submit URL");
        else
        {
                req.release();
                http_client.Run();

                if (!succ)
                        throw Switch::data_error("Failed to interface KMS");
        }
}

std::unordered_map<str_view8, str_view8> KMSClient::get_keys(const std::vector<str_view8> &input)
{
	std::unordered_map<str_view8, str_view8> res;

	if (input.empty())
		return res;

	URL url(_S("https"), 
		endpoint.hostname.data(),
		endpoint.hostname.size(),
		_S("/get_keys"));

	url.SetPort(endpoint.port);

	auto req = std::make_unique<HTTPClient::request>("POST", url);
	auto api = req->OwnAPI();
	bool succ{false};

	allocator.reuse();
	api->requestsBuilder = [this, &input](auto req, auto buf) {
		HTTPClient::BuildHTTPRequestMainHeaders(req, buf);
		buf->append("X-Auth: PHAISTOS\r\n"_s32);
		if (!auth_token_base64.empty())
		{
			buf->append("Authorization: KMS "_s32, auth_token_base64.as_s32(), '\n');
		}
		buf->append("Content-Length: "_s32);

		const auto clo = buf->size();
		buf->append("                \r\n\r\n");

		const auto body_offset = buf->size();

		for (const auto &it : input)
			buf->append(it, '\n');

		const auto content_len = buf->size() - body_offset;

		buf->data()[clo + sprintf(buf->data() + clo, "%u", content_len)] = ' ';
	};

	api->faultHandler = [&succ](auto req, const auto fault) {
		SLog("Unexpected fault ", unsigned(fault),  " ", *req->url, "\n");
		succ = false;
	};

	api->responseHeadersHandler = [&succ](auto req, auto &headers) {
		if (req->ResponseCode() != 200)
		{
			succ = false;
			SLog("Unexpected response code for ", *req->url, " ", req->ResponseCode(), "\n");
		}
		else
		{
			succ = true;
		}
	};

	api->allContentConsumer = [&succ, &res, this](auto req, const auto &content) {
		if (req->ResponseCode() != 200)
		{
			succ = false;
			return;
		}

		for (const auto line : content.Split('\n'))
		{
			const auto [objid, unwrapped_key_base64] = line.Divided(' ');

			if (objid && unwrapped_key_base64)
			{
				base64_repr.clear();
				Base64::Decode(reinterpret_cast<const uint8_t *>(unwrapped_key_base64.data()), unwrapped_key_base64.size(), &base64_repr);

				const auto unwrapped_key = base64_repr.as_s8();

				res.insert({{allocator.CopyOf(objid.data(), objid.size()), objid.size()},
						{allocator.CopyOf(unwrapped_key.data(), unwrapped_key.size()), unwrapped_key.size()}});
			}
		}
	};

	if (!http_client.Submit(req.get()))
		throw Switch::data_error("Failed to contact KMS -- cannot submit URL");
	else
	{
		req.release();
		http_client.Run();

		if (!succ)
			throw Switch::data_error("Failed to interface KMS");
	}

	return res;
}

std::unordered_map<str_view8, str_view8> KMSClient::unwrap(const std::vector<std::pair<str_view8, str_view8>> &input)
{
	std::unordered_map<str_view8, str_view8> res;

	if (input.empty())
		return res;

	URL url(_S("https"), 
		endpoint.hostname.data(),
		endpoint.hostname.size(),
		_S("/unwrap"));

	url.SetPort(endpoint.port);

	auto req = std::make_unique<HTTPClient::request>("POST", url);
	auto api = req->OwnAPI();
	bool succ{false};

	allocator.reuse();
	api->requestsBuilder = [this, &input](auto req, auto buf) {

		HTTPClient::BuildHTTPRequestMainHeaders(req, buf);
		buf->append("X-Auth: PHAISTOS\r\n"_s32);
		if (!auth_token_base64.empty())
		{
			buf->append("Authorization: KMS "_s32, auth_token_base64.as_s32(), '\n');
		}
		buf->append("Content-Length: "_s32);

		const auto clo = buf->size();
		buf->append("                \r\n\r\n");

		const auto body_offset = buf->size();

		for (const auto &it : input)
		{
			buf->append(it.first, ' ');

			// wrapped key will be base64 encoded
			Base64::Encode(reinterpret_cast<const uint8_t *>(it.second.data()), it.second.size(), buf);
			buf->append('\n');
		}

		const auto content_len = buf->size() - body_offset;

		buf->data()[clo + sprintf(buf->data() + clo, "%u", content_len)] = ' ';
	};

	api->faultHandler = [&succ](auto req, const auto fault) {
		SLog("Unexpected fault ", unsigned(fault),  " ", *req->url, "\n");
		succ = false;
	};

	api->responseHeadersHandler = [&succ](auto req, auto &headers) {
		if (req->ResponseCode() != 200)
		{
			succ = false;
			SLog("Unexpected response code for ", *req->url, " ", req->ResponseCode(), "\n");
		}
		else
		{
			succ = true;
		}
	};

	api->allContentConsumer = [&succ, &res, this](auto req, const auto &content) {
		if (req->ResponseCode() != 200)
		{
			succ = false;
			return;
		}

		for (const auto line : content.Split('\n'))
		{
			const auto [objid, unwrapped_key_base64] = line.Divided(' ');

			if (objid && unwrapped_key_base64)
			{
				base64_repr.clear();
				Base64::Decode(reinterpret_cast<const uint8_t *>(unwrapped_key_base64.data()), unwrapped_key_base64.size(), &base64_repr);

				const auto unwrapped_key = base64_repr.as_s8();

				res.insert({{allocator.CopyOf(objid.data(), objid.size()), objid.size()},
						{allocator.CopyOf(unwrapped_key.data(), unwrapped_key.size()), unwrapped_key.size()}});
			}
		}
	};

	if (!http_client.Submit(req.get()))
		throw Switch::data_error("Failed to contact KMS -- cannot submit URL");
	else
	{
		req.release();
		http_client.Run();

		if (!succ)
			throw Switch::data_error("Failed to interface KMS");
	}

	return res;
}

void KMSClient::set(const std::vector<std::pair<str_view8, str_view8>> &input)
{
        if (input.empty())
                return;

	URL url(_S("https"), 
		endpoint.hostname.data(),
		endpoint.hostname.size(),
		_S("/set_keys"));

	url.SetPort(endpoint.port);

        auto req = std::make_unique<HTTPClient::request>("POST", url);
        auto api = req->OwnAPI();
        bool succ{false};

        api->requestsBuilder = [&input, this](auto req, auto buf) {
                HTTPClient::BuildHTTPRequestMainHeaders(req, buf);
                buf->append("X-Auth: PHAISTOS\r\n"_s32);

		if (!auth_token_base64.empty())
		{
			buf->append("Authorization: KMS "_s32, auth_token_base64.as_s32(), '\n');
		}

                buf->append("Content-Length: "_s32);

                const auto clo = buf->size();
                buf->append("                \r\n\r\n");

                const auto body_offset = buf->size();

                for (const auto &it : input)
                {
                        buf->append(it.first, ' ');

                        // wrapping key will be base64 encoded
                        base64_repr.clear();
                        Base64::Encode(reinterpret_cast<const uint8_t *>(it.second.data()), it.second.size(), UINT32_MAX, buf);
                        buf->append('\n');
                }

                const auto content_len = buf->size() - body_offset;

                buf->data()[clo + sprintf(buf->data() + clo, "%u", content_len)] = ' ';
        };

        api->faultHandler = [&succ](auto req, const auto fault) {
                succ = false;
        };

        api->responseHeadersHandler = [&succ](auto req, auto &headers) {
                if (req->ResponseCode() != 200)
                {
                        succ = false;
                        SLog("Unexpected response code for ", *req->url, " ", req->ResponseCode(), "\n");
                }
                else
                {
                        succ = true;
                }
        };

        if (!http_client.Submit(req.get()))
                throw Switch::data_error("Failed to update KMS -- cannot submit URL");
        else
        {
                req.release();
                http_client.Run();

                if (!succ)
                        throw Switch::data_error("Failed to update KMS");
        }
}

#ifdef DBG_KMS_CLIENTY
int main(int argc, char *argv[])
{
        uint8_t data_key[32], wrapping_key[32];
        uint64_t iv[2];
        const str_view32 data("Lord of the Rings, the return of the King");
        const str_view32 objid("bp.users.64");

#pragma WRITE
        // Generate a data key
        switch_security::gen_rnd(32, data_key);
        // Generate a (matching) wrapping key
        switch_security::gen_rnd(32, wrapping_key);

	// iv is derived from the object-id
	KMSClient::Util::build_iv(objid.as_s8(), iv);

        // Encrypt the data using the data key
        auto encrypted_data = switch_security::ciphers::aes256{{data_key, 32}, {reinterpret_cast<const uint8_t *>(iv), 16}}.encrypt(data);

        // Now encrypt the data key with the wrapping key to produce the wrapped key
        auto wrapped_key = switch_security::ciphers::aes256{{wrapping_key, 32}, {reinterpret_cast<const uint8_t *>(iv), 16}}.encrypt(str_view32(reinterpret_cast<const char *>(data_key), 32));

	{
		KMSClient kms_client;

		kms_client.set(
		{
			{objid.as_s8(), { reinterpret_cast<const char *>(wrapping_key), 32 }}
		}
		);


		const auto res = kms_client.unwrap( {
			{objid.as_s8(), wrapped_key.as_s8()}
		}
		
		);

		for (const auto &it : res)
		{
			SLog("Unwrapped ", it.first, " ", it.second.size(), "\n");
		}
	}

#pragma READ
	// Client provides (objid, wrapped_key)
	
	// Fetch the wrapping_key from somewhere(it should have been encrypted there)
	
	// Decrypt the wrapped key to get the data key
	const auto unwrapped_key = switch_security::ciphers::aes256{{wrapping_key, 32}, {reinterpret_cast<const uint8_t *>(iv), 16}}.decrypt(wrapped_key.as_s32());

	// Decrypt the data with the unwrapped key
	const auto decrypted_data = switch_security::ciphers::aes256{{reinterpret_cast<const uint8_t *>(unwrapped_key.data()), 32}, {reinterpret_cast<const uint8_t *>(iv), 16}}.decrypt(encrypted_data.as_s32());

	
	SLog("OK [", decrypted_data, "]\n");
        return 0;
}
#endif
