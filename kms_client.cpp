#include "kms_client.h"
#include <dns_client.h>

void KMSClient::consider_endpoint_activity(const HTTPClient::request *const req) {
        [[maybe_unused]] const auto &host = req->connection->endpoint->host;
        fault_cnt                         = 0;
}

void KMSClient::configure_http_client() {
        // We are accesinng KMS instances via a load balancer with a single IP address(endpoint)
        // so if e.g a connection fails because one of the KMS instances is stopped while a connection
        // is being processes, the client will 'forget' the endpoint, which means there will
        // be no other endpoints to connect to(it would have been fine if the client was accessing all
        // different KMS instances individually).
        //
        //XXX: The current solution is kind of naive
        http_client.behavior.addrFallbackProvider = [this](const auto &host, uint32_t *const out) {
                bool succ;

                if (fault_cnt > 8) {
                        // abort it
                        fault_cnt = 0;
                        return 0;
                } else if (++fault_cnt > 4) {
                        Timings::Seconds::Sleep(1);
                }

                if (const auto addr4 = URL::ParseHostAddress(host.name, succ); succ) {
                        out[1] = addr4;
                        Timings::Milliseconds::Sleep(100);
                        return 1;
                } else {
                        static thread_local DNSClient dns_client;
                        char                          buf[2048];

                        if (DNSClient dns_client; const auto *q = dns_client.ResolveByNameEx(host.name, DNSClient::Query::A, buf, 2, sizeof(buf))) {
                                uint8_t n{0};

                                do {
                                        if (q->rType == DNSClient::Query::A && q->rLen == sizeof(uint32_t)) {
                                                out[n++] = *reinterpret_cast<const uint32_t *>(q->rVal);
                                        }

                                } while (n < 128 && (q = q->next));

                                if (n)
                                        Timings::Milliseconds::Sleep(100);
                        }
                }

                return 0;
        };
}

void KMSClient::set_kms_endpoint(const str_view32 e) {
        endpoint.port = 8282;
        endpoint.hostname.clear();
        if (const auto p = e.Search(':')) {
                endpoint.port = e.SuffixFrom(p + 1).as_uint32();
                if (!endpoint.port)
                        throw Switch::data_error("Unexpected endpoint");

                endpoint.hostname.append(e.PrefixUpto(p));
        } else
                endpoint.hostname.append(e);

        if (endpoint.hostname.empty())
                throw Switch::data_error("Unexpected endpoint");
}

std::unordered_map<str_view8, str_view8> KMSClient::assign(const std::vector<str_view8> &input) {
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
                if (!auth_token_base64.empty()) {
                        buf->append("Authorization: KMS "_s32, auth_token_base64.as_s32(), '\n');
                }
                buf->append("Content-Length: "_s32);

                const auto clo = buf->size();
                buf->append("                \r\n\r\n"_s32);

                const auto body_offset = buf->size();

                for (const auto &it : input)
                        buf->append(it, '\n');

                const auto content_len = buf->size() - body_offset;

                buf->data()[clo + sprintf(buf->data() + clo, "%u", content_len)] = ' ';
        };

        api->faultHandler = [&succ, this](auto req, const auto fault) {
                SLog("Unexpected fault ", unsigned(fault), " ", *req->url, ":", http_client.last_error().as_s32(), "\n");
                succ = false;
        };

        api->responseHeadersHandler = [this, &succ](auto req, auto &headers) {
                consider_endpoint_activity(req);
                if (req->ResponseCode() != 200) {
                        succ = false;
                        SLog("Unexpected response code for ", *req->url, " ", req->ResponseCode(), "\n");
                } else {
                        succ = true;
                }
        };

        api->allContentConsumer = [&succ, &res, this](auto req, const auto &content) {
                if (req->ResponseCode() != 200) {
                        succ = false;
                        return;
                }

                for (const auto line : content.Split('\n')) {
                        const auto[objid, unwrapped_key_base64] = line.Divided(' ');

                        if (objid && unwrapped_key_base64) {
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
        else {
                req.release();
                http_client.Run();

                if (!succ)
                        throw Switch::data_error("Failed to update KMS:assign");
        }

        return res;
}

void KMSClient::erase_keys(const std::vector<str_view8> &input) {
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
                if (!auth_token_base64.empty()) {
                        buf->append("Authorization: KMS "_s32, auth_token_base64.as_s32(), '\n');
                }
                buf->append("Content-Length: "_s32);

                const auto clo = buf->size();
                buf->append("                \r\n\r\n"_s32);

                const auto body_offset = buf->size();

                for (const auto &it : input)
                        buf->append(it, '\n');

                const auto content_len = buf->size() - body_offset;

                buf->data()[clo + sprintf(buf->data() + clo, "%u", content_len)] = ' ';
        };

        api->faultHandler = [&succ, this](auto req, const auto fault) {
                SLog("Unexpected fault ", unsigned(fault), " ", *req->url, ":", http_client.last_error().as_s32(), "\n");
                succ = false;
        };

        api->responseHeadersHandler = [this, &succ](auto req, auto &headers) {
                consider_endpoint_activity(req);
                if (req->ResponseCode() != 200) {
                        succ = false;
                        SLog("Unexpected response code for ", *req->url, " ", req->ResponseCode(), "\n");
                } else {
                        succ = true;
                }
        };

        api->allContentConsumer = [&succ](auto req, const auto &content) {
                if (req->ResponseCode() != 200) {
                        succ = false;
                        return;
                }
        };

        if (!http_client.Submit(req.get()))
                throw Switch::data_error("Failed to contact KMS -- cannot submit URL");
        else {
                req.release();
                http_client.Run();

                if (!succ)
                        throw Switch::data_error("Failed to interface with KMS:erase_keys");
        }
}

std::unordered_map<str_view8, str_view8> KMSClient::get_keys(const std::vector<str_view8> &input) {
        std::unordered_map<str_view8, str_view8> res;

        if (input.empty())
                return res;

        URL url(_S("https"),
                endpoint.hostname.data(),
                endpoint.hostname.size(),
                _S("/get_keys"));

        url.SetPort(endpoint.port);

        auto   req = std::make_unique<HTTPClient::request>("POST", url);
        auto   api = req->OwnAPI();
        bool   succ{false};
        Buffer eb;

        allocator.reuse();

        api->requestsBuilder = [this, &input](auto req, auto buf) {
                HTTPClient::BuildHTTPRequestMainHeaders(req, buf);
                buf->append("X-Auth: PHAISTOS\r\n"_s32);
                if (!auth_token_base64.empty()) {
                        buf->append("Authorization: KMS "_s32, auth_token_base64.as_s32(), '\n');
                }
                buf->append("Content-Length: "_s32);

                const auto clo = buf->size();
                buf->append("                \r\n\r\n"_s32);

                const auto body_offset = buf->size();

                for (const auto &it : input)
                        buf->append(it, '\n');

                const auto content_len = buf->size() - body_offset;

                buf->data()[clo + sprintf(buf->data() + clo, "%u", content_len)] = ' ';
        };

        api->faultHandler = [&eb, &succ, this](auto req, const auto fault) {
                SLog("Unexpected fault ", unsigned(fault), " ", *req->url, ":", http_client.last_error().as_s32(), "\n");
                eb.append("fault ", unsigned(fault), ":", http_client.last_error().as_s32());
                succ = false;
        };

        api->responseHeadersHandler = [this, &succ, &eb](auto req, auto &headers) {
                consider_endpoint_activity(req);
                if (req->ResponseCode() != 200) {
                        succ = false;
                        eb.append("rc = ", req->ResponseCode());
                        SLog("Unexpected response code for ", *req->url, " ", req->ResponseCode(), "\n");
                } else {
                        succ = true;
                }
        };

        api->allContentConsumer = [&succ, &res, this](auto req, const auto &content) {
                if (req->ResponseCode() != 200) {
                        succ = false;
                        return;
                }

                for (const auto line : content.Split('\n')) {
                        const auto[objid, unwrapped_key_base64] = line.Divided(' ');

                        if (objid && unwrapped_key_base64) {
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
        else {
                req.release();
                http_client.Run();

                if (!succ)
                        throw Switch::data_error("Failed to interface with KMS:get_keys(", eb.as_s32(), ") ", input.size(), " keys");
        }

        return res;
}

std::unordered_map<str_view8, str_view8> KMSClient::unwrap(const std::vector<std::pair<str_view8, str_view8>> &input) {
        std::unordered_map<str_view8, str_view8> res;

        if (input.empty())
                return res;

        URL url(_S("https"),
                endpoint.hostname.data(),
                endpoint.hostname.size(),
                _S("/unwrap"));

        url.SetPort(endpoint.port);

        auto   req = std::make_unique<HTTPClient::request>("POST", url);
        auto   api = req->OwnAPI();
        bool   succ{false};
        Buffer eb;

        allocator.reuse();

        api->requestsBuilder = [this, &input](auto req, auto buf) {

                HTTPClient::BuildHTTPRequestMainHeaders(req, buf);
                buf->append("X-Auth: PHAISTOS\r\n"_s32);
                if (!auth_token_base64.empty()) {
                        buf->append("Authorization: KMS "_s32, auth_token_base64.as_s32(), '\n');
                }
                buf->append("Content-Length: "_s32);

                const auto clo = buf->size();
                buf->append("                \r\n\r\n"_s32);

                const auto body_offset = buf->size();

                for (const auto &it : input) {
                        buf->append(it.first, ' ');

                        // wrapped key will be base64 encoded
                        Base64::Encode(reinterpret_cast<const uint8_t *>(it.second.data()), it.second.size(), buf);
                        buf->append('\n');
                }

                const auto content_len = buf->size() - body_offset;

                buf->data()[clo + sprintf(buf->data() + clo, "%u", content_len)] = ' ';
        };

        api->faultHandler = [&succ, &eb, this](auto req, const auto fault) {
                SLog("Unexpected fault ", unsigned(fault), " ", *req->url, ":", http_client.last_error().as_s32(), "\n");
                eb.append("fault ", unsigned(fault), ":", http_client.last_error().as_s32());
                succ = false;
        };

        api->responseHeadersHandler = [this, &succ, &eb](auto req, auto &headers) {
                consider_endpoint_activity(req);
                if (req->ResponseCode() != 200) {
                        succ = false;
                        eb.append("rc = ", req->ResponseCode());
                        SLog("Unexpected response code for ", *req->url, " ", req->ResponseCode(), "\n");
                } else {
                        succ = true;
                }
        };

        api->allContentConsumer = [&succ, &res, this](auto req, const auto &content) {
                if (req->ResponseCode() != 200) {
                        succ = false;
                        return;
                }

                for (const auto line : content.Split('\n')) {
                        const auto[objid, unwrapped_key_base64] = line.Divided(' ');

                        if (objid && unwrapped_key_base64) {
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
        else {
                req.release();
                http_client.Run();

                if (!succ)
                        throw Switch::data_error("Failed to interface with KMS:unwrap(", eb.as_s32(), ") ", input.size(), " input");
        }

        return res;
}

void KMSClient::set(const std::vector<std::pair<str_view8, str_view8>> &input) {
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

                if (!auth_token_base64.empty()) {
                        buf->append("Authorization: KMS "_s32, auth_token_base64.as_s32(), '\n');
                }

                buf->append("Content-Length: "_s32);

                const auto clo = buf->size();
                buf->append("                \r\n\r\n"_s32);

                const auto body_offset = buf->size();

                for (const auto &it : input) {
                        buf->append(it.first, ' ');

                        // wrapping key will be base64 encoded
                        base64_repr.clear();
                        Base64::Encode(reinterpret_cast<const uint8_t *>(it.second.data()), it.second.size(), UINT32_MAX, buf);
                        buf->append('\n');
                }

                const auto content_len = buf->size() - body_offset;

                buf->data()[clo + sprintf(buf->data() + clo, "%u", content_len)] = ' ';
        };

        api->faultHandler = [&succ, this](auto req, const auto fault) {
                SLog("Unexpected fault ", unsigned(fault), " ", *req->url, ":", http_client.last_error().as_s32(), "\n");
                succ = false;
        };

        api->responseHeadersHandler = [this, &succ](auto req, auto &headers) {
                consider_endpoint_activity(req);
                if (req->ResponseCode() != 200) {
                        succ = false;
                        SLog("Unexpected response code for ", *req->url, " ", req->ResponseCode(), "\n");
                } else {
                        succ = true;
                }
        };

        if (!http_client.Submit(req.get()))
                throw Switch::data_error("Failed to update KMS -- cannot submit URL");
        else {
                req.release();
                http_client.Run();

                if (!succ)
                        throw Switch::data_error("Failed to update KMS:set");
        }
}

#ifdef DBG_KMS_CLIENT
int main(int argc, char *argv[]) {
        uint8_t          data_key[32], wrapping_key[32];
        uint64_t         iv[2];
        const str_view32 data("Lord of the Rings, the return of the King");
        const str_view32 objid("bp.users.64");

#if 1
        {
                KMSClient  client("10.5.5.13:80");
                const auto res = client.get_keys({"foo/bar"_s8});

                SLog("ddone\n");
                return 0;
        }
#endif

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
                    {{objid.as_s8(), {reinterpret_cast<const char *>(wrapping_key), 32}}});

                const auto res = kms_client.unwrap({{objid.as_s8(), wrapped_key.as_s8()}}

                );

                for (const auto &it : res) {
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
