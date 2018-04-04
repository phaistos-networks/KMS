// KMS: A simple Keys management service
// (C) Phaistos Networks, S.A.
#include "sss/sss.h"
#include <base64.h>
#include <data.h>
#include <ext/tl/optional.hpp>
#include <network.h>
#include <switch.h>
#include <switch_security.h>
#include <sys/mman.h>
#ifndef SWITCH_MIN
#include <overseer_client.h>
#include <switch_rpc.h>
#include <switch_url.h>
#include <tls.h>
#else
#include <compress.h>
#include <ext/json.hpp>
#include <network.h>
#include <openssl/bio.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslconf.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <switch_hash.h>
#include <switch_mallocators.h>
#include <text.h>
#endif
#include <net/if.h>
#include <sys/ioctl.h>
#include <system_error>
#include <unordered_map>

static constexpr bool        dev_mode{true}; // enable it for development
static constexpr std::size_t max_masterkey_shares{16};

struct authenticated_session final {
        uint32_t account_id;
        uint32_t lease_exp_ts;
        uint32_t token_exp_ts;
};

struct connection final {
        int fd; // must be first field in the struct

        IOBuffer *inb{nullptr}, *outb{nullptr};
        SSL *     ssl{nullptr};
        time_t    last_activity;

        ~connection() {
                if (ssl)
                        SSL_free(ssl);
        }

        struct
        {
                struct iovec data[128];
                uint16_t     size{0};
                uint16_t     idx{0};
                bool         need_patch{false};

                auto reserve() {
                        require(size != sizeof_array(data));
                        return data + (size++);
                }

                auto append(const char *p, const std::size_t len) {
                        require(size != sizeof_array(data));

                        data[size] = iovec{(void *)p, len};
                        return data + (size++);
                }

                auto append(const str_view32 s) {
                        return append(s.data(), s.size());
                }

                void set_range(const range32_t range, struct iovec *iv) {
                        need_patch   = true;
                        iv->iov_base = (void *)uintptr_t(range.offset);
                        iv->iov_len  = range.size() | (1u << 30);
                }

                auto append_range(const range32_t range) {
                        require(size != sizeof_array(data));
                        set_range(range, data + size);
                        return data + (size++);
                }
        } iov;

        enum class Flags : uint8_t {
                need_outavail      = 1,
                state_have_headers = 1 << 1,
                shutdown_onflush   = 1 << 2,

                tls_want_read   = 1 << 3,
                tls_want_write  = 1 << 4,
                tls_want_accept = 1 << 5,
                tls_accept_ok   = 1 << 6,
        };

        uint32_t flags{0};

        struct
        {
                struct
                {
                        uint32_t   content_length;
                        str_view32 method, path;
                        bool       expect_connection_close;

                        tl::optional<authenticated_session> auth;
                } cur_req;

        } state;

        inline bool is_root() const noexcept {
                return state.cur_req.auth && state.cur_req.auth.value().account_id == 0;
        }

        connection(int fd_)
            : fd{fd_} {
        }
};

static void wrapping_key_from_master_key(const uint8_t master_key[sss_MLEN], uint8_t wrapping_key[32]) {
        // switch_security::hmac with EVP_sha256 is suitable(because it produces a 256-bit digest, and our wrapping key must be 256-bits)
        // Or maybe, for the extra effort, switch_security::hmac::PBKDF2 should be used instad
        // where salt is something reasonable.
        //
        // For now, we 'll use an HMAC
        // XXX: what are we going to use for the key of this hmac? whatever it is, it needs to be
        // non-legible so that e.g someone won't just use strings(1) to extract all strings from the binary
        // (although the binary should only be readable by root anyway)
        switch_security::hmac hmac(EVP_sha256(), _S("foo.key"));

        hmac.update(master_key, sss_MLEN);
        hmac.finalize(wrapping_key);
}

static bool verify_secret_prop_name(const str_view32 prop) noexcept {
        if (!prop.size() || prop.size() > 64)
                return false;

        for (const auto *p = prop.data(), *const e = p + prop.size(); p != e; ++p) {
                if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || *p == '_') {
                        // accept
                } else
                        return false;
        }

        return true;
}

// Verifies a key name, or otherwise known as an object id
// root/sub/sub/sub...
static bool verify_objid(const str_view32 s) noexcept {
        static constexpr bool trace{false};

        if (s.size() < 2 || s.size() > 128 || s.front() == '/' || s.back() == '/') {
                if (trace)
                        SLog("Invalid key name[", s, "]\n");

                return false;
        }

        std::size_t components{0};

        for (const auto *p = s.data(), *const e = p + s.size(); p != e; ++p) {
                if (*p == '/') {
                        if (p[-1] == '/') {
                                if (trace)
                                        SLog("Invalid key name[", s, "]\n");

                                return false;
                        } else
                                ++components;
                } else if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || *p == '_') {
                        // accept
                } else {
                        if (trace)
                                SLog("Invalid key name[", s, "]\n");

                        return false;
                }
        }

        return components && components < 16;
}

namespace {
        // The IV we use for encrypting/decrypting keys we manage is based on their key name
        // This is the iv[] we will use for encrypting/decrypting managed keys(i.e key => manged key) -- the encrypted keys
        // are stored in the backing store
        //
        // We use the same iv[] for encrypting/decrypting arbitrary (plaintext or ciphertext) content
        // and by extension, for wrap/unwrap operations, for the provided *wrapped* key
        void build_iv(const str_view32 keyname, uint64_t iv[]) {
                iv[0] = FNVHash64(reinterpret_cast<const uint8_t *>(keyname.data()), keyname.size());
                iv[1] = XXH64(keyname.data(), keyname.size(), 1151);
        }

        void build_iv(const str_view32 keyname, uint8_t iv[16]) {
                build_iv(keyname, reinterpret_cast<uint64_t *>(iv));
        }
} // namespace

int main(int argc, char *argv[]) {

        [[maybe_unused]] const auto verify_ownership = [](const auto path) {
                struct stat64 s;

                if (-1 == stat64(path, &s)) {
                        Print("Failed to authorize user: unable to stat file:", strerror(errno), "\n");
                        return false;
                }

                if (s.st_uid) {
                        Print("Failed to authorize user. ", path, " owner is not root\n");
                        return false;
                }

                if (s.st_mode & S_IRWXO) {
                        // Others cannot possibly read, write, or execute this binary
                        Print("Failed to authorize user. Unexpected file permissions for ", path, "\n");
                        return false;
                }

                return true;
        };

        // Select an ip4 address from one of the network interaces.
        // Choose based on a simple heuristic
        [[maybe_unused]] const auto main_if_ipaddr4 = []() -> uint32_t {
                struct ifconf       ifc;
                struct ifreq        ifreqs[128];
                const struct ifreq *sel{nullptr};
                int                 sel_idx;

                memset(&ifc, 0, sizeof(ifc));
                ifc.ifc_len = sizeof(ifreqs);
                ifc.ifc_buf = reinterpret_cast<char *>(&ifreqs);

                int fd = socket(AF_INET, SOCK_DGRAM, 0);

                if (fd == -1)
                        throw std::system_error(errno, std::system_category());

                if (ioctl(fd, SIOCGIFCONF, &ifc) == -1) {
                        close(fd);
                        throw std::system_error(errno, std::system_category());
                }

                for (const auto *it = ifreqs, *const e = it + ifc.ifc_len / sizeof(ifreq); it != e; ++it) {
                        if (ioctl(fd, SIOCGIFFLAGS, it) == -1)
                                continue;

                        if ((it->ifr_flags & (IFF_UP | IFF_LOOPBACK)) == IFF_UP) {
                                if (ioctl(fd, SIOCGIFBRDADDR, it) == -1)
                                        continue;

                                const auto s             = reinterpret_cast<const sockaddr_in *>(&it->ifr_addr);
                                const auto broadcast_ip4 = *reinterpret_cast<const uint32_t *>(&s->sin_addr.s_addr);

                                if (broadcast_ip4 == INADDR_ANY)
                                        continue;

                                if (ioctl(fd, SIOCGIFINDEX, it) == -1)
                                        continue;

                                if (!sel || (it->ifr_ifindex < sel_idx || strlen(it->ifr_name) < strlen(sel->ifr_name))) {
                                        sel_idx = it->ifr_ifindex;
                                        sel     = it;
                                }
                        }
                }

                if (sel) {
                        if (ioctl(fd, SIOCGIFADDR, sel) == -1) {
                                close(fd);
                                throw std::system_error(errno, std::system_category());
                        }

                        close(fd);

                        const auto s        = reinterpret_cast<const sockaddr_in *>(&sel->ifr_addr);
                        const auto addr_ip4 = *reinterpret_cast<const uint32_t *>(&s->sin_addr.s_addr);

                        return addr_ip4;
                } else {
                        close(fd);
                        return 0;
                }
        };

        [[maybe_unused]] const auto verify_ownership_with_fd = [](const auto path, auto fd) {
                struct stat s;

                if (-1 == fstat(fd, &s)) {
                        Print("Failed to authorize user: unable to stat file:", strerror(errno), "\n");
                        return false;
                }

                if (s.st_uid) {
                        Print("Failed to authorize user. ", path, " owner is not root\n");
                        return false;
                }

                if (s.st_mode & S_IRWXO) {
                        Print("Failed to authorize user. Unexpected file permissions for ", path, "\n");
                        return false;
                }

                return true;
        };

        if (false == dev_mode) {
                const auto uid = geteuid();

                if (0 != uid) {
                        Print("Unauthorized execution not allowed. KMS requires root access.\n");
                        return 1;
                }

#ifdef MLOCK_ONFAULT
                if (-1 == mlockall(MLOCK_ONFAULT))
#else
                if (-1 == mlockall(MCL_CURRENT | MCL_FUTURE))
#endif
                {
                        Print("System Error: cannot guarantee safety. Cowardly aborting: ", strerror(errno), "\n");
                        return 1;
                }

                // verify that we have the right to do this
                char b[8192];

                if (auto fh = fopen("/proc/self/cmdline", "r"); nullptr == fh) {
                        Print("Failed to authorize user: unable to access /proc/self/cmdline\n");
                        return 1;
                } else if (nullptr == fgets(b, sizeof(b), fh)) {
                        fclose(fh);
                        Print("Failed to authorize user: unable to read /proc/self/cmdline\n");
                        return 1;
                } else {
                        if (!verify_ownership(b /* this works, because command is \0 terminated */))
                                return 1;
                }
        }

        MysqlClient             mysql_client;
        Switch::endpoint        e;
        int                     r;
        uint32_t                now = time(nullptr);
        IOBuffer                base64_buf, tbuf;
        static const str_view32 server_name("Phaistos KMS");
        struct
        {
                struct
                {
                        std::size_t create_keys;
                        std::size_t delete_keys;
                        std::size_t set_keys;
                        std::size_t encrypt;
                        std::size_t decrypt;
                        std::size_t get_keys;
                        std::size_t unwrap;
                        std::size_t get_secrets;
                        std::size_t set_secrets;
                } reqs;
                uint32_t if_addr4;
        } runtime_metrics;
        time_t past{0};

        struct Enclave final {
                simple_allocator allocator;
                // it's important that we get the tokens generation right
                // for now, this will just be unix epoch time
                // but even if someone is messing with the data in an attempt to fool KMS, we will likely still be fine (see build_new_token() impl.)
                uint32_t tokens_sequencer_gen{0};
                uint32_t tokens_sequencer{0};

                uint8_t enc_key[256 / 8]; // AES-256, 8-bytes key
                bool    locked{true};

                struct
                {
                        // used for tokens generation
                        // initialized on startup and is hopefully unique
                        uint64_t session_id;
                } cur_sess;

                struct
                {
                        uint8_t shares_cnt{0};
                        uint8_t master_key_shares_threshold;

                        uint8_t collected{0};
                        Buffer  shares[max_masterkey_shares];

                        // used for encrypting all provided shares
                        // we reset when we get the first share
                        uint8_t enc_key[32] = {0};
                        uint8_t enc_iv[16];

                        struct
                        {
                        } root_token;

                        void reset() {
                                collected = 0;
                                memset(enc_key, 0, sizeof(enc_key));
                                memset(enc_iv, 0, sizeof(enc_iv));
                        }
                } mk_unlock_ctx;

                // a token encodes:
                // - account id:u32
                // - lease expiration:u32
                // - token expiration:u32
                // - seq:u32
                // - gen:u32
                // - hash of KMS instance session digest:u64
                // - digest hash:u64
                //
                // - the digest hash is the hash of (lease expiration, token expiration, seq, gen, KMS enc.key, hash of KMS instance session digest)
                // - instance session digest:u8[16] is initialized once on startup via switch_security::gen_rnd()
                // - we have two different expiration timestamps(lease and token), because when the lease
                //	expires, that's when we check if the token has been revoked, and if not, we create another
                // 	token with a new lease time. By setting short lease times (e.g 1 minute), we can revoke within 1 minute
                // - gen is reset to time(null) on startup, and (gen, seq) are useful because we can rely on them and
                // 	on the hash instance session digest
                //
                // For representation, we 'll just concatenate the fields, then encrypt it using our kms.enc key and will use a base64 representation for it
                void build_token(uint64_t data[7], const uint32_t account_id, const uint32_t lease_exp_ts, const uint32_t token_exp_ts) {
                        const auto seq = ++tokens_sequencer;

                        data[0] = account_id;
                        data[1] = lease_exp_ts;
                        data[2] = token_exp_ts;
                        data[3] = seq;
                        data[4] = tokens_sequencer_gen;
                        data[5] = cur_sess.session_id;

                        uint64_t h = BeginFNVHash64();

                        for (uint32_t i{0}; i != 6; ++i)
                                h = FNVHash64(h, reinterpret_cast<const uint8_t *>(data + i), sizeof(uint64_t));

                        h       = FNVHash64(h, enc_key, 32);
                        data[6] = h;
                }

                tl::optional<authenticated_session> parse_token(const str_view32 repr, const uint32_t now) const {
                        static constexpr bool trace{false};
                        uint64_t              input[8];
                        uint8_t               n{0};

                        if (trace)
                                SLog("Parsing [", repr, "]\n");

                        for (const auto it : repr.Split('-')) {
                                if (it.empty() || it.size() > 64) {
                                        if (trace)
                                                SLog("Unexpected input\n");

                                        return tl::nullopt;
                                } else
                                        input[n++] = Text::FromBase(it.data(), it.size(), 60);
                        }

                        if (n != 7) {
                                if (trace)
                                        SLog("Expected ", n, " segments\n");

                                return tl::nullopt;
                        }

                        if (const auto exp_ts = input[2]; exp_ts && exp_ts < now) {
                                // Expired
                                // TODO: delete from tokens
                                if (trace)
                                        SLog("Expired already (now = ", now, ", exp_ts = ", exp_ts, ")\n");

                                return tl::nullopt;
                        }

                        uint64_t h = BeginFNVHash64();

                        for (uint32_t i{0}; i != 6; ++i)
                                h = FNVHash64(h, reinterpret_cast<const uint8_t *>(input + i), sizeof(uint64_t));

                        h = FNVHash64(h, enc_key, 32);
                        if (h != input[6]) {
                                if (trace)
                                        SLog("Failed to verify hash ", h, " ", input[6], "\n");

                                return tl::nullopt;
                        }

                        if (const auto lease_exp_ts = input[1]; now > lease_exp_ts) {
                                [[maybe_unused]] const auto account_id = input[0];

                                // TODO: check if account_id is in our revoked tokens list
                                // If it is not, see if it's in our database
                                // if it is, make room for it in the in-memory revoked tokens list and reny access
                                // if not, we need to create a new token
                                // with a proper lease. Short leases faciliate frequent checks for revoked tokens
                        }

                        if (trace)
                                SLog("Auth token repr OK\n");

                        return authenticated_session{uint32_t(input[0]), uint32_t(input[1]), uint32_t(input[2])};
                }

                // aa-bb-cc-dd-ee-ff
                static std::size_t token_repr(const uint64_t token[7], char *out) {
                        const auto base{out};

                        out += Text::ToBase(token[0], 60, out);
                        for (uint32_t i{1}; i != 7; ++i) {
                                *out++ = '-';
                                const auto c{out};

                                out += Text::ToBase(token[i], 60, out);
                                // sanity check
                                require(Text::FromBase(c, std::distance(c, out), 60) == token[i]);
                        }

                        return std::distance(base, out);
                }
        } secure_enclave;

        struct token_props final {
                uint8_t                         domains_cnt{0};
                std::pair<str_view8, uint32_t> *domains;
                uint32_t                        last_update{0};

                ~token_props() {
                        while (domains_cnt)
                                std::free((void *)(domains[--domains_cnt].first.data()));
                }
        };

        std::unordered_map<uint32_t, std::unique_ptr<token_props>> tokens_map;
        Buffer                                                     _mc;
        bool                                                       use_http{false};

        if (dev_mode)
                Print("KMS is running in DEVELOPMENT MODE. Please make sure you acknowledge that\n");

        e.unset();
        while ((r = getopt(argc, argv, dev_mode ? "l:M:f:P" : "l:f:P")) != -1) {
                switch (r) {
                        case 'P':
                                use_http = true;
                                break;

                        case 'f': {
                                int fd = open(optarg, O_RDONLY | O_CLOEXEC);

                                if (fd == -1) {
                                        Print("Unable to access ", optarg, ": ", strerror(errno), "\n");
                                        return 1;
                                }

                                if (!dev_mode && !verify_ownership_with_fd(optarg, fd))
                                        return 1;

                                struct vma_dtor {
                                        const off_t size_;

                                        vma_dtor(const off_t size)
                                            : size_{size} {
                                        }

                                        void operator()(void *ptr) {
                                                if (ptr != MAP_FAILED)
                                                        munmap(ptr, size_);
                                        }
                                };

                                const auto                      file_size = lseek(fd, 0, SEEK_END);
                                std::unique_ptr<void, vma_dtor> vma(mmap(nullptr, file_size, PROT_READ, MAP_SHARED, fd, 0), vma_dtor(file_size));

                                close(fd);

                                if (vma.get() == MAP_FAILED) {
                                        Print("System Error:", strerror(errno), "\n");
                                        return 1;
                                }

                                madvise(vma.get(), file_size, MADV_SEQUENTIAL | MADV_DONTDUMP);

                                for (const auto s : str_view32(reinterpret_cast<const char *>(vma.get()), file_size).Split('\n')) {
                                        // no longer treating '#' as a comment, because it may be used in a password
                                        if (const auto l = s.ws_trimmed()) {
                                                //if (const auto l = s.Divided('#').first.ws_trimmed()) {
                                                const auto[n, v] = l.Divided('=');
                                                const auto name  = n.ws_trimmed();
                                                const auto value = v.ws_trimmed();

                                                if (name.Eq(_S("persist.mysql.endpoint"))) {
                                                        _mc.clear();
                                                        _mc.append(value);
                                                } else
                                                        Print("Unsupported configuration option '", name, "'\n");
                                        }
                                }
                        } break;

                        case 'M':
                                if (!dev_mode) {
                                        Print("Not Supported Option\n");
                                        return 1;
                                } else {
                                        // not supposed to use this
                                        // this is for development puproses really
                                        _mc.append(optarg);
                                        break;
                                }

                        case 'l': {
                                const str_view32 repr(optarg);

                                try {
                                        e = Switch::ParseSrvEndpoint(repr, "http"_s8, 80);
                                } catch (...) {
                                        e.unset();
                                }

                                if (!e) {
                                        Print("Unable to parse endpoint from ", repr, "\n");
                                        return 1;
                                }
                        } break;

                        default:
                                return 1;
                }
        }

        argc -= optind;
        argv += optind;

        if (_mc.empty()) {
                char input[512];

                fprintf(stderr, "mySQL endpoint (username:password@host[:port]/databasename): ");
                fgets(input, sizeof(input), stdin);

                _mc.append(input);
#ifndef SWITCH_MIN
                _mc.TrimWS();
#endif
        }

        {
                if (_mc.size() > 255) {
                        Print("Invalid mySQL endpoint: ", _mc, "\n");
                        return 1;
                }

                // user[:password]@endpoint[/database_name]
                const auto[auth, r] = _mc.as_s32().Divided('@');

                if (!auth || !r) {
                        Print("Invalid mySQL endpoint \"", _mc.as_s32(), "\". Expected authentication\n");
                        return 1;
                }

                const auto[endpoint, dbname] = r.Divided('/');

                if (!endpoint || !dbname) {
                        Print("Invalid mySQL endpoint. Expecte database name\n");
                        return 1;
                }

                const auto[hostname, port_repr] = endpoint.Divided(':');
                const uint32_t port             = port_repr ? port_repr.as_uint32() : 3306;
                const auto[username, password]  = auth.Divided(':');

                if (!username) {
                        Print("Invalid mySQL endpoint. Username not specified\n");
                        return 1;
                }

                char hostname_data[0xff], username_data[0xff], password_data[0xff], dbname_data[0xff];

                hostname.ToCString(hostname_data, sizeof(hostname_data));
                username.ToCString(username_data, sizeof(username_data));
                password.ToCString(password_data, sizeof(password_data));
                dbname.ToCString(dbname_data, sizeof(dbname_data));

                try {
                        mysql_client.enable_ssl();
                        mysql_client.connect(hostname_data, username_data, password_data, dbname_data, port, nullptr, 0);
                } catch (...) {
                        Print("Unable to establish secure connection. Aborting\n");
                        return 1;
                }

                mysql_client.exec(R"stmt(CREATE TABLE IF NOT EXISTS `kms_runtime_metrics` ( `ip_addr4` int unsigned not null, `op_create_keys` bigint(20) unsigned NOT NULL, `op_delete_keys` bigint(20) unsigned NOT NULL, `op_set_keys` bigint(20) unsigned NOT NULL, `op_encrypt` bigint(20) unsigned NOT NULL, `op_decrypt` bigint(20) unsigned NOT NULL, `op_get_keys` bigint(20) unsigned NOT NULL, `op_unwrap` bigint(20) unsigned NOT NULL, `op_get_secrets` bigint(20) unsigned NOT NULL, `op_set_secrets` bigint(20) unsigned NOT NULL, PRIMARY KEY(ip_addr4)))stmt"_s32);

                runtime_metrics.if_addr4 = main_if_ipaddr4();

                if (runtime_metrics.if_addr4) {
                        if (auto &&rows = mysql_client.select("SELECT * FROM kms_runtime_metrics WHERE ip_addr4 = "_s32, runtime_metrics.if_addr4); auto &&row = rows.next()) {
                                auto &r{runtime_metrics.reqs};

                                r.create_keys = row[1].as_uint64();
                                r.delete_keys = row[2].as_uint64();
                                r.set_keys    = row[3].as_uint64();
                                r.encrypt     = row[4].as_uint64();
                                r.decrypt     = row[5].as_uint64();
                                r.get_keys    = row[6].as_uint64();
                                r.unwrap      = row[7].as_uint64();
                                r.get_secrets = row[8].as_uint64();
                                r.set_secrets = row[9].as_uint64();
                        } else
                                memset(&runtime_metrics.reqs, 0, sizeof(runtime_metrics.reqs));
                } else {
                        Print("Unable to select a hardware network interface IP4 address for metrics. Will not track metrics\n");
                }
        }

        const auto set_response_connection_header = [](auto c) {
                // TODO: if (c->inb->offset() == c->inb->size()), we have more requests to processs, so maybe we should shutdown the connection
                if ((c->flags & unsigned(connection::Flags::shutdown_onflush)) || c->state.cur_req.expect_connection_close) {
                        c->iov.append("Connection: close\r\n"_s32);
                        c->flags |= unsigned(connection::Flags::shutdown_onflush);
                } else
                        c->iov.append("Connection: keep-alive\r\n"_s32);
        };
        std::vector<IOBuffer *> reusable_bufs;
        const auto              new_buf = [&reusable_bufs]() {
                if (reusable_bufs.empty())
                        return new IOBuffer();

                auto res = reusable_bufs.back();

                reusable_bufs.pop_back();
                return res;
        };
        const auto renew_token = [&](auto c, const uint32_t lease_exp_ts, const uint32_t token_exp_ts) {
                require(c->state.cur_req.auth);

                if (lease_exp_ts >= token_exp_ts) {
                        c->iov.append("X-KMS-SetAuth: \r\n"_s32);
                } else {
                        const auto sess = c->state.cur_req.auth.value();
                        uint64_t   new_auth_token[7];
                        char       token_repr[128];
                        uint8_t    token_iv[16];

                        build_iv("**"_s32, token_iv);
                        secure_enclave.build_token(new_auth_token, sess.account_id, lease_exp_ts, token_exp_ts);

                        const uint32_t token_repr_size = Enclave::token_repr(new_auth_token, token_repr);
                        const auto     wrapped_token   = switch_security::ciphers::aes256{{secure_enclave.enc_key, 32}, {token_iv, 16}}.encrypt({token_repr, token_repr_size});
                        auto           outb            = c->outb ?: (c->outb = new_buf());
                        const auto     o               = outb->size();

                        c->iov.append("X-KMS-SetAuth: "_s32);
                        Base64::Encode(reinterpret_cast<const uint8_t *>(wrapped_token.data()), wrapped_token.size(), outb);

                        c->iov.append_range({o, outb->size() - o});
                        c->iov.append("\r\n"_s32);
                }
        };

        [[maybe_unused]] const auto extend_lease = [&](auto c, const uint32_t extension) {
                require(c->state.cur_req.auth);

                const auto sess = c->state.cur_req.auth.value();

                renew_token(c, std::min<uint32_t>(now + extension, sess.token_exp_ts), sess.token_exp_ts);
        };

        [[maybe_unused]] const auto maybe_extend_lease = [&](auto c) {
                if (c->state.cur_req.auth && !c->is_root()) {
                        if (const auto lease_exp_ts = c->state.cur_req.auth.value().lease_exp_ts; lease_exp_ts < now) {
                                // a minute later
                                extend_lease(c, 60);
                        }
                }
        };

        const auto build_response = [&new_buf, &set_response_connection_header](auto c, const str_view32 resp, const str_view32 msg = {}) {
                if (!msg) {
                        c->iov.append("HTTP/1.1 "_s32);
                        c->iov.append(resp);
                        c->iov.append("\r\nContent-Length: 0\r\nServer: "_s32);
                        c->iov.append(server_name);
                        c->iov.append("\r\n");
                        set_response_connection_header(c);
                        c->iov.append("\r\n"_s32);
                } else {
                        auto outb = c->outb ?: (c->outb = new_buf());

                        c->iov.append("HTTP/1.1 "_s32);
                        c->iov.append(resp);
                        c->iov.append("\r\nContent-Length: "_s32);

                        const auto o{outb->size()};

                        outb->append(msg.size());
                        c->iov.append_range({o, outb->size() - o});

                        c->iov.append("\r\nServer: "_s32);
                        c->iov.append(server_name);
                        c->iov.append("\r\n"_s32);
                        set_response_connection_header(c);
                        c->iov.append("\r\n"_s32);

                        if (IsConstant(msg.data())) {
                                c->iov.append(msg);
                        } else {
                                const auto o2{outb->size()};

                                outb->append(msg);
                                c->iov.append_range({o2, outb->size() - o2});
                        }
                }
        };
        const auto try_unlock = [&](const sss_Share *shares, const std::size_t cnt) {
                uint8_t    restored_master_key[sss_MLEN];
                uint8_t    wrapping_key[32];
                const auto res = sss_combine_shares(restored_master_key, shares, cnt);

                if (0 != res) {
                        Print("Failed to reconstruct master key\n");
                        return false;
                }

                // great, we can now derive a wrapping key
                // from the restored master key, and use that to unwrap the KMS enc.key
                wrapping_key_from_master_key(restored_master_key, wrapping_key);

                // Fetch the wrapped key from the backing store
                try {
                        if (auto rows = mysql_client.select("SELECT k FROM keyring WHERE id = '*'"_s32); auto &&row = rows.next()) {
                                if (row[0].size() < 8) {
                                        // Sanity check
                                        return false;
                                }

                                const auto wrapped_key = row[0].SuffixFrom(2); // skip encoded (total shares, required shares)

                                try {
                                        // decrypt wrapped key using the wrapping key to produce the plaintext(which will be the enc_key)
                                        // the iv is derived from the master key
                                        const uint64_t iv[2]{
                                            FNVHash64(restored_master_key, sss_MLEN),
                                            XXH64(restored_master_key, sss_MLEN, 5022)};
                                        const auto plaintext = switch_security::ciphers::aes256{{wrapping_key, 32}, {reinterpret_cast<const uint8_t *>(iv), 16}}.decrypt(wrapped_key);

                                        if (plaintext.size() != 32) {
                                                Print("Unexpected state: Cowardly rejecting unlock operation (#2)\n");
                                                return false;
                                        }

                                        memcpy(secure_enclave.enc_key, plaintext.data(), plaintext.size());
                                        secure_enclave.locked = false;

                                        Print(ansifmt::bold, ansifmt::color_green, "KMS unlocked", ansifmt::reset, "\n");
                                        return true;
                                } catch (...) {
                                        Print("FAILED to unlock KMS. Unexpected state\n");
                                        return false;
                                }
                        } else {
                                Print("Not initialized yet?\n");
                                return false;
                        }
                } catch (...) {
                        Print("Failed to access `keyring` table. Please make sure you have initialised the mySQL databased used by KMS first.\n");
                        return false;
                }
        };

        secure_enclave.tokens_sequencer_gen = time(nullptr);

        if (argc == 3 && !strcmp(argv[0], "init")) {
                const auto cnt = str_view32(argv[1]).as_uint32();

                if (cnt > max_masterkey_shares || cnt < 1) {
                        Print("Unexpected number of shares requested\n");
                        return 1;
                } else {
                        const auto threshold = str_view32(argv[2]).as_uint32();

                        if (threshold > cnt) {
                                Print("Invalid number of shares required to reconstruct key\n");
                                return 1;
                        } else {
                                if (false == dev_mode) {
                                        if (mysql_client.select("SELECT 1 FROM keyring WHERE id = '*'"_s32).size()) {
                                                Print("Already initialized. Cowardingly aborting\n");
                                                return 1;
                                        }
                                }

                                uint8_t   master_key[sss_MLEN];
                                uint8_t   wrapping_key[32], enc_key[32];
                                uint64_t  enc_key_iv[2];
                                sss_Share shares[cnt]; // this is uint8_t[sss_SHARE_LEN]
                                Buffer    repr;

                                // Let's create the enc.key
                                // This is the key that we will use to encrypt and ecrypt everything in the backing store, except
                                // for the objid identified by '*'
                                switch_security::gen_rnd(32, enc_key);

                                // We will need a root token
                                // create one here, one that never expires
                                char     root_token_repr[256];
                                uint64_t root_token[7];

                                memcpy(secure_enclave.enc_key, enc_key, 32); // because secure_enclave::build_token() requires enc_key
                                secure_enclave.build_token(root_token, 0, 0, 0);

                                const uint32_t root_token_repr_size = Enclave::token_repr(root_token, root_token_repr);

                                // The master key is specifically used to build a wrapping key, which will be used, once, for
                                // encrypting the KMS enc.key
                                // It will be used hence forth for unlocking KMS. That is, we will again derive a wrapping key from
                                // the master key, and we will use that to unwrap the KMS enc.key
                                switch_security::gen_rnd(sss_MLEN, master_key);

                                // We will derive the wrapping key from master key
                                // Because we need a 32-bytes key, we will use salt/digests to get from the sss_MLEN-bytes master key
                                // to a wrapping key.
                                wrapping_key_from_master_key(master_key, wrapping_key);

                                // Encrypt the enc.key with the wrapping key, and *store* the wrapped KMS enc.key somewhere
                                // the iv depends on the master_key.
                                enc_key_iv[0] = FNVHash64(master_key, sss_MLEN);
                                enc_key_iv[1] = XXH64(master_key, sss_MLEN, 5022);

                                const auto wrapped_enc_key = switch_security::ciphers::aes256{{wrapping_key, 32}, {reinterpret_cast<uint8_t *>(enc_key_iv), 16}}
                                                                 .encrypt(str_view32(reinterpret_cast<const char *>(enc_key), 32));

                                // we also include (cnt, threshold)
                                // encoded as the first characters of the row
                                // it's fine if someone accesses it anyway, because that's just two numbers
                                // TODO: consider alternative ways to store those
                                mysql_client.begin();
                                mysql_client.exec("REPLACE INTO keyring VALUES ('*', '", char('a' + cnt), char('a' + threshold), escaped_repr(wrapped_enc_key.as_s32()), "')");

                                // Another for the root token
                                // We will encrypt it using our KMS enc.key
                                // and the IV[] just depends on the key name which is "**"
                                // we will encrypt it, and then base64 encode it
                                uint8_t root_token_iv[16];
                                Buffer  wrapped_root_token_base64;

                                build_iv("**"_s32, root_token_iv);

                                const auto wrapped_root_token = switch_security::ciphers::aes256{{enc_key, 32}, {root_token_iv, 16}}.encrypt({root_token_repr, root_token_repr_size});

                                Base64::Encode(reinterpret_cast<const uint8_t *>(wrapped_root_token.data()), wrapped_root_token.size(), &wrapped_root_token_base64);

                                // We will split the master key into shares pieces and will require threshold parts
                                // to reconstruct the master key.
                                // So, to unwrap the wrapped KMS enc.key, the master key is required
                                sss_create_shares(shares, master_key, cnt, threshold);

                                Base64::Encode(master_key, sss_MLEN, &repr);

                                // There is no need to display the Master Key here
                                // It should't be stored anywhere, TODO: UNLESS you have a trusted environment, and you want to store it somewhere
                                // so that when you unlock it later, you can somehow use the master key instead of requiring shares
                                // This is so that it can be automated to some extent (no need for someone to physically paste/type their shares)
                                //
                                // TODO: maybe we should salt, and encrypt each share, so that the base64 representation will be less uniform and
                                // will be harder for someone to - in theory - guess a share.

                                Print("Root Token: ", wrapped_root_token_base64, "\n");
                                for (uint32_t i{0}; i != cnt; ++i) {
                                        repr.clear();
                                        Base64::Encode(reinterpret_cast<const uint8_t *>(shares + i), sss_SHARE_LEN, &repr);
                                        Print("Share ", i, ": ", ansifmt::bold, repr.as_s32(), ansifmt::reset, "\n");
                                }

                                Print("Trusted operators should own those shares. A minimum of ", threshold, " shares are required to reconstruct the Master Key, and unseal KMS.\n");
                                Print("If you can't reconstruct the Master Key, you are toast. Backup often.\n");
                                mysql_client.commit();
                                return 0;
                        }
                }
        } else if (argc > 1 && !strcmp(argv[0], "rotate")) {
                // we will unlock, see try_unlock()
                // enc.key, and then we will create a new master key, etc (see "init" impl.)
                //
                // This is useful when you want to alter the number of trusted parties, or number of required shares, etc.
                Print("Not Implemented\n");
                return 1;
        }

        if (!e) {
                Print("Listen (address:)port not specified\n");
                return 1;
        }

        if (auto rows = mysql_client.select("SELECT k FROM keyring WHERE id = '*'"_s32); auto &&row = rows.next()) {
                if (row[0].size() < 8) {
                        Print("Unexpected state. Aborting\n");
                        return 1;
                }

                const auto a = row[0].data()[0], b = row[0].data()[1];

                if (a < 'a' + 1 || a > 'a' + max_masterkey_shares || b < 'a' + 1 || b > 'a' + max_masterkey_shares) {
                        Print("Unexpected state. Aborting\n");
                        return 1;
                }

                secure_enclave.mk_unlock_ctx.shares_cnt                  = a - 'a';
                secure_enclave.mk_unlock_ctx.master_key_shares_threshold = b - 'a';

                if (secure_enclave.mk_unlock_ctx.master_key_shares_threshold > secure_enclave.mk_unlock_ctx.shares_cnt) {
                        Print("Unexpected state. Aborting\n");
                        return 1;
                }

                Print("KMS is ready and locked. You need to provide ", secure_enclave.mk_unlock_ctx.master_key_shares_threshold, " shares to unlock it.\n");
                Print("You cannot use it set or access secrets before you unlock it.\n");
        } else {
                Print("KMS is not initialized yet.\n");
                return 1;
        }

        {
                // this is required for tokens generation
                uint8_t digest_input[32];

                switch_security::gen_rnd(sizeof(digest_input), digest_input);
                secure_enclave.cur_sess.session_id = FNVHash64(digest_input, sizeof(digest_input));
        }

        std::unique_ptr<SSL_CTX, decltype(&::SSL_CTX_free)> ssl_ctx(nullptr, SSL_CTX_free);

        if (!use_http) {
                SSL_library_init();
                SSL_load_error_strings();
                SSLeay_add_ssl_algorithms();
                OpenSSL_add_all_algorithms();
        }

        DEFER({
                if (!use_http) {
                        FIPS_mode_set(0);
                        ENGINE_cleanup();
                        CONF_modules_unload(1);
                        CONF_modules_free();
                        EVP_cleanup();
                        CRYPTO_cleanup_all_ex_data();
                        sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
                        ERR_remove_state(0);
                        ERR_free_strings();
                }
        });

        if (!use_http) {
                ssl_ctx.reset(SSL_CTX_new(SSLv23_server_method()));

                require(ssl_ctx);

#if 0
	SSL_CTX_set_info_callback(ssl_ctx.get(), [](const SSL *s, int where, int ret) { 
		if (ret & SSL_CB_LOOP) SLog("SSL_CB_LOOP\n");
		if (ret & SSL_CB_EXIT) SLog("SSL_CB_EXIT\n");
		if (ret & SSL_CB_READ) SLog("SSL_CB_READ\n");
		if (ret & SSL_CB_READ) SLog("SSL_CB_READ\n");
		if (ret & SSL_CB_WRITE) SLog("SSL_CB_WRITE\n");
		if (ret & SSL_CB_ALERT) SLog("SSL_CB_ALERT\n");
		if (ret & SSL_CB_HANDSHAKE_START) SLog("SSL_CB_HANDSHAKE_START\n");
		if (ret & SSL_CB_HANDSHAKE_DONE) SLog("SSL_CB_HANDSHAKE_DONE\n");


		SLog("state:", SSL_state_string(s), ", ", SSL_state_string_long(s), ", where = ", where, "\n");
	});

	SSL_CTX_set_msg_callback(ssl_ctx.get(), [](int writep, int version, int content_type, 
		const void *buf, std::size_t len, SSL *ssl, void *arg) {

		SLog("Exchanged message (", writep ? "SND" : "RCV", ") ", len, "\n");
	});
#endif

#if 0
	// We will likely wind-up verifying the clients
	// make sure that client certificate identifies who we expect to see
	//
	// SEE: https://wiki.openssl.org/index.php/Manual:SSL_CTX_set_verify(3)
	// example - how to verify peer
	// We should probably use (SSL_VERIFY_CLIENT_ONCE | SSL_VERIFY_FAIL_IF_NO_PEER_CERT) along with SSL_VERIFY_PEER
	//
	// verify with openssl s_client -connect endpoint
	// or e.g openssl s_client -connect localhost:8282  -cert /tmp/crts/origin-crt.pem  -key /tmp/crts/origin-key.pem 
        SSL_CTX_set_verify(ssl_ctx.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_CLIENT_ONCE, [](int ok, X509_STORE_CTX *store) {
                char b[256];
                auto cert = X509_STORE_CTX_get_current_cert(store);
                [[maybe_unused]] auto err = X509_STORE_CTX_get_error(store);
                [[maybe_unused]] auto depth = X509_STORE_CTX_get_error_depth(store);

		if (0 != depth)
		{
			// only verify at depth 0
			return 1;
		}

		// fast access to the SSL* and from there to the connection that owns it
                auto ssl = reinterpret_cast<SSL *>(X509_STORE_CTX_get_ex_data(store, SSL_get_ex_data_X509_STORE_CTX_idx()));
                auto c = reinterpret_cast<connection *>(SSL_get_app_data(ssl));

                X509_NAME_oneline(X509_get_subject_name(cert), b, sizeof(b));
                SLog(depth, " From ", b, " ", ptr_repr(c), " ", c->fd, "\n");
                X509_NAME_oneline(X509_get_issuer_name(cert), b, sizeof(b));
		SLog("issuer ", b, "\n");

		return 1;
        });
#else
                SSL_CTX_set_verify(ssl_ctx.get(), SSL_VERIFY_NONE, nullptr);
#endif

                // If we don't configure our SSL_CTX with a private key, certificate
                // then all connection/handshake attempts will fail
                const char *key_path{"./crts/key.pem"};
                const char *crt_path{"./crts/crt.pem"};

                if (!dev_mode) {
                        if (!verify_ownership(key_path))
                                return 1;
                        else if (!verify_ownership(crt_path))
                                return 1;
                }

                if (1 != SSL_CTX_use_PrivateKey_file(ssl_ctx.get(), key_path, SSL_FILETYPE_PEM) && 1 != SSL_CTX_use_PrivateKey_file(ssl_ctx.get(), key_path, SSL_FILETYPE_ASN1) &&
                    1 != SSL_CTX_use_RSAPrivateKey_file(ssl_ctx.get(), key_path, SSL_FILETYPE_PEM) &&
                    1 != SSL_CTX_use_RSAPrivateKey_file(ssl_ctx.get(), key_path, SSL_FILETYPE_ASN1)) {
                        SLog("Failed to use private key. Verify that ./crts/key.pem and ./crts/crt.pem are valid\n");
                        return 1;
                }

                if (-1 == SSL_CTX_check_private_key(ssl_ctx.get())) {
                        SLog("Failed to verify private key\n");
                        return 1;
                }

                if (1 != SSL_CTX_use_certificate_file(ssl_ctx.get(), crt_path, SSL_FILETYPE_PEM) && 1 != SSL_CTX_use_certificate_file(ssl_ctx.get(), crt_path, SSL_FILETYPE_ASN1)) {
                        SLog("Failed to set certificate\n");
                        return 1;
                }

                SSL_CTX_set_mode(ssl_ctx.get(), SSL_MODE_AUTO_RETRY | SSL_MODE_ENABLE_PARTIAL_WRITE);
                SSL_CTX_set_default_read_ahead(ssl_ctx.get(), 1);
                SSL_CTX_set_options(ssl_ctx.get(), SSL_OP_ALL | SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | SSL_OP_LEGACY_SERVER_CONNECT);

                if (SSL_CTX_set_cipher_list(ssl_ctx.get(), "ALL") <= 0) {
                        Print("TLS initialization failed: Unable to setup ciphers\n");
                        return 1;
                }
        }

        int                                                  listener = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        struct sockaddr_in                                   sa;
        EPoller                                              io_events;
        std::unordered_map<int, std::unique_ptr<connection>> connections_map;

        if (listener == -1) {
                perror("socket()");
                return 1;
        }

        Switch::SetReuseAddr(listener, 1);
        Switch::SetDeferAccept(listener, 2);

        memset(&sa, 0, sizeof(sa));
        sa.sin_family      = AF_INET;
        sa.sin_addr.s_addr = e.addr4;
        sa.sin_port        = htons(e.port);

        signal(SIGPIPE, SIG_IGN);

        const auto put_buf = [&reusable_bufs](auto b) {
                if (b) {
                        if (reusable_bufs.size() > 16)
                                delete b;
                        else {
                                b->clear();
                                reusable_bufs.push_back(b);
                        }
                }
        };

        const auto shutdown = [&](auto c, const auto ref, [[maybe_unused]] const bool unexpected) {
                const int fd{c->fd};

#ifndef SWITCH_MIN
                if (unexpected) {
                        Overseer::Emit(_S("kms.srv.shutdown"), {{_S("ref"), ref}});
                }
#endif

                if (auto ssl = std::exchange(c->ssl, nullptr)) {
                        SSL_set_fd(ssl, -1);
                        SSL_free(ssl);
                }

                io_events.erase(fd);
                close(fd);
                c->fd = -1;

                if (auto b = c->inb)
                        put_buf(b);
                if (auto b = c->outb)
                        put_buf(b);

                connections_map.erase(fd);
        };

        static const auto log_SSL_error = [](const auto ref) {
                const char *f, *d;
                int         l;
                int         flags;

                ERR_peek_last_error_line_data(&f, &l, &d, &flags);
                Print("SSL error at ", ref, ": Failed at ", f, ":", l, ": ", d, "\n");
        };

        const auto try_ssl_accept = [&](auto c) {
                auto ssl{c->ssl};

                c->flags &= ~unsigned(connection::Flags::tls_want_accept);
                if (const auto r = SSL_accept(ssl); r == -1) {
                        if (const auto reason = SSL_get_error(ssl, r); reason == SSL_ERROR_WANT_READ)
                                c->flags |= unsigned(connection::Flags::tls_want_read);
                        else if (reason == SSL_ERROR_WANT_WRITE)
                                c->flags |= unsigned(connection::Flags::tls_want_write);
                        else if (reason == SSL_ERROR_WANT_ACCEPT)
                                c->flags |= unsigned(connection::Flags::tls_want_accept);
                        else if (reason == SSL_ERROR_SYSCALL) {
                                if (EAGAIN != errno && EINTR != errno && EINPROGRESS != errno) {
                                        shutdown(c, __LINE__, true);
                                        return false;
                                }
                        } else if (reason == SSL_ERROR_SSL) {
                                // A failure in the SSL library, usually a protocol error
                                // We need to check the OpenSSL error queue
                                log_SSL_error(__LINE__);
                                shutdown(c, __LINE__, true);
                                return false;
                        } else if (reason != SSL_ERROR_NONE) {
                                shutdown(c, __LINE__, true);
                                return false;
                        }
                }

                c->flags |= unsigned(connection::Flags::tls_accept_ok);
                return true;

        };

        const auto poll_out_avail = [&io_events](auto c) {
                if (0 == (c->flags & unsigned(connection::Flags::need_outavail))) {
                        c->flags |= unsigned(connection::Flags::need_outavail);
                        io_events.set_data_events(c->fd, c, POLLIN | POLLOUT);
                }
        };

        const auto try_write = [&](auto c) {
                static constexpr auto trace{false};
                const auto            fd{c->fd};
                auto                  idx{c->iov.idx};
                const auto            size{c->iov.size};
                int                   r;
                const auto            before = Timings::Microseconds::Tick();

                if (trace)
                        SLog("Output ", c->iov.need_patch, "\n");

                if (c->iov.need_patch) {
                        for (uint32_t i = idx; i != size; ++i) {
                                const auto real_len = c->iov.data[i].iov_len & (~((1u) << 30));

                                if (real_len != c->iov.data[i].iov_len) {
                                        c->iov.data[i].iov_len  = real_len;
                                        c->iov.data[i].iov_base = c->outb->data() + uintptr_t(c->iov.data[i].iov_base);
                                }
                        }

                        c->iov.need_patch = false;
                }

                if (auto ssl = c->ssl) {
                        if ((c->flags & unsigned(connection::Flags::tls_want_accept)) && !try_ssl_accept(c))
                                return false;

                        // XXX: can we use TCP corks instead of, this?
                        // It's not a great idea anyway, because thanks to Meltdown, the costs of individual syscalls is higher
                        // so we may as well just build the buffer here and try sending that instead
                        std::size_t sum{0};

                        tbuf.clear();
                        for (uint32_t i = idx; i != size; ++i) {
                                const auto it{c->iov.data + i};

                                tbuf.serialize(it->iov_base, it->iov_len);
                                sum += it->iov_len;

                                if (sum > 2 * 1024 * 1024) {
                                        // don't try that hard
                                        break;
                                }
                        }

                        c->flags &= ~unsigned(connection::Flags::tls_want_write);

                        r = SSL_write(ssl, tbuf.data(), tbuf.size());

                        if (trace)
                                SLog("SSL_write() ", r, "\n");

                        if (r < 0) {
                                if (const auto reason = SSL_get_error(ssl, r); reason == SSL_ERROR_WANT_READ) {
                                        c->flags |= unsigned(connection::Flags::tls_want_read);
                                        return true;
                                } else if (reason == SSL_ERROR_WANT_ACCEPT) {
                                        c->flags |= unsigned(connection::Flags::tls_want_accept);
                                        return true;
                                } else if (reason == SSL_ERROR_WANT_WRITE) {
                                        // need to try again as soon as possible
                                        poll_out_avail(c);
                                        return true;
                                } else if (reason == SSL_ERROR_SYSCALL) {
                                        if (EINTR == errno || EAGAIN == errno)
                                                return true;
                                        else {
                                                shutdown(c, __LINE__, true);
                                                return false;
                                        }
                                } else if (reason == SSL_ERROR_SSL) {
                                        log_SSL_error(__LINE__);
                                        shutdown(c, __LINE__, true);
                                        return false;
                                } else if (reason != SSL_ERROR_NONE) {
                                        shutdown(c, __LINE__, true);
                                        return false;
                                } else {
                                        if (trace)
                                                SLog("Will need to retry?\n");

                                        return true;
                                }
                        } else
                                goto l1;
                } else {
                        r = writev(fd, c->iov.data + c->iov.idx, size - idx);

                        if (-1 == r) {
                                if (errno == EINTR || errno == EAGAIN)
                                        return true;
                                else {
                                        shutdown(c, __LINE__, true);
                                        return false;
                                }
                        }

                l1:
                        auto *     it{c->iov.data + c->iov.idx};
                        const auto end = c->iov.data + size;

                        while (r >= it->iov_len) {
                                r -= it->iov_len;

                                if (++it == end) {
                                        require(0 == r);

                                        if (c->flags & unsigned(connection::Flags::shutdown_onflush)) {
                                                if (trace)
                                                        SLog("Took ", duration_repr(Timings::Microseconds::Since(before)), "\n");

                                                shutdown(c, __LINE__, false);
                                                return false;
                                        }

                                        if (c->flags & unsigned(connection::Flags::need_outavail)) {
                                                c->flags ^= unsigned(connection::Flags::need_outavail);
                                                io_events.set_data_events(fd, c, POLLIN);
                                        }

                                        if (auto b = std::exchange(c->outb, nullptr))
                                                put_buf(b);

                                        c->iov.idx  = 0;
                                        c->iov.size = 0;

                                        if (trace)
                                                SLog("Took ", duration_repr(Timings::Microseconds::Since(before)), "\n");
                                        return true;
                                }
                        }

                        it->iov_base = reinterpret_cast<char *>(it->iov_base) + r;
                        it->iov_len -= r;
                        c->iov.idx = std::distance(c->iov.data, it);

                        poll_out_avail(c);
                }

                return true;
        };

        const auto try_flush = [&](auto c) {
                if (0 == (c->flags & unsigned(connection::Flags::need_outavail)))
                        return try_write(c);
                else {
                        // will be flushed eventually
                        return true;
                }
        };

        const auto req_method_check = [&](auto c, const auto method) {
                if (c->state.cur_req.method == method)
                        return true;
                else {
                        build_response(c, "405 Method Not Allowed"_s32);
                        try_flush(c);
                        return false;
                }
        };

        [[maybe_unused]] const auto auth_check = [&](auto c, const auto key, const uint32_t mode) {
                if (key.empty() || key.front() == '*' || !c->state.cur_req.auth)
                        return false;

                if (c->is_root())
                        return true;

                static constexpr bool trace{false};
                const auto            account_id = c->state.cur_req.auth.value().account_id;
                auto                  res        = tokens_map.emplace(account_id, std::unique_ptr<token_props>{});

                if (res.second) {
                        if (auto rows = mysql_client.select("SELECT iv, domains FROM tokens WHERE id = ", account_id); auto &&row = rows.next()) {
                                if (row[0].size() != 16) {
                                        if (trace)
                                                SLog("Unexpected IV\n");

                                        return false;
                                }

                                try {
                                        const auto                                  plaintext = switch_security::ciphers::aes256{{secure_enclave.enc_key, 32}, {reinterpret_cast<const uint8_t *>(row[0].data()), 16}}.decrypt(row[1]);
                                        std::vector<std::pair<str_view8, uint32_t>> all;

                                        for (const auto *p = reinterpret_cast<const uint8_t *>(plaintext.data()), *const e = p + plaintext.size(); p != e;) {
                                                const auto len = decode_pod<uint8_t>(p);

                                                if (len == 0 || len > 128 || p + len + sizeof(uint32_t) > e) {
                                                        if (trace)
                                                                SLog("Unexpected data\n");

                                                        break;
                                                }

                                                const str_view8 domain(reinterpret_cast<const char *>(p), len);

                                                p += len;

                                                const auto perms = decode_pod<uint32_t>(p);

                                                if (trace)
                                                        SLog("Got [", domain, "] ", perms, "\n");

                                                all.push_back({domain, perms});
                                        }

                                        if (trace)
                                                SLog("total ", all.size(), "\n");

                                        auto tp = std::make_unique<token_props>();

                                        tp->last_update = now;
                                        tp->domains_cnt = all.size();
                                        tp->domains     = (std::pair<str_view8, uint32_t> *)malloc(sizeof(std::pair<str_view8, uint32_t>) * all.size());

                                        for (uint32_t i{0}; i != all.size(); ++i) {
                                                auto p = static_cast<char *>(malloc(sizeof(char) * all[i].first.size()));

                                                memcpy(p, all[i].first.data(), all[i].first.size());
                                                tp->domains[i] = {{p, all[i].first.size()}, all[i].second};
                                        }

                                        res.first->second = std::move(tp);

                                        if (trace)
                                                SLog("AUTH\n");
                                } catch (...) {
                                        return false;
                                }
                        }
                }

                if (!res.first->second) {
                        // Missing
                        if (trace)
                                SLog("Missing?\n");

                        return false;
                }

                const auto props = res.first->second.get();
                const auto all   = props->domains;

                for (uint32_t i{0}; i != props->domains_cnt; ++i) {
                        const auto[domain, permissions] = all[i];

                        if (trace)
                                SLog("[", key, "] against [", domain, "](", domain.size(), ")\n");

                        if (key.BeginsWith(domain.data(), domain.size())) {
                                if (trace)
                                        SLog("Matched ", domain, "\n");

                                if ((permissions & mode) != mode) {
                                        if (trace)
                                                SLog("Permissions Check Fail\n");

                                        return false;
                                }

                                if (trace)
                                        SLog("OK\n");

                                return true;
                        }
                }

                return false;
        };

        const auto process_req = [&](auto c, const auto _p, const auto content) {
                const auto[path, query_string] = _p.Divided('?');

#define INC_REQ(f) runtime_metrics.reqs.f++

                if (content.size() > 32 * 1024 * 1024) {
                        build_response(c, "400 Bad Request"_s32, "Unexpected Input"_s32);
                        return try_flush(c);
                }

                // See README.md
                if (path.Eq(_S("/create_keys"))) {
                        INC_REQ(create_keys);

                        if (!req_method_check(c, "POST"_s32))
                                return false;

                        if (!c->state.cur_req.auth) {
                                build_response(c, "407 Authentication Required"_s32);
                                return try_flush(c);
                        }

                        if (secure_enclave.locked) {
                                build_response(c, "403 Forbidden"_s32, "LOCKED"_s32);
                                return try_flush(c);
                        }

                        auto       b    = mysql_client.internal_buffer();
                        auto       outb = c->outb ?: (c->outb = new_buf());
                        const auto co{outb->size()};

                        b->clear();
                        b->append("REPLACE INTO keyring VALUES "_s32);
                        for (const auto id : content.Split('\n')) {
                                if (id) {
                                        if (false == verify_objid(id)) {
                                                build_response(c, "400 Bad Request"_s32, "Unexpected ID"_s32);
                                                return try_flush(c);
                                        }

                                        if (!auth_check(c, id.as_s32(), O_WRONLY | O_RDONLY)) {
                                                build_response(c, "401 Unauthorized"_s32);
                                                return try_flush(c);
                                        }

                                        uint8_t  key[32];
                                        uint64_t iv[2];

                                        //  IV depends on the key id
                                        build_iv(id, iv);

                                        // Create a new key for this key id
                                        // (clients will likely use this as a wrapping key)
                                        switch_security::gen_rnd(32, key);

                                        // Encrypt it using our enc.key
                                        const auto ciphertext = switch_security::ciphers::aes256{{secure_enclave.enc_key, 32}, {reinterpret_cast<const uint8_t *>(iv), 16}}
                                                                    .encrypt({reinterpret_cast<const char *>(key), 32});

                                        b->append("('", escaped_repr(id.data(), id.size()), "', '", escaped_repr(ciphertext.data(), ciphertext.size()), "'),"_s32);

                                        outb->append(id, ' ');
                                        Base64::Encode(reinterpret_cast<const uint8_t *>(key), 256 / 8, outb);
                                        outb->append('\n');
                                }
                        }

                        if (b->back() == ',') {
                                b->pop_back();
                                if (!mysql_client.exec_stmt(false, b->data(), b->size())) {
                                        build_response(c, "500 Internal Server Error"_s32);
                                        return try_flush(c);
                                } else {
                                        c->iov.append("HTTP/1.1 200 OK\r\n"_s32);
                                        c->iov.append("Content-Length: "_s32);

                                        const auto o{outb->size()};
                                        const auto cl = outb->size() - co;

                                        outb->append(cl);
                                        c->iov.append_range({o, outb->size() - o});

                                        c->iov.append("\r\nServer: "_s32);
                                        c->iov.append(server_name);
                                        c->iov.append("\r\n"_s32);
                                        set_response_connection_header(c);
                                        c->iov.append("\r\n"_s32);

                                        c->iov.append_range({co, cl});
                                        return try_flush(c);
                                }
                        }

                        build_response(c, "200 OK"_s32);
                        return try_flush(c);
                } else if (path.Eq(_S("/delete_keys"))) {
                        INC_REQ(delete_keys);

                        if (!req_method_check(c, "POST"_s32))
                                return false;

                        // TODO: verify, for each distinct key, that we can do this
                        if (secure_enclave.locked) {
                                build_response(c, "403 Forbidden"_s32, "KMS is LOCKED"_s32);
                                return try_flush(c);
                        }

                        if (!c->state.cur_req.auth) {
                                build_response(c, "407 Authentication Required"_s32);
                                return try_flush(c);
                        }

                        auto b = mysql_client.internal_buffer();

                        b->clear();
                        b->append("DELETE FROM keyring WHERE id IN ("_s32);

                        for (const auto line : content.Split('\n')) {
                                const auto key_name = line.ws_trimmed();

                                if (false == verify_objid(key_name) || b->size() > 20 * 1024 * 1024) {
                                        build_response(c, "400 Bad Request"_s32, "Cannot verify key name"_s32);
                                        return try_flush(c);
                                }

                                if (!auth_check(c, key_name.as_s32(), O_WRONLY | O_RDONLY)) {
                                        build_response(c, "401 Unauthorized"_s32);
                                        return try_flush(c);
                                }

                                b->append('\'', escaped_repr(key_name), "',"_s32);
                        }

                        if (b->back() == ',') {
                                b->pop_back();
                                b->append(')');

                                if (false == mysql_client.exec_stmt(false, b->data(), b->size())) {
                                        build_response(c, "500 Internal Server Error"_s32);
                                        return try_flush(c);
                                }
                        }

                        build_response(c, "200 OK"_s32);
                        return try_flush(c);
                } else if (path.Eq(_S("/set_keys"))) {
                        INC_REQ(set_keys);

                        if (!req_method_check(c, "POST"_s32))
                                return false;

                        if (!c->state.cur_req.auth) {
                                build_response(c, "407 Authentication Required"_s32);
                                return try_flush(c);
                        }

                        if (secure_enclave.locked) {
                                build_response(c, "403 Forbidden"_s32, "KMS is LOCKED"_s32);
                                return try_flush(c);
                        }

                        std::vector<std::pair<str_view32, str_view32>> all;

                        // expect keyname:string SPACE wrapping key:base64
                        for (const auto line : content.Split('\n')) {
                                auto[objid, wrapping_key_base64] = line.Divided(' ');

                                objid.TrimWS();
                                wrapping_key_base64.TrimWS();

                                if (objid && wrapping_key_base64) {
                                        if (false == verify_objid(objid) || wrapping_key_base64.size() > 512) {
                                                build_response(c, "400 Bad Request"_s32, "Cannot verify key name"_s32);
                                                return try_flush(c);
                                        }

                                        if (!auth_check(c, objid.as_s32(), O_WRONLY | O_RDONLY)) {
                                                build_response(c, "401 Unauthorized"_s32);
                                                return try_flush(c);
                                        }

                                        all.push_back({objid, wrapping_key_base64});
                                }
                        }

                        mysql_client.begin();

                        auto     b = mysql_client.internal_buffer();
                        uint64_t iv[2];

                        b->clear();
                        b->append("REPLACE INTO keyring VALUES "_s32);
                        for (const auto &it : all) {
                                const auto[id, wrapping_key_base64] = it;

                                // wrapping key is base64 encoded in the request
                                base64_buf.clear();
                                if (-1 == Base64::Decode(reinterpret_cast<const uint8_t *>(wrapping_key_base64.data()), wrapping_key_base64.size(), &base64_buf)) {
                                        build_response(c, "400 Bad Request"_s32, "Unable to parse base64"_s32);
                                        return try_flush(c);
                                }

                                const auto wrapping_key = base64_buf.as_s32();

                                // IV depends on the object id
                                build_iv(id, iv);

                                // Encrypt the provided WRAPPING key using KMS's encryption key
                                //
                                // This wrapping key was generated the application, and was used to encrypt the data key(the _wrapped_ key)
                                // The data key was used to encrypt the data. The encrypted data is stored together with the wrapped key.
                                const auto ciphertext = switch_security::ciphers::aes256{{secure_enclave.enc_key, 32}, {reinterpret_cast<const uint8_t *>(iv), 16}}.encrypt(wrapping_key);

                                b->append("('", escaped_repr(id.data(), id.size()), "', '", escaped_repr(ciphertext.data(), ciphertext.size()), "'),"_s32);
                        }

                        if (b->back() == ',') {
                                b->pop_back();
                                if (!mysql_client.exec_stmt(false, b->data(), b->size())) {
                                        mysql_client.rollback();
                                        build_response(c, "500 Internal Server Error"_s32);
                                        return try_flush(c);
                                } else {
                                        mysql_client.commit();
                                }
                        } else {
                                mysql_client.rollback();
                        }

                        build_response(c, "200 OK"_s32);
                        return try_flush(c);
                } else if (path.Eq(_S("/encrypt")) || path.Eq(_S("/wrap"))) {
                        // /encrypt and /decrypt are only really meaningful if you are not using the (entity key, wrapping key, wrapped key) pattern
                        // where you create the entity key and the wrapping key that's used to encrypt the entity key, and then associate the key with the wrapping key on KMS.
                        //
                        // If you used /create_key or /set_keys, and that key is used for encrypting/decrypting arbitrary plaintext in ways that make sense in your application, then
                        // /encrypt and /decrypt are handy. This is the functionality Google's KMS offers currently. You create keys in keyrings(KMS currently only supports a single keyring)
                        // and use the APIS for encrypting plaintext and decrypting ciphertext provided in the RPC
                        INC_REQ(encrypt);

                        if (!req_method_check(c, "POST"_s32))
                                return false;

                        if (!c->state.cur_req.auth) {
                                build_response(c, "407 Authentication Required"_s32);
                                return try_flush(c);
                        }

                        // keyname:s32 SPACE plaintext:base64[,plaintext:base64]...
                        if (secure_enclave.locked) {
                                build_response(c, "403 Forbidden"_s32, "KMS is LOCKED"_s32);
                                return try_flush(c);
                        }

                        const auto[keyname, plaintext_base64_list] = content.Divided(' ');

                        if (!verify_objid(keyname)) {
                                build_response(c, "400 Bad Request"_s32, "Unable to verify keyname"_s32);
                                return try_flush(c);
                        }

                        if (!auth_check(c, keyname.as_s32(), O_RDONLY)) {
                                build_response(c, "401 Unauthorized"_s32);
                                return try_flush(c);
                        }

                        if (auto &&rows = mysql_client.select("SELECT k FROM keyring WHERE id = '", escaped_repr(keyname), "'"); auto &&row = rows.next()) {
                                uint64_t   iv[2];
                                const auto ciphertext{row[0]};

                                build_iv(keyname, iv);

                                // Decrypte the stored key using KM's encryption key
                                // this will produce the wrapping key we associated with this key earlier using /set_keys or /create_key
                                const auto plaintext = switch_security::ciphers::aes256{{secure_enclave.enc_key, 32}, {reinterpret_cast<const uint8_t *>(iv), 16}}.decrypt(ciphertext);

                                // that's our key (key name=>key)
                                // we will use that to encrypt the provided plaintext
                                const auto wrapping_key   = plaintext.as_s32();
                                auto       outb           = c->outb ?: (c->outb = new_buf());
                                const auto content_offset = outb->size();

                                for (const auto plaintext_base64 : plaintext_base64_list.Split(',')) {
                                        // plaintext is base64 encoded
                                        base64_buf.clear();
                                        if (-1 == Base64::Decode(reinterpret_cast<const uint8_t *>(plaintext_base64.data()), plaintext_base64.size(), &base64_buf)) {
                                                build_response(c, "400 Bad Request"_s32, "Unable to decode base64"_s32);
                                                return try_flush(c);
                                        }

                                        // OK, now encrypt the provided plaintext to get the output ciphertext
                                        //
                                        // this only makes sense if the associated (to key) wrapping key, is not used for unwrapping an 'entity key'
                                        // i.e the wrapping key associated with the key is used for encrypting the actual content, not for encryption and decryption of another(entity) key
                                        const auto ciphertext_out = switch_security::ciphers::aes256{{reinterpret_cast<const uint8_t *>(wrapping_key.data()), wrapping_key.size()},
                                                                                                     {reinterpret_cast<const uint8_t *>(iv), 16}}
                                                                        .encrypt(base64_buf.as_s32());

                                        Base64::Encode(reinterpret_cast<const uint8_t *>(ciphertext_out.data()), ciphertext_out.size(), outb);
                                        outb->append('\n');
                                }
                                const auto clo_offset     = outb->size();
                                const auto content_length = clo_offset - content_offset;

                                outb->append(content_length);

                                c->iov.append("HTTP/1.1 200 OK\r\nServer: "_s32);
                                c->iov.append(server_name);
                                c->iov.append("\r\nContent-Length: "_s32);
                                c->iov.append_range({clo_offset, outb->size() - clo_offset});
                                c->iov.append("\r\n"_s32);
                                set_response_connection_header(c);
                                maybe_extend_lease(c);
                                c->iov.append("\r\n"_s32);
                                c->iov.append_range({content_offset, content_length});

                                return try_flush(c);
                        } else {
                                build_response(c, "404 Not Found"_s32);
                                return try_flush(c);
                        }
                } else if (path.Eq(_S("/decrypt"))) {
                        INC_REQ(decrypt);

                        if (!req_method_check(c, "POST"_s32))
                                return false;

                        if (!c->state.cur_req.auth) {
                                build_response(c, "407 Authentication Required"_s32);
                                return try_flush(c);
                        }

                        // keyname:s32 SPACE ciphertext:base64[,ciphertext:base64]...
                        // You may want to use /unwrap if you are dealing with multiple keys, which is the case for
                        // 	when you e.g want to unwrap multiple wrapped entity data keys
                        if (secure_enclave.locked) {
                                build_response(c, "403 Forbidden"_s32, "KMS is LOCKED"_s32);
                                return try_flush(c);
                        }

                        const auto[keyname, ciphertext_base64_list] = content.Divided(' ');

                        if (!verify_objid(keyname)) {
                                build_response(c, "400 Bad Request"_s32, "Unable to verify key name"_s32);
                                return try_flush(c);
                        }

                        if (!auth_check(c, keyname.as_s32(), O_RDONLY)) {
                                build_response(c, "401 Unauthorized"_s32);
                                return try_flush(c);
                        }

                        if (auto &&rows = mysql_client.select("SELECT k FROM keyring WHERE id = '", escaped_repr(keyname), "'"); auto &&row = rows.next()) {
                                uint64_t   iv[2];
                                const auto ciphertext{row[0]};
                                auto       outb           = c->outb ?: (c->outb = new_buf());
                                const auto content_offset = outb->size();

                                build_iv(keyname, iv);
                                // Decrypte the stored key using KM's encryption key
                                const auto plaintext = switch_security::ciphers::aes256{{secure_enclave.enc_key, 32}, {reinterpret_cast<const uint8_t *>(iv), 16}}.decrypt(ciphertext);

                                // that's our key (key name=>key)
                                // we will use that to decrypt the provided ciphertext
                                const auto wrapping_key = plaintext.as_s32();

                                for (const auto ciphertext_base64 : ciphertext_base64_list.Split(',')) {

                                        try {
                                                // ciphertext is base64 encoded
                                                base64_buf.clear();
                                                if (-1 == Base64::Decode(reinterpret_cast<const uint8_t *>(ciphertext_base64.data()), ciphertext_base64.size(), &base64_buf)) {
                                                        build_response(c, "400 Bad Request"_s32, "Unable to decode base64"_s32);
                                                        return try_flush(c);
                                                }

                                                // OK, now decrypt the provided ciphertext to get the output plaintext
                                                const auto plaintext_out = switch_security::ciphers::aes256{{reinterpret_cast<const uint8_t *>(wrapping_key.data()), wrapping_key.size()},
                                                                                                            {reinterpret_cast<const uint8_t *>(iv), 16}}
                                                                               .decrypt(base64_buf.as_s32());

                                                Base64::Encode(reinterpret_cast<const uint8_t *>(plaintext_out.data()), plaintext_out.size(), outb);
                                                outb->append('\n');
                                        } catch (...) {
                                                outb->resize(content_offset);
                                                if (outb->empty()) {
                                                        put_buf(outb);
                                                        c->outb = nullptr;
                                                }
                                                build_response(c, "400 Bad Request"_s32, "Unexpected content"_s32);
                                                return try_flush(c);
                                        }
                                }

                                c->iov.append("HTTP/1.1 200 OK\r\nServer: "_s32);
                                c->iov.append(server_name);
                                c->iov.append("\r\nContent-Length: "_s32);

                                const auto cl_offset   = outb->size();
                                const auto content_len = cl_offset - content_offset;

                                outb->append(content_len);

                                c->iov.append_range({cl_offset, outb->size() - cl_offset});
                                c->iov.append("\r\n"_s32);
                                set_response_connection_header(c);
                                maybe_extend_lease(c);
                                c->iov.append("\r\n"_s32);
                                c->iov.append_range({content_offset, content_len});

                                return try_flush(c);
                        } else {
                                build_response(c, "404 Not Found"_s32);
                                return try_flush(c);
                        }
                } else if (path.Eq(_S("/seal"))) {
                        if (!c->state.cur_req.auth) {
                                build_response(c, "407 Authentication Required"_s32);
                                return try_flush(c);
                        }

                        if (!c->is_root()) {
                                build_response(c, "401 Unauthorized"_s32);
                                return try_flush(c);
                        }

                        if (secure_enclave.locked) {
                                build_response(c, "400 Bad Request"_s32, "Already LOCKED"_s32);
                                return try_flush(c);
                        }

                        secure_enclave.locked = true;
                        memset(secure_enclave.enc_key, 0, sizeof(secure_enclave.enc_key));
                        secure_enclave.mk_unlock_ctx.reset();

                        build_response(c, "200 OK"_s32, "UNLOCKED"_s32);
                        return try_flush(c);
                } else if (path.Eq(_S("/status"))) {
                        auto       outb = c->outb ?: (c->outb = new_buf());
                        const auto co   = outb->size();

                        outb->append("sealed="_s32, secure_enclave.locked ? "yes" : "no", "\n");
                        outb->append("total_shares="_s32, secure_enclave.mk_unlock_ctx.collected, "\n");

                        const auto clo_offset     = outb->size();
                        const auto content_length = clo_offset - co;

                        c->iov.append("HTTP/1.1 200 OK\r\nServer: "_s32);
                        c->iov.append(server_name);
                        c->iov.append("\r\nContent-Length: "_s32);

                        outb->append(content_length);
                        c->iov.append_range({clo_offset, outb->size() - clo_offset});
                        c->iov.append("\r\n"_s32);
                        set_response_connection_header(c);
                        c->iov.append("\r\n"_s32);

                        c->iov.append_range({co, content_length});
                        return try_flush(c);
                } else if (path.Eq(_S("/status_prometheus"))) {
                        auto        outb = c->outb ?: (c->outb = new_buf());
                        const auto  co   = outb->size();
                        const auto &r{runtime_metrics.reqs};

                        outb->append("# TYPE kms_rps gauge\n"_s32);
                        outb->append(R"(kms_rps{r="create_keys"} )"_s32, r.create_keys, '\n');
                        outb->append(R"(kms_rps{r="delete_keys"} )"_s32, r.delete_keys, '\n');
                        outb->append(R"(kms_rps{r="encrypt"} )"_s32, r.encrypt, '\n');
                        outb->append(R"(kms_rps{r="decrypt"} )"_s32, r.decrypt, '\n');
                        outb->append(R"(kms_rps{r="get_keys"} )"_s32, r.get_keys, '\n');
                        outb->append(R"(kms_rps{r="unwrap"} )"_s32, r.unwrap, '\n');
                        outb->append(R"(kms_rps{r="get_secrets"} )"_s32, r.get_secrets, '\n');
                        outb->append(R"(kms_rps{r="set_secrets"} )"_s32, r.set_secrets, '\n');

                        const auto clo_offset     = outb->size();
                        const auto content_length = clo_offset - co;

                        c->iov.append("HTTP/1.1 200 OK\r\nServer: "_s32);
                        c->iov.append(server_name);
                        c->iov.append("\r\nContent-Length: "_s32);

                        outb->append(content_length);
                        c->iov.append_range({clo_offset, outb->size() - clo_offset});
                        c->iov.append("\r\n"_s32);
                        set_response_connection_header(c);
                        c->iov.append("\r\n"_s32);

                        c->iov.append_range({co, content_length});
                        return try_flush(c);
                } else if (path.Eq(_S("/seal_status"))) {
                        if (secure_enclave.locked)
                                build_response(c, "418 I am Teapot"_s32);
                        else
                                build_response(c, "200 OK"_s32);
                        return try_flush(c);
                } else if (path.Eq(_S("/revoke_token"))) {
                        if (!req_method_check(c, "POST"_s32))
                                return false;

                        if (secure_enclave.locked) {
                                build_response(c, "403 Forbidden"_s32, "LOCKED"_s32);
                                return try_flush(c);
                        }

                        if (!c->is_root()) {
                                build_response(c, "401 Unauthorized"_s32);
                                return try_flush(c);
                        }

                        try {
                                uint8_t iv[16];

                                tbuf.clear();
                                Base64::Decode(reinterpret_cast<const uint8_t *>(content.data()), content.size(), &tbuf);
                                build_iv("**"_s32, iv);

                                const auto plaintext = switch_security::ciphers::aes256{{secure_enclave.enc_key, 32}, {iv, 16}}.decrypt(tbuf.as_s32());
                                const auto res       = secure_enclave.parse_token(plaintext.as_s32(), now);

                                if (!res) {
                                        build_response(c, "400 Bad Request"_s32, "Invalid Token"_s32);
                                        return try_flush(c);
                                } else {
                                        // OK, delete it
                                        // if mySQL database is accessible by anyone, then anyone can delete those rows
                                        // it's OK if they can read that data, because all data is encrypted, but
                                        // if they update anything, if they update or delete any tokens, then
                                        // applications that depend on those tokens will no longer function
                                        const auto auth = res.value();

                                        if (0 == auth.account_id) {
                                                build_response(c, "400 Bad Request"_s32, "Invalid Token"_s32);
                                                return try_flush(c);
                                        }

                                        try {
                                                // we will try again in a while
                                                mysql_client.exec("DELETE FROM tokens WHERE id = ", auth.account_id);
                                                build_response(c, "200 OK"_s32);
                                                return try_flush(c);
                                        } catch (...) {
                                                build_response(c, "500 Internal Server Error");
                                                return try_flush(c);
                                        }
                                }
                        } catch (...) {
                                build_response(c, "400 Bad Request"_s32, "Exception Raised"_s32);
                                return try_flush(c);
                        }
                }
#ifdef SWITCH_MIN
                else if (path.Eq(_S("/create_token"))) {
                        static constexpr bool trace{false};

                        if (!req_method_check(c, "POST"_s32))
                                return false;

                        if (secure_enclave.locked) {
                                build_response(c, "403 Forbidden"_s32, "LOCKED"_s32);
                                return try_flush(c);
                        }

                        if (!c->is_root()) {
                                build_response(c, "401 Unauthorized"_s32);
                                return try_flush(c);
                        }

                        nlohmann::json j;

                        try {
                                j = nlohmann::json::parse(std::string(content.data(), content.size()));
                        } catch (const std::exception &e) {
                                if (trace)
                                        SLog("Failed to parse JSON content: ", e.what(), "\n");

                                build_response(c, "400 Bad Request"_s32, "Failed to parse JSON content"_s32);
                                return try_flush(c);
                        }

                        if (!j.is_object()) {
                                if (trace)
                                        SLog("Expected DICTionary\n");

                                build_response(c, "400 Bad Request"_s32, "Expected dictionary"_s32);
                                return try_flush(c);
                        }

                        std::string display_name_stdstr;
                        auto        domains = nlohmann::json::array();
                        uint32_t    exp_ts{0};

                        for (auto it = j.begin(), end = j.end(); it != end; ++it) {
                                if (it.key() == "name" && it.value().is_string())
                                        display_name_stdstr = it.value();
                                else if (it.key() == "domains" && it.value().is_array())
                                        domains = it.value();
                                else if (it.key() == "expires" && it.value().is_number()) {
                                        if (const int64_t v = it.value(); v > 0)
                                                exp_ts = v;
                                }
                        }

                        if (display_name_stdstr.empty() || domains.empty() || display_name_stdstr.size() > 64 || exp_ts <= now) {
                                if (trace)
                                        SLog("Invalid JSON request\n");

                                build_response(c, "400 Bad Request"_s32, "Invalid JSON dictionary"_s32);
                                return try_flush(c);
                        }

                        const str_view32                              display_name(display_name_stdstr.data(), display_name_stdstr.size());
                        std::vector<std::pair<std::string, uint32_t>> all;

                        for (const auto &i : domains) {
                                if (!i.is_object()) {
                                        if (trace)
                                                SLog("Invalid domain\n");

                                        build_response(c, "400 Bad Request"_s32, "Invalid domain definition"_s32);
                                        return try_flush(c);
                                }

                                std::string domain;
                                uint32_t    perms;

                                if (const auto it = i.find("domain"); it != i.end()) {
                                        if (!(*it).is_string()) {
                                                build_response(c, "400 Bad Request"_s32, "Invalid domain name"_s32);
                                                return try_flush(c);
                                        }

                                        domain = *it;

                                        if (domain.size() < 2 || domain.size() > 64 || domain.front() == '/' || domain.back() != '/' || domain.find("//") != std::string::npos) {
                                                if (trace)
                                                        SLog("Invalid domain\n");

                                                build_response(c, "400 Bad Request"_s32, "Invalid domain name"_s32);
                                                return try_flush(c);
                                        }
                                } else {
                                        if (trace)
                                                SLog("Invalid JSON request\n");

                                        build_response(c, "400 Bad Request"_s32, "Domain specified"_s32);
                                        return try_flush(c);
                                }

                                if (const auto it = i.find("permissions"); it != i.end()) {
                                        if (!(*it).is_string()) {
                                                build_response(c, "400 Bad Request"_s32, "Invalid permissions"_s32);
                                                return try_flush(c);
                                        }

                                        const std::string v = *it;

                                        if (trace)
                                                SLog("Permissions [", v, "]\n");

                                        perms = 0;
                                        for (const auto c : v) {
                                                if (c == 'r')
                                                        perms |= O_RDONLY;
                                                else if (c == 'w')
                                                        perms |= O_WRONLY;
                                                else if (trace)
                                                        SLog("Unexpected permissions flag ['", c, "']\n");
                                        }
                                } else {
                                        if (trace)
                                                SLog("Invalid JSON request\n");

                                        build_response(c, "400 Bad Request"_s32, "Permissions not specified"_s32);
                                        return try_flush(c);
                                }

                                all.push_back({domain, perms});
                        }

                        if (all.empty()) {
                                if (trace)
                                        SLog("No domains specified\n");

                                build_response(c, "400 Bad Request"_s32, "No domains specified"_s32);
                                return try_flush(c);
                        }

                        std::sort(all.begin(), all.end(), [](const auto &a, const auto &b) noexcept {
                                return b.first.size() < a.first.size();
                        });

                        uint8_t  iv[16];
                        IOBuffer b;
                        uint64_t token_data[7];

                        for (const auto &it : all) {
                                const auto & [ domain, permissions ] = it;

                                b.pack(uint8_t(domain.size()));
                                b.serialize(domain.data(), domain.size());
                                b.pack(uint32_t(permissions));
                        }

                        // OK, let's create that token, and associate it with its policies
                        uint8_t token_iv[16];

                        switch_security::gen_rnd(16, token_iv);

                        tbuf.clear();
                        tbuf.append("INSERT INTO tokens SET id = 0, display_name = '"_s32);

                        tbuf.append(escaped_repr(switch_security::ciphers::aes256{{secure_enclave.enc_key, 32}, {token_iv, 16}}
                                                     .encrypt(display_name)
                                                     .as_s32()),
                                    "', create_ts = UNIX_TIMESTAMP(), domains = '"_s32);

                        tbuf.append(escaped_repr(switch_security::ciphers::aes256{{secure_enclave.enc_key, 32}, {token_iv, 16}}
                                                     .encrypt(b.as_s32())
                                                     .as_s32()),
                                    "', iv = '"_s32);

                        tbuf.append(escaped_repr(token_iv, 16), '\'');

                        mysql_client.begin();
                        if (!mysql_client.exec_stmt(false, tbuf.data(), tbuf.size())) {
                                mysql_client.rollback();
                                build_response(c, "500 Internal Server Error"_s32);
                                return try_flush(c);
                        }

                        const auto id = mysql_client.insert_id();
                        char       token_repr_buf[128];

                        mysql_client.commit();

                        secure_enclave.build_token(token_data, id, 60, exp_ts);
                        build_iv("**"_s32, iv);

                        const str_view32 token_repr(token_repr_buf, Enclave::token_repr(token_data, token_repr_buf));
                        const auto       encrypted_token_repr = switch_security::ciphers::aes256{{secure_enclave.enc_key, 32}, {iv, 16}}.encrypt(token_repr);
                        auto             outb                 = c->outb ?: (c->outb = new_buf());
                        const auto       bo                   = outb->size();

                        Base64::Encode(reinterpret_cast<const uint8_t *>(encrypted_token_repr.data()), encrypted_token_repr.size(), outb);

                        const auto co = outb->size();
                        const auto bs = co - bo;

                        c->iov.append("HTTP/1.1 200 OK\r\nServer: "_s32);
                        c->iov.append(server_name);
                        c->iov.append("\r\nContent-Length: "_s32);

                        outb->append(bs);
                        c->iov.append_range({co, outb->size() - co});
                        c->iov.append(_S("\r\n"));
                        set_response_connection_header(c);
                        maybe_extend_lease(c);
                        c->iov.append("\r\n"_s32);
                        c->iov.append_range({bo, bs});

                        return try_flush(c);
                }
#else
                else if (path.Eq(_S("/create_token"))) {
                        // Currently, only root can create new tokens. KMS nodes are stateless, or rather, they don't
                        // directly share state with other nodes for resilience. Currently, there is no support for policies but
                        // they will be supported like so:
                        // https://www.vaultproject.io/docs/concepts/policies.html
                        //
                        // They encode an account_id, which is currently only used to differentiate between root and other users
                        // but eventually will be used to track the actual user(i.e users will be created, and tokens will be created for those users), and
                        // users will be associated with policies.
                        //
                        // See also:
                        // https://www.vaultproject.io/api/auth/token/index.html
                        //
                        // For now, when we create a token, we track it in table so we can tell when it was created, its display name, etc
                        // for accounting reasons, and we will also include all domains it has access to. (encrypted).
                        //
                        // Each node will track all creates tokens(for now, we 'll associate the token account_id with the token_id, but it should
                        //	instead change to be able to generate multiple tokens for the same account, see comments) and
                        // if we get a request for an unknown token that hasn't expired yet, we 'll look it up
                        //
                        //
                        // TODO: properly support tokens and policies, use Tank, encrypt messages to synchronize state among nodes
                        static constexpr bool trace{false};

                        if (!req_method_check(c, "POST"_s32))
                                return false;

                        if (secure_enclave.locked) {
                                build_response(c, "403 Forbidden"_s32, "LOCKED"_s32);
                                return try_flush(c);
                        }

                        if (!c->is_root()) {
                                build_response(c, "401 Unauthorized"_s32);
                                return try_flush(c);
                        }

                        std::unique_ptr<RPCValue> v;

                        try {
                                v.reset(RPCValue::ValueFromJSON(content));
                        } catch (...) {
                                if (trace)
                                        SLog("Unable to parse JSON request\n");

                                build_response(c, "400 Bad Request"_s32);
                                return try_flush(c);
                        }

                        if (!v || !v->Is(RPCValue::DICT)) {
                                if (trace)
                                        SLog("Expected DICTionary\n");

                                build_response(c, "400 Bad Request"_s32);
                                return try_flush(c);
                        }

                        const auto d = static_cast<RPCDict *>(v.get());
                        str_view32 display_name;
                        RPCArray * domains{nullptr};
                        uint32_t   exp_ts{0};

                        for (const auto &it : *d) {
                                if (it.name.Eq(_S("name")) && it.value->Is(RPCValue::STRING))
                                        display_name = it.value->AsString()->as_s32();
                                else if (it.name.Eq(_S("domains")) && it.value->Is(RPCValue::ARRAY))
                                        domains = it.value->AsArray();
                                else if (it.name.Eq(_S("expires")) && it.value->Is(RPCValue::INT)) {
                                        if (const auto v = it.value->AsInt()->get(); v > 0)
                                                exp_ts = v;
                                }
                        }

                        if (!display_name || display_name.size() > 64 || !domains || exp_ts <= now) {
                                if (trace)
                                        SLog("Invalid JSON request\n");

                                build_response(c, "400 Bad Request"_s32);
                                return try_flush(c);
                        }

                        std::vector<std::pair<str_view32, uint32_t>> all;

                        for (const auto i : *domains) {
                                if (false == i->Is(RPCValue::DICT)) {
                                        if (trace)
                                                SLog("Invalid domain\n");
                                        build_response(c, "400 Bad Request"_s32);
                                        return try_flush(c);
                                }

                                const auto s = i->AsDict();
                                str_view32 domain;
                                uint32_t   perms;

                                if (const auto v = s->GetString(_S("domain"))) {
                                        domain = v->AsString()->as_s32().ws_trimmed();

                                        if (domain.size() < 2 || domain.size() > 64 || domain.front() == '/' || domain.back() != '/' || domain.Search(_S("//"))) {
                                                if (trace)
                                                        SLog("Invalid domain\n");
                                                build_response(c, "400 Bad Request"_s32);
                                                return try_flush(c);
                                        }
                                } else {
                                        if (trace)
                                                SLog("Invalid JSON request\n");
                                        build_response(c, "400 Bad Request"_s32);
                                        return try_flush(c);
                                }

                                if (const auto v = s->GetString(_S("permissions"))) {
                                        perms = 0;
                                        for (const auto c : v->AsString()->as_s32()) {
                                                if (c == 'r')
                                                        perms |= O_RDONLY;
                                                else if (c == 'w')
                                                        perms |= O_WRONLY;
                                        }
                                } else {
                                        if (trace)
                                                SLog("Invalid JSON request\n");
                                        build_response(c, "400 Bad Request"_s32);
                                        return try_flush(c);
                                }

                                all.push_back({domain, perms});
                        }

                        if (all.empty()) {
                                if (trace)
                                        SLog("No domains specified\n");
                                build_response(c, "400 Bad Request"_s32);
                                return try_flush(c);
                        }

                        std::sort(all.begin(), all.end(), [](const auto &a, const auto &b) noexcept {
                                return b.first.size() < a.first.size();
                        });

                        uint8_t  iv[16];
                        IOBuffer b;
                        uint64_t token_data[7];

                        for (const auto &it : all) {
                                const auto[domain, permissions] = it;

                                b.pack(uint8_t(domain.size()));
                                b.serialize(domain.data(), domain.size());
                                b.pack(uint32_t(permissions));
                        }

                        // OK, let's create that token, and associate it with its policies
                        uint8_t token_iv[16];

                        switch_security::gen_rnd(16, token_iv);

                        tbuf.clear();
                        tbuf.append("INSERT INTO tokens SET id = 0, display_name = '"_s32);

                        tbuf.append(escaped_repr(switch_security::ciphers::aes256{{secure_enclave.enc_key, 32}, {token_iv, 16}}.encrypt(display_name).as_s32()), "', create_ts = UNIX_TIMESTAMP(), domains = '"_s32);
                        tbuf.append(escaped_repr(switch_security::ciphers::aes256{{secure_enclave.enc_key, 32}, {token_iv, 16}}.encrypt(b.as_s32()).as_s32()), "', iv = '"_s32);
                        tbuf.append(escaped_repr(token_iv, 16), '\'');

                        mysql_client.begin();
                        if (!mysql_client.exec_stmt(false, tbuf.data(), tbuf.size())) {
                                mysql_client.rollback();
                                build_response(c, "500 Internal Server Error"_s32);
                                return try_flush(c);
                        }

                        const auto id = mysql_client.insert_id();
                        char       token_repr_buf[128];

                        mysql_client.commit();

                        secure_enclave.build_token(token_data, id, 60, exp_ts);
                        build_iv("**"_s32, iv);

                        const str_view32 token_repr(token_repr_buf, Enclave::token_repr(token_data, token_repr_buf));
                        const auto       encrypted_token_repr = switch_security::ciphers::aes256{{secure_enclave.enc_key, 32}, {iv, 16}}.encrypt(token_repr);
                        auto             outb                 = c->outb ?: (c->outb = new_buf());
                        const auto       bo                   = outb->size();

                        Base64::Encode(reinterpret_cast<const uint8_t *>(encrypted_token_repr.data()), encrypted_token_repr.size(), outb);

                        const auto co = outb->size();
                        const auto bs = co - bo;

                        c->iov.append("HTTP/1.1 200 OK\r\nServer: "_s32);
                        c->iov.append(server_name);
                        c->iov.append("\r\nContent-Length: "_s32);

                        outb->append(bs);
                        c->iov.append_range({co, outb->size() - co});
                        c->iov.append(_S("\r\n"));
                        set_response_connection_header(c);
                        maybe_extend_lease(c);
                        c->iov.append("\r\n"_s32);
                        c->iov.append_range({bo, bs});

                        return try_flush(c);
                }
#endif
                else if (path.Eq(_S("/unseal"))) {
                        if (!req_method_check(c, "POST"_s32))
                                return false;

                        if (false == secure_enclave.locked) {
                                build_response(c, "400 Bad Request"_s32, "UNLOCKED already"_s32);
                                return try_flush(c);
                        }

                        try {
                                for (const auto S : content.Split('\n')) {
                                        if (!S)
                                                continue;

                                        base64_buf.clear();
                                        if (-1 == Base64::Decode(reinterpret_cast<const uint8_t *>(S.data()), S.size(), &base64_buf)) {
                                                build_response(c, "400 Bad Request"_s32);
                                                return try_flush(c);
                                        }

                                        if (base64_buf.size() != sss_SHARE_LEN) {
                                                build_response(c, "400 Bad Request"_s32, "Failed to decode base64 input"_s32);
                                                return try_flush(c);
                                        }

                                        if (secure_enclave.mk_unlock_ctx.collected == 0) {
                                                // reset
                                                switch_security::gen_rnd(32, secure_enclave.mk_unlock_ctx.enc_key);
                                                switch_security::gen_rnd(16, secure_enclave.mk_unlock_ctx.enc_iv);
                                        }

                                        secure_enclave.mk_unlock_ctx.shares[secure_enclave.mk_unlock_ctx.collected++] = switch_security::ciphers::aes256{{secure_enclave.mk_unlock_ctx.enc_key, 32}, {secure_enclave.mk_unlock_ctx.enc_iv, 16}}
                                                                                                                            .encrypt(base64_buf.as_s32());

                                        if (secure_enclave.mk_unlock_ctx.collected == secure_enclave.mk_unlock_ctx.master_key_shares_threshold) {
                                                // OK, let's try to unlock it
                                                // if we fail, reset state
                                                sss_Share shares[secure_enclave.mk_unlock_ctx.collected];

                                                for (uint32_t i{0}; i != secure_enclave.mk_unlock_ctx.collected; ++i) {
                                                        const auto plaintext = switch_security::ciphers::aes256{{secure_enclave.mk_unlock_ctx.enc_key, 32}, {secure_enclave.mk_unlock_ctx.enc_iv, 16}}
                                                                                   .decrypt(secure_enclave.mk_unlock_ctx.shares[i].as_s32());

                                                        require(plaintext.size() == sss_SHARE_LEN);
                                                        memcpy(shares[i], plaintext.data(), plaintext.size());
                                                }

                                                if (!try_unlock(shares, secure_enclave.mk_unlock_ctx.collected)) {
                                                        secure_enclave.mk_unlock_ctx.reset();
                                                        build_response(c, "401 Unauthorized"_s32);
                                                        return try_flush(c);
                                                } else {
                                                        secure_enclave.locked = false;
                                                        secure_enclave.mk_unlock_ctx.reset();
                                                        build_response(c, "200 OK"_s32, "KMS is now UNLOCKED"_s32);
                                                        return try_flush(c);
                                                }
                                        }
                                }

                                tbuf.clear();
                                tbuf.append("{\"cnt\": "_s32, secure_enclave.mk_unlock_ctx.collected, ", \"required\": "_s32, secure_enclave.mk_unlock_ctx.master_key_shares_threshold, "}");
                                build_response(c, "200 OK"_s32, tbuf.as_s32());
                                return try_flush(c);
                        } catch (...) {
                                build_response(c, "400 Bad Request"_s32);
                                return try_flush(c);
                        }
                } else if (path.Eq(_S("/get_keys"))) {
                        // You shouldn't be using this, because it transfers the stored wrapping key to
                        // the client, instead of using the wrapping key with the provided wrapped keys
                        // to unwrap them and return the unwrapped keys back to the client.
                        INC_REQ(get_keys);

                        if (!req_method_check(c, "POST"_s32))
                                return false;

                        if (!c->state.cur_req.auth) {
                                build_response(c, "407 Authentication Required"_s32);
                                return try_flush(c);
                        }

                        if (secure_enclave.locked) {
                                build_response(c, "403 Forbidden"_s32, "KMS is LOCKED"_s32);
                                return try_flush(c);
                        }

                        // array of arrays, and each array must be of size 1, containing
                        // (object id:string)
                        std::vector<str_view32> all;

                        for (const auto line : content.Split('\n')) {
                                if (const auto objid = line.ws_trimmed()) {
                                        if (false == verify_objid(objid)) {
                                                build_response(c, "400 Bad Request"_s32);
                                                return try_flush(c);
                                        }

                                        if (!auth_check(c, objid.as_s32(), O_RDONLY)) {
                                                build_response(c, "401 Unauthorized"_s32);
                                                return try_flush(c);
                                        }

                                        all.push_back(objid);
                                }
                        }

                        auto       outb        = c->outb ?: (c->outb = new_buf());
                        const auto resp_offset = outb->size();

                        if (!all.empty()) {
                                auto b = mysql_client.internal_buffer();

                                b->clear();
                                b->append("SELECT id, k FROM keyring WHERE id IN ("_s32);
                                for (const auto &it : all)
                                        b->append('\'', escaped_repr(it), "',"_s32);

                                if (b->back() == ',') {
                                        static constexpr bool trace{false};

                                        b->pop_back();
                                        b->append(')');

                                        const auto before = Timings::Microseconds::Tick();

                                        if (!mysql_client.exec_stmt(false, b->data(), b->size())) {
                                                build_response(c, "500 Internal Server Error"_s32);
                                                return try_flush(c);
                                        }

                                        auto     rows = mysql_client.rows();
                                        uint64_t iv[2];

                                        if (trace)
                                                SLog("Took ", duration_repr(Timings::Microseconds::Since(before)), "\n");

                                        const auto before_ = Timings::Microseconds::Tick();

                                        for (auto &&row : rows) {
                                                const auto id{row[0]};
                                                const auto encrypted_wrapping_key{row[1]};

                                                build_iv(id, iv);

                                                try {
                                                        // Decrypt the stored WRAPPING key using KMS's encryption key
                                                        const auto plaintext = switch_security::ciphers::aes256{{secure_enclave.enc_key, 32}, {reinterpret_cast<const uint8_t *>(iv), 16}}
                                                                                   .decrypt(encrypted_wrapping_key);
                                                        const auto wrapping_key = plaintext.as_s32();

                                                        // Provide just the wrapping key back to the client
                                                        outb->append(id, ' ');
                                                        Base64::Encode(reinterpret_cast<const uint8_t *>(wrapping_key.data()), wrapping_key.size(), outb);
                                                        outb->append('\n');
                                                } catch (const std::exception &e) {
                                                        SLog("Failed:", e.what(), "\n");
                                                }
                                        }

                                        if (trace)
                                                SLog("Took ", duration_repr(Timings::Microseconds::Since(before_)), "\n");
                                }
                        }

                        c->iov.append("HTTP/1.1 200 OK\r\nServer: "_s32);
                        c->iov.append(server_name);
                        c->iov.append("\r\nContent-Type: text/plain\r\n"_s32);
                        set_response_connection_header(c);
                        maybe_extend_lease(c);

                        const auto content_len = outb->size() - resp_offset;

                        c->iov.append(_S("Content-Length: "));

                        const auto o = outb->size();
                        outb->append(content_len);

                        c->iov.append_range({o, outb->size() - o});
                        c->iov.append(_S("\r\n\r\n"));

                        c->iov.append_range({resp_offset, content_len});
                        return try_flush(c);
                } else if (path.Eq(_S("/unwrap"))) {
                        INC_REQ(unwrap);

                        if (!req_method_check(c, "POST"_s32))
                                return false;

                        if (!c->state.cur_req.auth) {
                                build_response(c, "407 Authentication Required"_s32);
                                return try_flush(c);
                        }

                        if (secure_enclave.locked) {
                                build_response(c, "403 Forbidden"_s32, "KMS is LOCKED"_s32);
                                return try_flush(c);
                        }

                        // array of arrays, and each array must be of size 2, containing
                        // (object id:string, and WRAPPED key:string)
                        //
                        // We 'll access the wrapping key stored earlier using /set_keys or /create_keys
                        // decrypt it using KMS's enc_key, and then use the wrapping key to unwrap the wrapped key
                        // and return it back to the client.
                        std::unordered_map<str_view32, str_view32> all;

                        for (const auto line : content.Split('\n')) {
                                auto[objid, wrapped_key_base64] = line.Divided(' ');

                                objid.TrimWS();
                                wrapped_key_base64.TrimWS();

                                if (objid && wrapped_key_base64) {
                                        if (false == verify_objid(objid) || wrapped_key_base64.size() > 512) {
                                                build_response(c, "400 Bad Request"_s32);
                                                return try_flush(c);
                                        }

                                        if (!auth_check(c, objid.as_s32(), O_RDONLY)) {
                                                build_response(c, "401 Unauthorized"_s32);
                                                return try_flush(c);
                                        }

                                        all.insert({objid, wrapped_key_base64});
                                }
                        }

                        auto       outb        = c->outb ?: (c->outb = new_buf());
                        const auto resp_offset = outb->size();

                        if (!all.empty()) {
                                auto b = mysql_client.internal_buffer();

                                b->clear();
                                b->append("SELECT id, k FROM keyring WHERE id IN ("_s32);
                                for (const auto &it : all)
                                        b->append('\'', escaped_repr(it.first), "',"_s32);

                                if (b->back() == ',') {
                                        static constexpr bool trace{false};

                                        b->pop_back();
                                        b->append(')');

                                        const auto before = Timings::Microseconds::Tick();

                                        if (!mysql_client.exec_stmt(false, b->data(), b->size())) {
                                                build_response(c, "500 Internal Server Error"_s32);
                                                return try_flush(c);
                                        }

                                        auto     rows = mysql_client.rows();
                                        uint64_t iv[2];

                                        if (trace)
                                                SLog("Took ", duration_repr(Timings::Microseconds::Since(before)), "\n");

                                        const auto before_ = Timings::Microseconds::Tick();

                                        for (auto &&row : rows) {
                                                const auto id                     = row[0];
                                                const auto encrypted_wrapping_key = row[1];

                                                build_iv(id, iv);

                                                try {
                                                        // Decrypt the stored WRAPPING key using KMS's encryption key
                                                        const auto plaintext = switch_security::ciphers::aes256{{secure_enclave.enc_key, 32}, {reinterpret_cast<const uint8_t *>(iv), 16}}
                                                                                   .decrypt(encrypted_wrapping_key);
                                                        const auto wrapping_key = plaintext.as_s32();

                                                        // Wrapped key is provided in the request(base64 encoded)
                                                        const auto wrapped_key_base64 = all.find(id)->second;

                                                        // base64 decode to get the wrapped key(i.e the ciphertext) we will have to unwrap
                                                        base64_buf.clear();
                                                        if (-1 == Base64::Decode(reinterpret_cast<const uint8_t *>(wrapped_key_base64.data()), wrapped_key_base64.size(), &base64_buf)) {
                                                                build_response(c, "400 Bad Request"_s32);
                                                                return try_flush(c);
                                                        }

                                                        const auto wrapped_key = base64_buf.as_s32();

                                                        // OK, now use the wrapping key to unwrap the provided wrapped key(i.e ciphertext)
                                                        // and send it back to the client as plaintext
                                                        const auto unwrapped_key = switch_security::ciphers::aes256{{reinterpret_cast<const uint8_t *>(wrapping_key.data()), wrapping_key.size()},
                                                                                                                    {reinterpret_cast<const uint8_t *>(iv), 16}}
                                                                                       .decrypt(wrapped_key);

                                                        outb->append(id, ' ');

                                                        // base64 encode the unwrapped key(i.e the data key)
                                                        Base64::Encode(reinterpret_cast<const uint8_t *>(unwrapped_key.data()), unwrapped_key.size(), outb);
                                                        outb->append('\n');
                                                } catch (const std::exception &e) {
                                                        SLog("Failed:", e.what(), "\n");
                                                }
                                        }

                                        if (trace)
                                                SLog("Took ", duration_repr(Timings::Microseconds::Since(before_)), "\n");
                                }
                        }

                        c->iov.append("HTTP/1.1 200 OK\r\nServer: "_s32);
                        c->iov.append(server_name);
                        c->iov.append("\r\nContent-Type: text/plain\r\n"_s32);
                        set_response_connection_header(c);
                        maybe_extend_lease(c);

                        const auto content_len = outb->size() - resp_offset;

                        c->iov.append(_S("Content-Length: "));

                        const auto o = outb->size();
                        outb->append(content_len);

                        c->iov.append_range({o, outb->size() - o});
                        c->iov.append(_S("\r\n\r\n"));

                        c->iov.append_range({resp_offset, content_len});
                        return try_flush(c);
                } else if (path.Eq(_S("/get_secrets"))) {
                        INC_REQ(get_secrets);

                        if (!req_method_check(c, "POST"_s32))
                                return false;

                        if (!c->state.cur_req.auth) {
                                build_response(c, "407 Authentication Required"_s32);
                                return try_flush(c);
                        }

                        if (secure_enclave.locked) {
                                build_response(c, "403 Forbidden"_s32, "KMS is LOCKED"_s32);
                                return try_flush(c);
                        }

                        Buffer _buf, *b{&_buf};

                        b->clear();
                        for (const auto line : content.Split('\n')) {
                                const auto[key_name, props_list] = line.Divided(' ');

                                if (!key_name)
                                        continue;
                                else if (false == verify_objid(key_name)) {
                                        build_response(c, "400 Bad Request"_s32, "Invalid key name"_s32);
                                        return try_flush(c);
                                }

                                if (!auth_check(c, key_name.as_s32(), O_RDONLY)) {
                                        build_response(c, "401 Unauthorized"_s32);
                                        return try_flush(c);
                                }

                                if (false == b->empty())
                                        b->append(" UNION "_s32);
                                if (props_list.empty())
                                        b->append("SELECT id, pair_k, pair_v FROM secrets WHERE id = '"_s32, key_name, "'");
                                else {
                                        b->append("SELECT id, pair_k, pair_v FROM secrets WHERE id = '"_s32, key_name, "' AND prop_k IN ("_s32);

                                        for (const auto name : props_list.Split(',')) {
                                                if (false == verify_secret_prop_name(name)) {
                                                        build_response(c, "400 Bad Request"_s32, "Invalid Property Name"_s32);
                                                        return try_flush(c);
                                                }

                                                b->append('\'', escaped_repr(name), "',"_s32);
                                        }
                                        b->pop_back();
                                        b->append(')');

                                        if (b->size() > 24 * 1024 * 1024) {
                                                build_response(c, "400 Bad Request"_s32, "Unexpected Input"_s32);
                                                return try_flush(c);
                                        }
                                }
                        }

                        if (false == b->empty()) {
                                if (false == mysql_client.exec_stmt(false, b->data(), b->size())) {
                                        build_response(c, "500 Internal Server Error"_s32);
                                        return try_flush(c);
                                }

                                auto       outb = c->outb ?: (c->outb = new_buf());
                                const auto bo   = outb->size();
                                uint8_t    iv[16];

                                for (auto &&row : mysql_client.rows()) {
                                        outb->append(row[0], ' ', row[1], '=');

                                        build_iv(row[0], iv);
                                        try {
                                                const auto plaintext = switch_security::ciphers::aes256{{secure_enclave.enc_key, 32}, {iv, 16}}
                                                                           .decrypt(row[2]);

                                                Base64::Encode(reinterpret_cast<const uint8_t *>(plaintext.data()), plaintext.size(), outb);
                                                outb->append('\n');
                                        } catch (...) {
                                                build_response(c, "400 Bad Request"_s32);
                                                return try_flush(c);
                                        }
                                }

                                const auto clo         = outb->size();
                                const auto content_len = clo - bo;

                                outb->append(content_len);
                                c->iov.append("HTTP/1.1 200 OK\r\nServer: "_s32);
                                c->iov.append(server_name);
                                c->iov.append("\r\nContent-Length: "_s32);
                                c->iov.append_range({clo, outb->size() - clo});
                                c->iov.append("\r\n"_s32);
                                set_response_connection_header(c);
                                maybe_extend_lease(c);
                                c->iov.append("\r\n"_s32);
                                c->iov.append_range({bo, content_len});

                                return try_flush(c);
                        } else {
                                build_response(c, "200 OK"_s32);
                                return try_flush(c);
                        }
                } else if (path.Eq(_S("/set_secrets"))) {
                        INC_REQ(set_secrets);

                        if (!req_method_check(c, "POST"_s32))
                                return false;

                        if (!c->state.cur_req.auth) {
                                build_response(c, "407 Authentication Required"_s32);
                                return try_flush(c);
                        }

                        if (secure_enclave.locked) {
                                build_response(c, "403 Forbidden"_s32, "KMS is LOCKED"_s32);
                                return try_flush(c);
                        }

                        mysql_client.begin();

                        auto    _b = mysql_client.internal_buffer();
                        auto    _b2{&tbuf};
                        uint8_t iv[16];

                        _b->clear();
                        _b->append("REPLACE INTO secrets VALUES "_s32);
                        for (const auto line : content.Split('\n')) {
                                auto[key_name, props_list] = line.Divided(' ');

                                if (!key_name)
                                        continue;
                                else if (false == verify_objid(key_name)) {
                                        build_response(c, "400 Bad Request"_s32, "Unexpected ID"_s32);
                                        return try_flush(c);
                                }

                                if (!auth_check(c, key_name.as_s32(), O_RDONLY)) {
                                        build_response(c, "401 Unauthorized"_s32);
                                        return try_flush(c);
                                }

                                build_iv(key_name, iv);

                                // Expecting (key, pair)
                                _b2->clear();
                                _b2->append("DELETE FROM secrets WHERE id = '", escaped_repr(key_name), "' AND pair_k IN ("_s32);
                                for (const auto pair : props_list.Split(',')) {
                                        const auto[name, value] = pair.Divided('=');

                                        if (false == verify_secret_prop_name(name)) {
                                                build_response(c, "400 Bad Request"_s32, "Unexpected propery"_s32);
                                                return try_flush(c);
                                        }

                                        if (value.empty()) {
                                                // to be deleted
                                                _b2->append("'", escaped_repr(name), "',"_s32);
                                        } else {
                                                _b->append("('", escaped_repr(key_name), "', '", escaped_repr(name), "','"_s32);

                                                try {
                                                        base64_buf.clear();

                                                        if (-1 == Base64::Decode(reinterpret_cast<const uint8_t *>(value.data()), value.size(), &base64_buf)) {
                                                                build_response(c, "400 Bad Request"_s32, "Failed to decode property value"_s32);
                                                                return try_flush(c);
                                                        }

                                                        // Encrypt using our encryption key
                                                        // TODO: encrypt secret_name and property name as well
                                                        const auto ciphertext = switch_security::ciphers::aes256{{secure_enclave.enc_key, 32}, {iv, 16}}
                                                                                    .encrypt(base64_buf.as_s32());

                                                        _b->append(escaped_repr(ciphertext.data(), ciphertext.size()), "'),"_s32);
                                                } catch (...) {
                                                        mysql_client.rollback();
                                                        build_response(c, "400 Bad Request"_s32, "Unexpected propery"_s32);
                                                        return try_flush(c);
                                                }
                                        }
                                }
                                if (_b2->back() == ',') {
                                        _b2->pop_back();
                                        _b2->append(')');
                                        if (false == mysql_client.exec_stmt(false, _b2->data(), _b2->size())) {
                                                mysql_client.rollback();
                                                build_response(c, "500 Internal Server Error"_s32);
                                                return try_flush(c);
                                        }
                                }

                                if (_b->size() > 24 * 1024 * 1024) {
                                        build_response(c, "400 Bad Request"_s32, "Unexpected Input"_s32);
                                        return try_flush(c);
                                }
                        }

                        if (_b->back() == ',') {
                                _b->pop_back();
                                if (false == mysql_client.exec_stmt(false, _b->data(), _b->size())) {
                                        mysql_client.rollback();
                                        build_response(c, "500 Internal Server Error"_s32);
                                        return try_flush(c);
                                }
                        }

                        mysql_client.commit();
                        build_response(c, "200 OK"_s32);
                        return try_flush(c);
                } else {
                        build_response(c, "404 Not Found"_s32);
                        return try_flush(c);
                }

                return true;
        };

        const auto read_content = [&](auto c) {
                auto       b{c->inb};
                const auto so_far = b->size() - b->offset();

                if (so_far < c->state.cur_req.content_length)
                        return true;
                else {
                        const str_view32 content(b->data() + b->offset(), c->state.cur_req.content_length);

                        c->flags ^= unsigned(connection::Flags::state_have_headers);
                        b->advance_offset(c->state.cur_req.content_length);

                        return process_req(c, c->state.cur_req.path, content);
                }
        };

        const auto read_headers = [&](auto c) -> bool {
                auto       b{c->inb};
                str_view32 s, method, path;
                const auto e{b->end()};

                for (;;) {
                        const auto *p{b->data() + b->offset()};

                        while (p != e && isspace(*p))
                                ++p;

                        if (p == e) {
                                put_buf(b);
                                c->inb = nullptr;
                                return true;
                        }

                        for (method.p = p; p != e && !isblank(*p); ++p)
                                continue;

                        method.SetEnd(p);
                        if (p == e)
                                return true;
                        else if (!isblank(*p)) {
                                shutdown(c, __LINE__, true);
                                return false;
                        }

                        for (++p; p != e && isblank(*p); ++p)
                                continue;

                        for (path.p = p; p != e && !isspace(*p); ++p)
                                continue;
                        if (p == e)
                                return true;

                        for (path.SetEnd(p); p != e && isblank(*p); ++p)
                                continue;

                        if (str_view32 s(p, std::distance(const_cast<const char *>(p), const_cast<const char *>(e))); s.size() < "HTTP/1.1"_len)
                                return true;
                        else if (!s.BeginsWith(_S("HTTP/"))) {
                                shutdown(c, __LINE__, true);
                                return false;
                        } else
                                p += "HTTP/"_len;

                        c->state.cur_req.expect_connection_close = false;

                        {
                                uint32_t major{0}, minor{0};

                                while (p != e && isdigit(*p))
                                        major = major * 10 + (*(p++) - '0');

                                if (p != e && *p == '.') {
                                        for (++p; p != e && isdigit(*p); ++p)
                                                minor = minor * 10 + (*p - '0');
                                }

                                if (major > 1 || (major == 1 && minor >= 1))
                                        c->state.cur_req.expect_connection_close = true;
                        }

                        while (p != e && *p != '\r' && *p != '\n')
                                ++p;

                        if (*p == '\r' && p[1] == '\n')
                                p += 2;
                        else if (*p == '\n')
                                ++p;
                        else
                                return true;

                        tl::optional<uint64_t>              content_length;
                        tl::optional<authenticated_session> auth;

                        for (;;) {
                                str_view32 n, v;

                                for (n.p = p;; ++p) {
                                        if (p == e)
                                                return true;
                                        else if (*p == ':') {
                                                n.SetEnd(p);

                                                for (++p; p != e && isblank(*p); ++p)
                                                        continue;

                                                for (v.p = p;; ++p) {
                                                        if (p == e)
                                                                return true;
                                                        else if (*p == '\r' && p[1] == '\n') {
                                                                v.SetEnd(p);
                                                                p += 2;
                                                                break;
                                                        } else if (*p == '\n') {
                                                                v.SetEnd(p++);
                                                                break;
                                                        }
                                                }
                                                break;
                                        } else if (*p == '\r' && p[1] == '\n') {
                                                n.SetEnd(p);
                                                p += 2;
                                                break;
                                        } else if (*p == '\n') {
                                                n.SetEnd(p++);
                                                break;
                                        }
                                }

                                if (!n) {
                                        std::size_t len;

                                        if (method.Eq(_S("POST"))) {
                                                if (!content_length) {
                                                        c->flags |= unsigned(connection::Flags::shutdown_onflush);
                                                        build_response(c, "411 Length Required"_s32);
                                                        return try_flush(c);
                                                }

                                                len = content_length.value();

                                                if (len > 64 * 1024 * 1024) {
                                                        c->flags |= unsigned(connection::Flags::shutdown_onflush);
                                                        build_response(c, "413 Request Entity Too Large"_s32);
                                                        return try_flush(c);
                                                }
                                        } else if (method.Eq(_S("GET"))) {
                                                if (content_length) {
                                                        c->flags |= unsigned(connection::Flags::shutdown_onflush);
                                                        build_response(c, "400 Bad Request"_s32, "GET request with content length specified"_s32);
                                                        return try_flush(c);
                                                }

                                                len = 0;
                                        } else {
                                                c->flags |= unsigned(connection::Flags::shutdown_onflush);
                                                build_response(c, "406 Not Acceptable"_s32);
                                                return try_flush(c);
                                        }

                                        c->state.cur_req.auth           = std::move(auth);
                                        c->state.cur_req.method         = method;
                                        c->state.cur_req.path           = path;
                                        c->state.cur_req.content_length = len;
                                        c->flags |= unsigned(connection::Flags::state_have_headers);
                                        b->set_offset(std::distance(const_cast<const char *>(b->data()), p));

                                        if (!read_content(c))
                                                return false;
                                        else {
                                                if (0 == (c->flags & unsigned(connection::Flags::state_have_headers))) {
                                                        // will try again, we support pipelining
                                                        break;
                                                } else {
                                                        // there's more, not available yet
                                                        return true;
                                                }
                                        }
                                } else {
                                        v.TrimWS();
                                        if (n.EqNoCase(_S("Content-Length")))
                                                content_length = v.as_uint64();
                                        else if (n.EqNoCase(_S("Connection"))) {
                                                if (v.EqNoCase(_S("close")))
                                                        c->state.cur_req.expect_connection_close = false;
                                                else if (v.EqNoCase(_S("keep-alive")) || v.Eq(_S("keepalive")))
                                                        c->state.cur_req.expect_connection_close = true;
                                        } else if (n.EqNoCase(_S("Authorization"))) {
                                                static constexpr bool trace{false};

                                                if (false == secure_enclave.locked) {
                                                        const auto[type, credentials] = v.Divided(' ');

                                                        if (type.Eq(_S("KMS"))) {
                                                                // If it's locked, we have no way to verify the token
                                                                try {
                                                                        tbuf.clear();
                                                                        if (Base64::Decode(reinterpret_cast<const uint8_t *>(credentials.data()), credentials.size(), &tbuf) < 1) {
                                                                                if (trace)
                                                                                        SLog("Failed to decode base64 [", credentials, "]\n");

                                                                                auth.reset();
                                                                        } else {
                                                                                uint8_t iv[16];

                                                                                build_iv("**"_s32, iv);

                                                                                const auto decrypted = switch_security::ciphers::aes256{{secure_enclave.enc_key, 32}, {iv, 16}}.decrypt(tbuf.as_s32());

                                                                                auth = secure_enclave.parse_token(decrypted.as_s32(), now);
                                                                        }
                                                                } catch (...) {
                                                                        auth.reset();
                                                                }
                                                        } else {
                                                                if (trace)
                                                                        SLog("Unexpected type [", type, "]\n");
                                                        }
                                                }
                                        }
                                }
                        }
                }

                return true;
        };

        const auto process_input = [&](auto c) -> bool {
                static constexpr bool trace{false};

                if (trace)
                        SLog("Connection buffer size ", c->inb->size(), "\n");

                if (c->flags & unsigned(connection::Flags::state_have_headers)) {
                        if (!read_content(c))
                                return false;
                        else if (0 == (c->flags & unsigned(connection::Flags::state_have_headers))) {
                                // OK, read all the content, we don't have headers, look for another request (pipelined)
                                return read_headers(c);
                        } else {
                                // There's more, not available yet
                                return true;
                        }
                } else
                        return read_headers(c);
        };

        const auto try_read = [&](auto c) {
                static constexpr bool trace{false};
                auto                  b = c->inb;
                auto                  fd{c->fd};
                int                   n;

                if (!b)
                        b = c->inb = new_buf();

                if (auto ssl = c->ssl) {
                        ERR_clear_error();

                        if ((c->flags & unsigned(connection::Flags::tls_want_accept)) && !try_ssl_accept(c))
                                return false;

                        c->flags &= ~unsigned(connection::Flags::tls_want_read);

                        // It turns out, we need to keep reading until we have drained the socket buffer
                        // otherwise we may get X bytes, and SSL_read() reads Y (< X) and obviously we don't
                        // get another POLLIN (level-triger semantics), so we need to drain it until we are done
                        // XXX: figure out why this is the case, and what we can do to improve it
                        for (const auto saved{b->size()};;) {
                                b->reserve(8192);

                                const auto r = SSL_read(ssl, b->data() + b->size(), b->capacity());

                                if (trace)
                                        SLog("Read ", r, "\n");

                                if (r < 0) {
                                        if (const auto reason = SSL_get_error(ssl, r); reason == SSL_ERROR_WANT_READ) {
                                                if (trace)
                                                        SLog("want read ", b->size() - saved, "\n");

                                                c->flags |= unsigned(connection::Flags::tls_want_read);
                                                return saved != b->size() ? process_input(c) : true;
                                        } else if (reason == SSL_ERROR_WANT_WRITE) {
                                                if (trace)
                                                        SLog("Want write\n");

                                                c->flags |= unsigned(connection::Flags::tls_want_write);
                                                poll_out_avail(c);
                                                return saved != b->size() ? process_input(c) : true;
                                        } else if (reason == SSL_ERROR_WANT_ACCEPT) {
                                                if (trace)
                                                        SLog("want accept\n");

                                                c->flags |= unsigned(connection::Flags::tls_want_accept);
                                                return saved != b->size() ? process_input(c) : true;
                                        } else if (reason == SSL_ERROR_SYSCALL) {
                                                if (trace)
                                                        SLog("syscall\n");

                                                if (EAGAIN != errno && EINTR != errno) {
                                                        shutdown(c, __LINE__, true);
                                                        return false;
                                                } else {
                                                        if (saved != b->size()) {
                                                                // got some data
                                                                return process_input(c);
                                                        }
                                                        return true;
                                                }
                                        } else if (reason == SSL_ERROR_SSL) {
                                                if (trace)
                                                        SLog("SSL error\n");

                                                log_SSL_error(__LINE__);
                                                shutdown(c, __LINE__, true);
                                                return false;
                                        } else if (reason == SSL_ERROR_ZERO_RETURN) {
                                                if (trace)
                                                        SLog("ZERO RETURN\n");

                                                shutdown(c, __LINE__, false);
                                                return false;
                                        } else if (reason != SSL_ERROR_NONE) {
                                                if (trace)
                                                        SLog("Other Error\n");

                                                shutdown(c, __LINE__, true);
                                                return false;
                                        } else {
                                                if (trace)
                                                        SLog("No Error?\n");

                                                return saved != b->size() ? process_input(c) : true;
                                        }
                                } else if (0 == r) {
                                        {
                                                shutdown(c, __LINE__, false);
                                                return false;
                                        }
                                }

                                b->advance_size(r);
                        }

                } else {
                        if (-1 == ioctl(fd, FIONREAD, &n)) {
                                // ioctl() is not supposed to fail here
                                // but if it does, let's try to read in some content
                                n = 512;
                        }

                        b->reserve(n);
                        if (const auto r = read(fd, b->data() + b->size(), n); 0 == r) {
                                shutdown(c, __LINE__, false);
                                return false;
                        } else if (-1 == r) {
                                if (EINTR == errno || EAGAIN == errno)
                                        return true;
                                else {
                                        shutdown(c, __LINE__, true);
                                        return false;
                                }
                        } else {
                                b->advance_size(r);
                                return process_input(c);
                        }
                }
        };

        if (-1 == bind(listener, reinterpret_cast<sockaddr *>(&sa), sizeof(sa))) {
                Print("Failed to bind socket:", strerror(errno), "\n");
                return 1;
        }

        if (-1 == listen(listener, 128)) {
                Print("Failed to initiate listener:", strerror(errno), "\n");
                return 1;
        }

        Switch::SetReusePort(listener, 1);

        io_events.insert(listener, POLLIN, &listener);
        Print("Accepting connections at ", use_http ? "http" : "https", "://", e, "\n");

        for (;;) {
                auto r = io_events.poll(1e3);

                if (-1 == r) {
                        if (errno == EINTR || errno == EAGAIN)
                                continue;
                        else {
                                Print("Failed to poll for I/O: ", strerror(errno), "\n");
                                return 1;
                        }
                }

                now = time(nullptr);

                if (now != past) {
                        const auto &r{runtime_metrics.reqs};

                        past = now;
                        if (runtime_metrics.if_addr4) {
                                mysql_client.exec("REPLACE INTO kms_runtime_metrics SET  ip_addr4 = ", runtime_metrics.if_addr4, ", op_create_keys = ", r.create_keys, ", op_delete_keys = ", r.delete_keys, ", op_set_keys = ", r.set_keys, ", op_encrypt = ", r.encrypt, ", op_decrypt = ", r.decrypt, ",op_get_keys = ", r.get_keys, ", op_unwrap = ", r.unwrap, ", op_get_secrets = ", r.get_secrets, ", op_set_secrets = ", r.set_secrets);
                        }
                }

                for (const auto it : io_events.new_events(r)) {
                        const auto events{it->events};
                        const int  fd = *static_cast<int *>(it->data.ptr);

                        if (fd == listener) {
                                if (!(events & POLLIN))
                                        continue;

                                socklen_t sa_len(sizeof(sa));
                                auto      fd = accept4(listener, reinterpret_cast<sockaddr *>(&sa), &sa_len, SOCK_NONBLOCK | SOCK_CLOEXEC);

                                if (fd == -1) {
                                        if (errno == EINTR || errno == EAGAIN)
                                                continue;
                                        else {
                                                Print("Unable to accept new connection:", strerror(errno), "\n");
                                                return 1;
                                        }
                                }

                                auto con = std::make_unique<connection>(fd);
                                auto c   = con.get();

                                c->last_activity = now;
                                io_events.insert(fd, POLLIN, c);
                                connections_map.emplace(c->fd, std::move(con));

                                if (ssl_ctx) {
                                        auto ssl = c->ssl = SSL_new(ssl_ctx.get());

                                        if (nullptr == ssl) {
                                                Print("Failed to initialize SSL, will abort\n");
                                                return 1;
                                        }

                                        ERR_clear_error();
                                        SSL_set_accept_state(ssl);
                                        SSL_set_fd(ssl, fd);
                                        SSL_set_app_data(ssl, c);

                                        if (false == try_ssl_accept(c))
                                                continue;
                                }

                                try_read(c);
                                continue;
                        }

                        auto c = reinterpret_cast<connection *>(it->data.ptr);

                        if (events & (POLLERR | POLLHUP)) {
                                shutdown(c, __LINE__, c->inb && !c->inb->empty());
                                continue;
                        }

                        if (events & POLLIN) {
                                c->last_activity = now;
                                if (!try_read(c))
                                        continue;
                        }

                        if (events & POLLOUT)
                                try_write(c);
                }
        }

        return 0;
}
