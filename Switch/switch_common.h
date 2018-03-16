#pragma once
#include "switch_numops.h"
#ifdef HAVE_ICU
#include <unicode/normalizer2.h>
#include <unicode/stringpiece.h>
#include <unicode/uchar.h>
#include <unicode/unistr.h>
#include <unicode/ustring.h>
#include <unicode/utf8.h>
#endif
#include <string.h>
#include "switch_compiler_aux.h"


// http://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html
// returns true if this is a static const, most likely allocated in RODATA segment
// This is _very_ useful, for we can check if that's the case and just don't alloc()/copy/free() data instead just point to them
extern char etext, edata, end;

template <typename T>
[[gnu::always_inline]] inline static bool IsConstant(T *const expr)
{
        if (__builtin_constant_p(expr))
                return true;
        else
        {
                // This is only valid in either a macro or an inline function.
                // However, if you use it in an inlined function and pass an argument of the function as the argument to the built-in,
                // GCC never returns when you call the inline function with a string constant or compount literal, and does not return 1 when you
                // pass a constant number value to the inline function unless you specify the -o opetion
                //
                // So what really need to do is perhaps check if this is in RODATA segment, but how to do that?
                // Turns out, we can
                // Ref: http://stackoverflow.com/questions/4308996/finding-the-address-range-of-the-data-segment
                // Ref: http://manpages.ubuntu.com/manpages/jaunty/man3/end.3.html
                const uintptr_t addr = (uintptr_t)expr;

                return addr >= (uintptr_t)&etext && addr < (uintptr_t)&edata;
        }
}

template <typename LT, typename CT = char>
struct strwithlen
{
        const CT *p;
        LT len;

        using iterator = const CT *;
        using value_type = CT;

        constexpr auto as_s32() const noexcept
        {
                return strwithlen<uint32_t, CT>{p, uint32_t(len)};
        }

        constexpr auto as_s16() const noexcept
        {
                return strwithlen<uint16_t, CT>{p, uint16_t(len)};
        }

        constexpr auto as_s8() const noexcept
        {
                return strwithlen<uint8_t, CT>{p, uint8_t(len)};
        }

        strwithlen ws_trimmed() const noexcept
        {
                strwithlen res(p, len);

                res.TrimWS();
                return res;
        }

        strwithlen<LT> Div(const CT c)
        {
                if (const auto *const p = Search(c))
                {
                        const auto res = SuffixFrom(p + 1);

                        SetEnd(p);
                        return res;
                }
                else
                        return {};
        }

        std::pair<strwithlen, strwithlen> Divided(const CT c) const
        {
                if (const auto *const p = Search(c))
                        return {PrefixUpto(p), SuffixFrom(p + 1)};
                else
                        return {{this->p, this->len}, {}};
        }

        // warning: with copy assignment operator not allowed in union
        // UODATE: Well, we don't care now, C++11 allows for non PODs in unions as long as you initialize them
        strwithlen &operator=(const strwithlen &o)
        {
                p = o.p;
                len = o.len;
                return *this;
        }

        strwithlen &operator=(const CT *const s)
        {
                p = s;
                len = strlen(s);
                return *this;
        }

        [[gnu::always_inline]] inline bool IsConstant()
        {
                return p == nullptr || ::IsConstant(p);
        }

        inline constexpr auto size() const noexcept
        {
                return len;
        }

        inline constexpr auto data() const noexcept
        {
                return p;
        }

        const CT *First(const CT c) const
        {
                for (const CT *it = p, *const e = p + len; it != e; ++it)
                {
                        if (*it == c)
                                return it;
                }

                return nullptr;
        }

        constexpr strwithlen SubstringFrom(const CT *const s) const
        {
                return strwithlen(s, (p + len) - s);
        }

        constexpr strwithlen SubstringFrom(const LT o) const // Equivalent to SuffixFrom()
        {
                return strwithlen(p + o, len - o);
        }

        LT CountOf(const CT c) const
        {
                LT res{0};

                for (const CT *it = p, *const e = it + len; it != e; ++it)
                {
                        if (*it == c)
                                ++res;
                }
                return res;
        }

        LT CountOf(const strwithlen needle) const
        {
                strwithlen in(p, len);
                LT cnt{0};

                while (const CT *const p = in.Search(needle))
                        in.AdvanceTo(p + needle.len);

                return cnt;
        }

        [[gnu::always_inline]] inline void FreeIfNotConstant()
        {
                if (IsConstant() == false)
                        free(const_cast<char *>(p));
                p = nullptr;
        }

        void Print() const
        {
                printf("%.*s\n", len, p);
        }

        constexpr auto front() const
        {
                return *p;
        }

        constexpr auto back() const
        {
                return p[len - 1];
        }

        inline const CT *Search(const CT c) const
        {
                if (sizeof(CT) != sizeof(char))
                {
                        for (const CT *it = p, *const e = p + len; it != e; ++it)
                        {
                                if (*it == c)
                                        return it;
                        }
                        return nullptr;
                }
                else
                        return (char *)memchr((void *)p, c, len);
        }

        inline const typename std::enable_if<std::is_same<char, CT>::value, CT *>::type SearchR(const char c) const
        {
                return (CT *)memrchr((void *)p, c, len);
        }

        inline typename std::enable_if<std::is_same<char, CT>::value, CT *>::type SearchRWithLimit(const CT c, const LT limit) const
        {
                const auto l = std::min<LT>(len, limit);

                return (CT *)memrchr(p + len - l, c, l);
        }

        inline const CT *Search(const strwithlen needle) const
        {
                // Apparently, http://volnitsky.com/project/str_search/
                // std::search() is _MUCH_ faster than glibc's memmem(), to the extent that it #including <algorithm> for it
                // XXX: std::search() is giving us end sometimes? is this what we should expect
                // Maybe we should just use std::find_first_of()
                if (sizeof(CT) == sizeof(char))
                {
                        return (char *)memmem(p, len, needle.p, needle.len);
                }
                else
                {
                        const CT *const res = std::search(p, p + len, needle.p, needle.p + needle.len);

                        return res == p + len ? nullptr : res;
                }
        }

        inline const CT *Search(const CT *const needle, const LT needleLen) const
        {
                return Search(strwithlen(needle, needleLen));
        }

        // We can now deal with this just fine, C++11 makes it possible
        constexpr strwithlen()
            : p{nullptr}, len{0}
        {
        }

        strwithlen(const char *const s)
            : p{s}, len(strlen(s))
        {
        }

        constexpr strwithlen(const char *const s, const char *const e)
            : p{s}, len{LT(e - s)}
        {
        }

        int constexpr Cmp(const CT *const s, const LT l) const
        {
                return l == len ? memcmp(p, s, l)
                                : len < l ? ({const auto r = memcmp(p, s, len); r == 0 ? -1 : r; })
                                          : ({const auto r = memcmp(p, s, l); r == 0 ? 1 : r; });
        }

        constexpr int Cmp(const strwithlen *const o) const
        {
                return Cmp(o->p, o->len);
        }

        constexpr int Cmp(const strwithlen &o) const
        {
                return Cmp(o.p, o.len);
        }

        constexpr bool operator<(const strwithlen &o) const
        {
                return Cmp(&o) < 0;
        }

        constexpr bool operator>(const strwithlen &o) const
        {
                return Cmp(&o) > 0;
        }

        [[gnu::always_inline]] constexpr static uint32_t MaxLength() noexcept
        {
                constexpr uint64_t lens[] = {0, UINT8_MAX, UINT16_MAX, 0, UINT32_MAX, 0, 0, 0, UINT64_MAX};
                return lens[sizeof(LT)];
        }

        [[ gnu::noinline, noreturn ]] static void fail_len_check(const uint32_t l)
        {
                std::abort();
        }

        // using const uint32_t l not const LT l to silence compiler warnings
        strwithlen(const CT *const s, const uint32_t l)
            : p{s}
        {
                if (sizeof(LT) < sizeof(uint32_t) && unlikely(l > MaxLength()))
                        fail_len_check(l);

                len = l;
        }

        enum class NoMaxLenCheck
        {

        };

        // A special variant; if you *know* l<=MaxLength(), use this constuctor instead
        // It's constexpr
        constexpr strwithlen(const CT *const s, const uint32_t l, const NoMaxLenCheck)
            : p{s}, len{LT(l)}
        {
        }

        constexpr operator bool() const
        {
                return len;
        }

        constexpr bool operator==(const strwithlen<LT> &o) const
        {
                return len == o.len && memcmp(p, o.p, len) == 0;
        }

        constexpr bool operator!=(const strwithlen<LT> &o) const
        {
                return len != o.len || memcmp(p, o.p, len);
        }

        // See range_base::Contains()
        constexpr bool Contains(const CT *const ptr) const
        {
                return sizeof(CT) == 8
                           ? ptr >= p && ptr < (p + len)
                           : uint32_t(ptr - p) < len;
        }

        constexpr bool Contains(const char *const op, const LT olen) const
        {
                return op >= p && op + olen <= p + len;
        }

        strwithlen Substr(const LT o, const LT l) const
        {
                assert(o + l <= len);

                return {p + o, l};
        }

        strwithlen Inset(const LT l, const LT r) const
        {
                const auto n = l + r;

                assert(n <= len);
                assert(n <= len);

                return {p + l, len - n};
        }

        template <typename T>
        constexpr bool Contains(const T &s) const
        {
                return Contains(s.p, s.len);
        }

        template <typename T>
        constexpr bool Contains(const T *const s) const
        {
                return Contains(*s);
        }

        inline bool Intersects(const CT *const op, const LT olen) const
        {
                const auto *const e = p + len, *const eo = op + olen;

                return e >= op && p <= eo;
        }

        template <typename T>
        inline bool Intersects(const T &s) const
        {
                return Intersects(s.p, s.len);
        }

        template <typename T>
        inline bool Intersects(const T *const s) const
        {
                return Intersects(*s);
        }

        constexpr void reset() noexcept
        {
                p = nullptr;
                len = 0;
        }

        // Not using const LT l, so that compiler won't have to complain about missing casts
        constexpr void Set(const CT *const ptr, const uint32_t l)
        {
                len = l;
                p = ptr;
        }

        typename std::enable_if<std::is_same<char, CT>::value>::type Set(const char *const ptr)
        {
                p = ptr;
                SetLengthExpl(strlen((char *)p));
        }

        typename std::enable_if<std::is_same<char, CT>::value, bool>::type printable() const noexcept
        {
                return printable_impl(p, len);
        }

        struct utils
        {
#ifdef HAVE_ICU
                static inline bool is_digit(const uint32_t v) noexcept
                {
                        return std::is_same<char, CT>::value ? isdigit(v) : u_isdigit(v);
                }

                static inline bool is_blank(const uint32_t v) noexcept
                {
                        return std::is_same<char, CT>::value ? isblank(v) : u_isblank(v);
                }

                static inline bool is_space(const uint32_t v) noexcept
                {
                        return std::is_same<char, CT>::value ? isspace(v) : u_isspace(v);
                }

                static inline unsigned to_lower(const uint32_t v) noexcept
                {
                        return std::is_same<char, CT>::value ? tolower(v) : u_tolower(v);
                }

                static inline unsigned to_upper(const uint32_t v) noexcept
                {
                        return std::is_same<char, CT>::value ? toupper(v) : u_toupper(v);
                }
#else
                static inline bool is_digit(const uint32_t v) noexcept
                {
                        return isdigit(v);
                }

                static inline bool is_blank(const uint32_t v) noexcept
                {
                        return isblank(v);
                }

                static inline bool is_space(const uint32_t v) noexcept
                {
                        return isspace(v);
                }

                static inline unsigned to_lower(const uint32_t v) noexcept
                {
                        return tolower(v);
                }

                static inline unsigned to_upper(const uint32_t v) noexcept
                {
                        return toupper(v);
                }
#endif
        };

	bool all_of(const CT c) const noexcept
	{
		for (CT i{0}; i != len; ++i)
		{
			if (p[i] != c)
				return false;
		}
		return true;
	}

	bool all_of_digits() const noexcept
	{
		return IsDigits();
	}

        inline bool IsDigits() const
        {
                const CT *it = p, *const e = it + len;

                while (likely(it != e))
                {
                        if (!isdigit(*it))
                                return false;
                        ++it;
                }

                return len;
        }

        bool operator==(const CT *ptr) const noexcept
        {
                const auto *it = p, *const end = p + len;

                while (it != end && *it == *ptr)
                {
                        ++it;
                        ++ptr;
                }

                return it == end && *ptr == '\0';
        }

        double AsDouble() const
        {
                const auto *it = p, *const e = p + len;
                double sign;

                if (it == e)
                        return 0; // strtod() returns 0 for empty input
                else if (*it == '-')
                {
                        ++it;
                        sign = -1;
                }
                else if (unlikely(*it == '+'))
                {
                        ++it;
                        sign = 1;
                }
                else
                        sign = 1;

                double v{0};

                do
                {
                        if (*it == '.' || *it == ',') // support both radix characters
                        {
                                double exp{0};
                                // We could just use: double pow10{10.0} and in each iteration
                                // pow10*=10.0
                                // and then just use v += exp * (1.0l / pow10)
                                // but because we usualyl expect a digit digits for the exponents, we 'll just use a switch to avoid
                                // the multiplication
                                // UPDATE: nevermind, we 'll do that later
                                double pow10{1.0}; // faster than pow(exp, totalExpDigits)
                                // we could use case(totalExpDigits) in order to avoid this, or just use
                                //constexpr uint64_t scale[] = {pow(10, 1), pow(10, 2), pow(10, 3), pow(10, 4), pow(10, 5), pow(10, 6), pow(10, 7), ...

                                for (++it; it != e; ++it)
                                {
                                        if (likely(isdigit(*it)))
                                        {
                                                exp = exp * 10 + (*it - '0');
                                                pow10 *= 10.0;
                                        }
                                        else
                                        {
                                                // We could have handled exponent (e|E)
                                                // See: http://www.leapsecond.com/tools/fast_atof.c
                                                // but it's not really worth it; we never use it
                                                return NAN;
                                        }
                                }

                                return (v + (exp * (1.0L / pow10))) * sign;
                        }
                        else if (likely(isdigit(*it)))
                                v = v * 10 + (*(it++) - '0');
                        else
                                return NAN;

                } while (it != e);

                return v * sign;
        }

        typename std::enable_if<std::is_same<char, CT>::value, uint32_t>::type AsUint32() const
        {
                static constexpr uint32_t pow10[10] =
                    {
                        1000000000ul,
                        100000000ul,
                        10000000ul,
                        1000000ul,
                        100000ul,
                        10000ul,
                        1000ul,
                        100ul,
                        10ul,
                        1ul,
                    };

                // this test() and the test for d >= 10 really impact performance
                // so just don't do it
                if (unlikely(len > 10))
                {
                        // throw something?
                        return 0;
                }

                uint32_t res{0}, k{0};

                for (uint32_t i = sizeof_array(pow10) - len; k != len; ++i)
                {
                        const auto d = unsigned(p[k++]) - '0';

                        res += pow10[i] * d;
                }

                return res;
        }

	auto as_uint32() const
	{
		return AsUint32();
	}

        int32_t AsInt32() const
        {
                const auto *it = p, *const e = it + len;

                if (it != e)
                {
                        int32_t v{0};

                        if (*it == '-')
                        {
                                for (++it; it != e && isdigit(*it); ++it)
                                        v = v * 10 + (*it - '0');

                                return -v;
                        }
                        else
                        {
                                for (; it != e && isdigit(*it); ++it)
                                        v = v * 10 + (*it - '0');
                                return v;
                        }
                }

                return 0;
        }

        typename std::enable_if<std::is_same<char, CT>::value, uint64_t>::type AsUint64() const
        {
                static constexpr uint64_t pow10[20] __attribute__((__aligned__(64))) = // 20 because 20 digits are enough for a 64bit number
                    {
                        10000000000000000000ul,
                        1000000000000000000ul,
                        100000000000000000ul,
                        10000000000000000ul,
                        1000000000000000ul,
                        100000000000000ul,
                        10000000000000ul,
                        1000000000000ul,
                        100000000000ul,
                        10000000000ul,
                        1000000000ul,
                        100000000ul,
                        10000000ul,
                        1000000ul,
                        100000ul,
                        10000ul,
                        1000ul,
                        100ul,
                        10ul,
                        1ul,
                    };

                if (unlikely(len > 20))
                {
                        // throw something?
                        return 0;
                }

                uint64_t res{0};
                uint32_t k{0};

                for (uint32_t i = sizeof_array(pow10) - len; k != len; ++i)
                {
                        const auto d = unsigned(p[k++]) - '0';

                        res += pow10[i] * d;
                }

                return res;
        }

	inline auto as_uint64() const
	{
		return AsUint64();
	}

        inline bool Eq(const CT *const ptr) const
        {
                return operator==(ptr);
        }

        inline bool Eq(const CT *const v, const LT l) const
        {
                return l == len && memcmp(v, p, l) == 0;
        }

        inline typename std::enable_if<std::is_same<char, CT>::value, bool>::type EqNoCase(const CT *const v, const LT l) const
        {
                return l == len ? !strncasecmp((char *)v, (char *)p, l) : false;
        }

        typename std::enable_if<std::is_same<char, CT>::value, bool>::type EqNoCase(const CT *v) const
        {
                const auto *it = p, *const e = p + len;

                while (it != e && toupper(*v) == toupper(*it))
                {
                        ++it;
                        ++v;
                }

                return it == e && *v == '\0';
        }

        [[gnu::always_inline]] inline bool EqNoCase(const strwithlen &o) const
        {
                return EqNoCase(o.p, o.len);
        }

        inline bool IsEqual(const CT *const ptr, const LT l) const
        {
                return l == len && memcmp(p, ptr, l) == 0;
        }

        inline bool EndsWith(const CT *const v, const LT l) const
        {
                return l <= len && memcmp(p + len - l, v, l) == 0;
        }

        inline bool EndsWithButNoExactMatch(const CT *const v, const LT l) const
        {
                return l < len && memcmp(p + len - l, v, l) == 0;
        }

        inline bool EndsWith(const CT *const v) const
        {
                return EndsWith(v, strlen(v));
        }

        inline bool EndsWithNoCase(const CT *const v) const
        {
                return EndsWithNoCase(v, strlen(v));
        }

        inline typename std::enable_if<std::is_same<char, CT>::value, bool>::type EndsWithNoCase(const CT *const v, const LT l) const
        {
                return l <= len && strncasecmp((char *)p + len - l, (char *)v, l) == 0;
        }

        inline typename std::enable_if<std::is_same<char, CT>::value, bool>::type BeginsWith(const CT *const v, const LT l) const
        {
                return l <= len && memcmp(p, v, l) == 0;
        }

        inline bool EndsWith(const CT c) const
        {
                return len && p[len - 1] == c;
        }

        inline bool HasPrefix(const CT *const v, const LT l) const
        {
                return BeginsWith(v, l);
        }

        inline bool BeginsWith(const CT c) const
        {
                return likely(len) ? *p == c : false;
        }

        inline bool HasPrefix(const CT c) const
        {
                return BeginsWith(c);
        }

        constexpr strwithlen Prefix(const LT l) const
        {
                return strwithlen(p, std::min(len, l));
        }

        constexpr strwithlen Suffix(const LT l) const
        {
                return strwithlen(End() - l, l);
        }

        constexpr strwithlen SuffixFrom(const CT *const offset) const
        {
                return strwithlen(offset, End() - offset);
        }

        strwithlen FirstDigitsSeq() const
        {
                // handy utility function
                for (const char *it = p, *const e = End();; ++it)
                {
                        if (isdigit(*it))
                        {
                                const char *const b = it;

                                for (++it; it != e && isdigit(*it); ++it)
                                        continue;

                                return {b, it};
                        }
                }
                return {};
        }

        constexpr strwithlen SuffixFrom(const LT o) const
        {
                return SuffixFrom(p + o);
        }

        constexpr strwithlen PrefixUpto(const CT *const o) const
        {
                return strwithlen(p, o - p);
        }

        // e.g if (name.Extension().Eq(_S("png"))) { .. }
        strwithlen Extension(const CT c = '.', const LT maxLength = 16) const
        {
                if (const auto *const it = SearchRWithLimit(c, maxLength))
                        return SuffixFrom(it + 1);
                else
                        return {};
        }

        inline typename std::enable_if<std::is_same<char, CT>::value, bool>::type BeginsWithNoCase(const CT *const v, const LT l) const
        {
                return l <= len && strncasecmp((char *)p, (char *)v, l) == 0;
        }

        bool BeginsWith(const CT *ptr) const
        {
                const auto *it = p;
                const auto *const end = p + len;

                while (it != end)
                {
                        if (*it != *ptr)
                                return false;

                        if (++it == end)
                                return true;
                        ++ptr;
                }

                return *ptr == '\0';
        }

        constexpr bool HasPrefix(const CT *ptr) const
        {
                return BeginsWith(ptr);
        }

        template <typename T>
        inline bool BeginsWith(const T &s) const
        {
                return BeginsWith(s.p, s.len);
        }

        template <typename T>
        inline bool BeginsWith(const T *const s) const
        {
                return BeginsWith(s);
        }

        template <typename T>
        inline bool EndsWith(const T *const s) const
        {
                return EndsWith(*s);
        }

        constexpr const CT *End() const
        {
                return p + len;
        }

        void Extend(const LT l)
        {
                len += l;
        }

        inline void SetLengthExpl(const LT l)
        {
                if (sizeof(LT) < sizeof(uint32_t) && unlikely(l > MaxLength()))
                        fail_len_check(l);

                len = l;
        }

        void InitWithCopy(const void *const s, const LT l)
        {
                SetLengthExpl(l);

                if (len)
                {
                        auto *const ptr = (CT *)malloc(len * sizeof(CT));

                        assert(ptr != nullptr);
                        memcpy(ptr, s, len * sizeof(CT));
                        p = ptr;
                }
                else
                        p = nullptr;
        }

        typename std::enable_if<std::is_same<char, CT>::value, CT *>::type ToCString() const
        {
                auto *const r = (CT *)malloc((len * sizeof(CT)) + 1);

                assert(r != nullptr);
                memcpy(r, p, len * sizeof(CT));
                r[len] = '\0';
                return r;
        }

        typename std::enable_if<std::is_same<char, CT>::value, CT *>::type ToCString(CT *const out) const
        {
                memcpy(out, p, len * sizeof(CT));
                out[len] = '\0';
                return out;
        }

        typename std::enable_if<std::is_same<char, CT>::value, CT *>::type ToCString(CT *const out, const uint32_t outSize) const
        {
                assert(len + 1 <= outSize);
                memcpy(out, p, len * sizeof(CT));
                out[len] = '\0';
                return out;
        }

        CT *Copy() const
        {
                auto *const r = (CT *)malloc(len * sizeof(CT));

                assert(r != nullptr);
                memcpy(r, p, len * sizeof(CT));
                return r;
        }

        [[gnu::always_inline]] inline const CT *At(const LT o) const
        {
                return p + o;
        }

        CT *CopyTo(CT *const to) const
        {
                memcpy(to, p, len * sizeof(CT));
                return to + len;
        }

        CT *asLowercase(CT *const out) const
        {
                for (LT i{0}; i != len; ++i)
                        out[i] = tolower(p[i]);

                return out;
        }

        void InitWithCopy(const strwithlen &o)
        {
                InitWithCopy(o.p, o.len);
        }

        void InitWithCopy(const strwithlen *const o)
        {
                InitWithCopy(o->p, o->len);
        }

        constexpr void AdjustRight(const LT v)
        {
                len -= v;
        }

        constexpr void AdjustLeft(const LT v)
        {
                p += v;
                len -= v;
        }

        auto &strip_prefix(const LT v) noexcept
        {
                p += v;
                len -= v;
                return *this;
        }

        auto &strip_suffix(const LT v) noexcept
        {
                len -= v;
                return *this;
        }

        LT CommonPrefixLen(const strwithlen o) const
        {
                const auto *it = p;

                for (const auto *oit = o.p, *const oend = oit + o.len, *const end = p + len;
                     it != end && oit != oend && *it == *oit;
                     ++it, ++oit)
                {
                        continue;
                }

                return it - p;
        }

        constexpr auto isNullTerminated() const
        {
                return !p[len];
        }

        inline strwithlen CommonPrefix(const strwithlen o) const
        {
                return strwithlen(p, CommonPrefixLen(o));
        }

        LT CommonSuffixLen(const strwithlen o) const
        {
                const auto *const e = End(), *const oend = o.End(), *const op = o.p;
                const auto *it = e;

                for (const auto *oit = oend;
                     oit != op && it != p && oit[-1] == it[-1];
                     --it, --oit)
                {
                        continue;
                }

                return e - it;
        }

        inline strwithlen IntersectionOf(const strwithlen o) const
        {
                const auto *const from = p + CommonPrefixLen(o);
                const auto *const upto = End() - CommonSuffixLen(o);

                return strwithlen(from, upto - from);
        }

        inline strwithlen CommonSuffix(const strwithlen o) const
        {
                return SuffixFrom(len - CommonSuffixLen(o));
        }

        inline void StripPrefix(const LT v)
        {
                AdjustLeft(v);
        }

        strwithlen AsTrimmedBy(const LT l) const
        {
                strwithlen res{p, len};

                res.StripSuffix(l);
                return res;
        }

        bool StripPrefix(const CT *const s, const LT l)
        {
                if (BeginsWith(s, l))
                {
                        StripPrefix(l);
                        return true;
                }
                else
                        return false;
        }

        strwithlen digits_prefix() const noexcept
        {
                const auto *it = p;

                for (const auto *const e = it + len; it != e && isdigit(*it); ++it)
                        continue;

                return {p, LT(it - p), NoMaxLenCheck{}};
        }

        bool StripSuffix(const CT *const s, const LT l)
        {
                if (EndsWith(s, l))
                {
                        StripSuffix(l);
                        return true;
                }
                else
                        return false;
        }

        inline void StripTrailingCharacter(const CT c)
        {
                while (len && p[len - 1] == c)
                        --len;
        }

        inline void StripInitialCharacter(const CT c)
        {
                while (len && *p == c)
                {
                        ++p;
                        --len;
                }
        }

        inline void StripSuffix(const LT v)
        {
                AdjustRight(v);
        }

        constexpr bool InRange(const CT *const s) const
        {
                return s >= p && s < p + len;
        }

        constexpr void AdvanceTo(const CT *const to)
        {
                len -= to - p;
                p = to;
        }

        constexpr void advance_to(const CT *const to) noexcept
        {
                len -= to - p;
                p = to;
        }

        constexpr void SetEnd(const CT *const e)
        {
                len = e - p;
        }

        void SetEndTo(const CT c)
        {
                if (const auto *const res = Search(c))
                        SetEnd(res);
        }

        const CT *NextWS() const
        {
                for (const auto *it = p, *const end = End(); it != end; ++it)
                {
                        if (isspace(*it))
                                return it;
                }
                return nullptr;
        }

        constexpr inline LT OffsetAt(const CT *const it) const
        {
                return it - p;
        }

        constexpr inline strwithlen Replica() const
        {
                return {p, len};
        }

        strwithlen &TrimWS() noexcept
        {
                while (len && isspace(*p))
                {
                        ++p;
                        --len;
                }
                while (len && isspace(p[len - 1]))
                        --len;
                return *this;
        }

        strwithlen ws_trimmed() noexcept
        {
                strwithlen res(p, len);

                res.TrimWS();
                return res;
        }

        auto as_length_limited(const uint32_t maxLen) const noexcept
        {
                return strwithlen(p, std::min<LT>(len, maxLen));
        }

        bool IsBlank() const noexcept
        {
                for (const auto *it = p, *const end = p + len; it != end; ++it)
                {
                        if (!isspace(*it))
                                return false;
                }
                return true;
        }

        constexpr bool empty() const noexcept
        {
                return !len;
        }

        constexpr const CT *begin() const
        {
                return p;
        }

        constexpr const CT *end() const
        {
                return p + len;
        }

        struct _segments
        {
                const strwithlen s;
                const CT sep;

                struct iterator
                {
                        strwithlen cur;
                        const CT sep;
                        const CT *next;

                        void Next()
                        {
                                const auto *const e = cur.End();

                                while (next != e && *next != sep)
                                        ++next;
                        }

                        iterator(const strwithlen input, const CT c)
                            : cur(input), sep(c), next(cur.p)
                        {
                                Next();
                        }

                        bool operator!=(const iterator &o) const
                        {
                                return cur.p != o.cur.p;
                        }

                        iterator &operator++()
                        {
                                cur.AdvanceTo(next);
                                if (cur)
                                {
                                        cur.AdjustLeft(1);
                                        ++next;
                                        Next();
                                }
                                return *this;
                        }

                        inline strwithlen operator*() const
                        {
                                return strwithlen(cur.p, next - cur.p);
                        }
                };

                _segments(const strwithlen in, const CT c)
                    : s(in), sep(c)
                {
                }

                iterator begin() const
                {
                        return iterator(s, sep);
                }

                iterator end() const
                {
                        return iterator({s.End(), uint32_t(0)}, sep);
                }
        };

        template <typename F>
        struct _segmentsF
        {
                const strwithlen s;
                F &l;

                struct iterator
                {
                        strwithlen cur;
                        F &l;
                        const CT *next;

                        void Next()
                        {
                                const auto *const e = cur.end();

                                while (next != e && !l(*next))
                                        ++next;
                        }

                        iterator(const strwithlen input, F &lambda)
                            : cur(input), l{lambda}, next(cur.p)
                        {
                                Next();
                        }

                        bool operator!=(const iterator &o) const
                        {
                                return cur.p != o.cur.p;
                        }

                        iterator &operator++()
                        {
                                cur.AdvanceTo(next);
                                if (cur)
                                {
                                        cur.AdjustLeft(1);
                                        ++next;
                                        Next();
                                }
                                return *this;
                        }

                        inline strwithlen operator*() const
                        {
                                return strwithlen(cur.p, next - cur.p);
                        }
                };

                _segmentsF(const strwithlen in, F &lambda)
                    : s(in), l(lambda)
                {
                }

                iterator begin() const
                {
                        return iterator(s, l);
                }

                iterator end() const
                {
                        return iterator({s.End(), uint32_t(0)}, l);
                }
        };

        // e.g for (const auto it : strwlen32_t("com.markpadakis.apps").Segments('.') { .. }
        auto Segments(const CT separator) const
        {
                return _segments(*this, separator);
        }

        auto Split(const CT separator) const
        {
                return _segments(*this, separator);
        }

        template <typename F>
        auto splitL(F &&l) const
        {
                return _segmentsF<F>(*this, l);
        }

        auto &trim_leading_whitespace() noexcept
        {
                const auto b = p;

                for (const auto e = p + len; p != e && utils::is_space(*p); ++p)
                        continue;
                len -= p - b;
                return *this;
        }

        auto &trim_trailing_whitespace() noexcept
        {
                while (len && utils::is_space(p[len - 1]))
                        --len;

                return *this;
        }

        auto &trim_leading(const CT c)
        {
                while (len && *p == c)
                {
                        ++p;
                        --len;
                }
                return *this;
        }

        uint32_t SplitInto(const CT separator, strwithlen *const out, const size_t capacity) const
        {
                if (!len)
                        return 0;

                uint32_t n{0};
                auto it = p;

                out->p = it;
                for (const auto *const e = end(); it != e;)
                {
                        if (*it == separator)
                        {
                                out[n++].SetEnd(it);
                                if (n == capacity)
                                        return UINT32_MAX;
                                out[n].p = ++it;
                        }
                        else
                                ++it;
                }
                out[n++].SetEnd(it);

                return n;
        }
};

typedef strwithlen<uint64_t> strwithlen64_t, strwlen64_t;
typedef strwithlen<uint32_t> strwithlen32_t, strwlen32_t;
typedef strwithlen<uint16_t> strwithlen16_t, strwlen16_t;
typedef strwithlen<uint8_t> strwithlen8_t, strwlen8_t;

inline auto operator"" _s8(const char *const s, const size_t len)
{
        return strwlen8_t(s, len);
}

inline auto operator"" _s16(const char *const s, const size_t len)
{
        return strwlen16_t(s, len);
}

constexpr auto operator"" _s32(const char *const s, const size_t len)
{
        return strwlen32_t(s, len, strwlen32_t::NoMaxLenCheck{});
}

constexpr size_t operator"" _len(const char *const, const size_t len)
{
        return len;
}

[[gnu::always_inline]] inline static auto S32(const char *const p, const uint32_t len)
{
        return strwlen32_t(p, len);
}

[[gnu::always_inline]] inline static auto S8(const char *const p, const uint32_t len)
{
        return strwlen8_t(p, len);
}

[[gnu::always_inline]] inline static auto S16(const char *const p, const uint32_t len)
{
        return strwlen16_t(p, len);
}

#define _S32(s) strwlen32_t(s, STRLEN(s))
#define _S16(s) strwlen16_t(s, STRLEN(s))
#define _S8(s) strwlen8_t(s, STRLEN(s))

#ifdef LEAN_SWITCH
namespace std
{
        template <typename LT, typename CT>
        struct hash<strwithlen<LT, CT>>
        {
                using argument_type = strwithlen<LT, CT>;
                using result_type = std::size_t;

                result_type operator()(const argument_type &e) const
                {
                        size_t h{2166136261U};

                        for (uint32_t i{0}; i != e.len; ++i)
                                h = (h * 16777619) ^ e.p[i];

                        return h;
                }
        };
}
#endif

template <typename T>
[[gnu::always_inline]] inline static constexpr int32_t TrivialCmp(const T &a, const T &b)
{
        // Ref: http://stackoverflow.com/questions/10996418/efficient-integer-compare-function
        return (a > b) - (a < b);
}

[[gnu::always_inline]] inline int32_t constexpr TrivialCmp(const uint8_t a, const uint8_t b)
{
        return a - b;
}

[[gnu::always_inline]] inline int32_t constexpr TrivialCmp(const int8_t a, const int8_t b)
{
        return a - b;
}

[[gnu::always_inline]] inline int32_t constexpr TrivialCmp(const uint16_t a, const uint16_t b)
{
        return a - b;
}

[[gnu::always_inline]] inline int32_t constexpr TrivialCmp(const int16_t a, const int16_t b)
{
        return a - b;
}

[[gnu::always_inline]] inline int32_t constexpr TrivialCmp(const uint32_t a, const uint32_t b)
{
        return (a > b) - (a < b);
}

[[gnu::always_inline]] inline int32_t constexpr TrivialCmp(const int32_t a, const int32_t b)
{
        return a - b;
}

[[gnu::always_inline]] inline int32_t constexpr TrivialCmp(const uint64_t a, const uint64_t b)
{
        return (a > b) - (a < b);
}

[[gnu::always_inline]] inline int32_t constexpr TrivialCmp(const int64_t a, const int64_t b)
{
        return (a > b) - (a < b);
}

template <typename T>
static inline void encode_pod(const T v, uint8_t *&ptr) noexcept
{
        *reinterpret_cast<T *>(ptr) = v;
        ptr += sizeof(T);
}

template <typename T>
static inline T decode_pod(const uint8_t *&p) noexcept
{
        const auto res = *(T *)p;

        p += sizeof(T);
        return res;
}

using str_view8 = strwlen8_t;
using str_view16 = strwlen16_t;
using str_view32 = strwlen32_t;

namespace std
{
        template <typename LT, typename CT>
        struct hash<strwithlen<LT, CT>>
        {
                using argument_type = strwithlen<LT, CT>;
                using result_type = std::size_t;

                result_type operator()(const argument_type &e) const
                {
                        size_t h{2166136261U};

                        for (uint32_t i{0}; i != e.len; ++i)
                                h = (h * 16777619) ^ e.p[i];

                        return h;
                }
        };
}
