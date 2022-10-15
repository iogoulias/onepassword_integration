'use strict'

exports.fetchAttributes = main;

const crypto = require('crypto');
const {
    subtle
} = require('crypto').webcrypto;
const bigInt = require('big-integer');
const request = require('request');
const CryptoJS = require("crypto-js");
const sjcl = require("sjcl");



var I00 = function(e) {
    return e.toString(16).replace(/^(0x)?0*/, "")
}


function str2ab(str) {
    var pwUtf8 = new TextEncoder().encode(str);

    return pwUtf8;
}

function myhash(input) {

    return CryptoJS.algo.SHA256.create().update(input).finalize();;

}

function getPartial(t) {
    return Math.round(t / 1099511627776) || 32
}

function bitLength(t) {
    var e = t.length;
    return 0 === e ? 0 : 32 * (e - 1) + getPartial(t[e - 1])
}

function fromBits(t) {
    var e, r, n = [],
        a = bitLength(t);
    for (e = 0; e < a / 8; e++)
        0 == (3 & e) && (r = t[e / 4]),
        n.push(r >>> 24),
        r <<= 8;
    return n
}

function bytes_toBits(t) {
    var e, r = [],
        n = 0;
    for (e = 0; e < t.length; e++)
        n = n << 8 | t[e],
        3 == (3 & e) && (r.push(n),
            n = 0);
    return 3 & e && r.push(partial(8 * (3 & e), n)),
        r
}

function hex_fromBits(t) {
    var e, r = "";
    for (e = 0; e < t.length; e++)
        r += (0xf00000000000 + (0 | t[e])).toString(16).substr(4);
    return r.substr(0, bitLength(t) / 4)
}

function computeRawKey(e, r02, i02, E, zero, one) {
    var t = e.auth,
        n = e.littleA,
        r0 = e.bigA,
        i = e.bigB,
        u = e.sessionId,
        f = r02,
        d = i02,
        p = E(t.srpX),
        y = E(n),
        h = E(i);

    if (h.mod(d).equals(zero) || h.mod(d).equals(one))
        throw new Error("Invalid SRP B value");
    var v = E((sjcl.codec.hex.fromBits(bytes_toBits(str2ab(u)))));
    if (v.mod(d).equals(zero))
        throw new Error("Invalid SRP k (sessionId) value");


    var m = E(hex_fromBits(myhash(r0 + i).words));

    var g = y.add(m.multiply(p)),
        b = h.subtract(f.modPow(p, d).multiply(v)),
        w = I00(b.modPow(g, d));

    return new Uint8Array(fromBits(myhash(w).words))
}

async function generateA(credentials, deviceUUID, newDevice) {
    if (newDevice == true) {
        var start_response = await getsession(deviceUUID, credentials.secretKey.id, credentials.secretKey.format, credentials.email);
        start_response = JSON.parse(start_response);
        var session = start_response.sessionID;
        var device = await register_device(deviceUUID, session);
        device = JSON.parse(device);
        if (!device.hasOwnProperty("success") || (device.hasOwnProperty("success") && device.success != 1)) {
            throw 'Device not registered';
        }
    }
    var start_response = await getsession(deviceUUID, credentials.secretKey.id, credentials.secretKey.format, credentials.email);
    start_response = JSON.parse(start_response);
    var session = start_response.sessionID;


    var e;

    function r(t, e, r) {
        null != t && ("number" == typeof t ? this.fromNumber(t, e, r) : null == e && "string" != typeof t ? this.fromString(t, 256) : this.fromString(t, e))
    }

    function n() {
        return new r(null)
    }
    var i = "undefined" != typeof navigator;
    i && "Microsoft Internet Explorer" == navigator.appName ? (r.prototype.am = function(t, e, r, n, i, a) {
                for (var o = 32767 & e, s = e >> 15; --a >= 0;) {
                    var u = 32767 & this[t],
                        c = this[t++] >> 15,
                        l = s * u + c * o;
                    i = ((u = o * u + ((32767 & l) << 15) + r[n] + (1073741823 & i)) >>> 30) + (l >>> 15) + s * c + (i >>> 30),
                        r[n++] = 1073741823 & u
                }
                return i
            },
            e = 30) : i && "Netscape" != navigator.appName ? (r.prototype.am = function(t, e, r, n, i, a) {
                for (; --a >= 0;) {
                    var o = e * this[t++] + r[n] + i;
                    i = Math.floor(o / 67108864),
                        r[n++] = 67108863 & o
                }
                return i
            },
            e = 26) : (r.prototype.am = function(t, e, r, n, i, a) {
                for (var o = 16383 & e, s = e >> 14; --a >= 0;) {
                    var u = 16383 & this[t],
                        c = this[t++] >> 14,
                        l = s * u + c * o;
                    i = ((u = o * u + ((16383 & l) << 14) + r[n] + i) >> 28) + (l >> 14) + s * c,
                        r[n++] = 268435455 & u
                }
                return i
            },
            e = 28),
        r.prototype.DB = e,
        r.prototype.DM = (1 << e) - 1,
        r.prototype.DV = 1 << e,
        r.prototype.FV = Math.pow(2, 52),
        r.prototype.F1 = 52 - e,
        r.prototype.F2 = 2 * e - 52;
    var a, o, s = new Array;
    for (a = "0".charCodeAt(0),
        o = 0; o <= 9; ++o)
        s[a++] = o;
    for (a = "a".charCodeAt(0),
        o = 10; o < 36; ++o)
        s[a++] = o;
    for (a = "A".charCodeAt(0),
        o = 10; o < 36; ++o)
        s[a++] = o;

    function u(t) {
        return "0123456789abcdefghijklmnopqrstuvwxyz".charAt(t)
    }

    function c(t, e) {
        var r = s[t.charCodeAt(e)];
        return null == r ? -1 : r
    }

    function l(t) {
        var e = n();
        return e.fromInt(t),
            e
    }

    function h(t) {
        var e, r = 1;
        return 0 != (e = t >>> 16) && (t = e,
                r += 16),
            0 != (e = t >> 8) && (t = e,
                r += 8),
            0 != (e = t >> 4) && (t = e,
                r += 4),
            0 != (e = t >> 2) && (t = e,
                r += 2),
            0 != (e = t >> 1) && (t = e,
                r += 1),
            r
    }

    function f(t) {
        this.m = t
    }

    function d(t) {
        this.m = t,
            this.mp = t.invDigit(),
            this.mpl = 32767 & this.mp,
            this.mph = this.mp >> 15,
            this.um = (1 << t.DB - 15) - 1,
            this.mt2 = 2 * t.t
    }

    function p(t, e) {
        return t & e
    }

    function m(t, e) {
        return t | e
    }

    function g(t, e) {
        return t ^ e
    }

    function b(t, e) {
        return t & ~e
    }

    function v(t) {
        if (0 == t)
            return -1;
        var e = 0;
        return 0 == (65535 & t) && (t >>= 16,
                e += 16),
            0 == (255 & t) && (t >>= 8,
                e += 8),
            0 == (15 & t) && (t >>= 4,
                e += 4),
            0 == (3 & t) && (t >>= 2,
                e += 2),
            0 == (1 & t) && ++e,
            e
    }

    function y(t) {
        for (var e = 0; 0 != t;)
            t &= t - 1,
            ++e;
        return e
    }

    function w() {}

    function _(t) {
        return t
    }

    function k(t) {
        this.r2 = n(),
            this.q3 = n(),
            r.ONE.dlShiftTo(2 * t.t, this.r2),
            this.mu = this.r2.divide(t),
            this.m = t
    }
    f.prototype.convert = function(t) {
            return t.s < 0 || t.compareTo(this.m) >= 0 ? t.mod(this.m) : t
        },
        f.prototype.revert = function(t) {
            return t
        },
        f.prototype.reduce = function(t) {
            t.divRemTo(this.m, null, t)
        },
        f.prototype.mulTo = function(t, e, r) {
            t.multiplyTo(e, r),
                this.reduce(r)
        },
        f.prototype.sqrTo = function(t, e) {
            t.squareTo(e),
                this.reduce(e)
        },
        d.prototype.convert = function(t) {
            var e = n();
            return t.abs().dlShiftTo(this.m.t, e),
                e.divRemTo(this.m, null, e),
                t.s < 0 && e.compareTo(r.ZERO) > 0 && this.m.subTo(e, e),
                e
        },
        d.prototype.revert = function(t) {
            var e = n();
            return t.copyTo(e),
                this.reduce(e),
                e
        },
        d.prototype.reduce = function(t) {
            for (; t.t <= this.mt2;)
                t[t.t++] = 0;
            for (var e = 0; e < this.m.t; ++e) {
                var r = 32767 & t[e],
                    n = r * this.mpl + ((r * this.mph + (t[e] >> 15) * this.mpl & this.um) << 15) & t.DM;
                for (t[r = e + this.m.t] += this.m.am(0, n, t, e, 0, this.m.t); t[r] >= t.DV;)
                    t[r] -= t.DV,
                    t[++r]++
            }
            t.clamp(),
                t.drShiftTo(this.m.t, t),
                t.compareTo(this.m) >= 0 && t.subTo(this.m, t)
        },
        d.prototype.mulTo = function(t, e, r) {
            t.multiplyTo(e, r),
                this.reduce(r)
        },
        d.prototype.sqrTo = function(t, e) {
            t.squareTo(e),
                this.reduce(e)
        },
        r.prototype.copyTo = function(t) {
            for (var e = this.t - 1; e >= 0; --e)
                t[e] = this[e];
            t.t = this.t,
                t.s = this.s
        },
        r.prototype.fromInt = function(t) {
            this.t = 1,
                this.s = t < 0 ? -1 : 0,
                t > 0 ? this[0] = t : t < -1 ? this[0] = t + this.DV : this.t = 0
        },
        r.prototype.fromString = function(t, e) {
            var n;
            if (16 == e)
                n = 4;
            else if (8 == e)
                n = 3;
            else if (256 == e)
                n = 8;
            else if (2 == e)
                n = 1;
            else if (32 == e)
                n = 5;
            else {
                if (4 != e)
                    return void this.fromRadix(t, e);
                n = 2
            }
            this.t = 0,
                this.s = 0;
            for (var i = t.length, a = !1, o = 0; --i >= 0;) {
                var s = 8 == n ? 255 & t[i] : c(t, i);
                s < 0 ? "-" == t.charAt(i) && (a = !0) : (a = !1,
                    0 == o ? this[this.t++] = s : o + n > this.DB ? (this[this.t - 1] |= (s & (1 << this.DB - o) - 1) << o,
                        this[this.t++] = s >> this.DB - o) : this[this.t - 1] |= s << o,
                    (o += n) >= this.DB && (o -= this.DB))
            }
            8 == n && 0 != (128 & t[0]) && (this.s = -1,
                    o > 0 && (this[this.t - 1] |= (1 << this.DB - o) - 1 << o)),
                this.clamp(),
                a && r.ZERO.subTo(this, this)
        },
        r.prototype.clamp = function() {
            for (var t = this.s & this.DM; this.t > 0 && this[this.t - 1] == t;)
                --this.t
        },
        r.prototype.dlShiftTo = function(t, e) {
            var r;
            for (r = this.t - 1; r >= 0; --r)
                e[r + t] = this[r];
            for (r = t - 1; r >= 0; --r)
                e[r] = 0;
            e.t = this.t + t,
                e.s = this.s
        },
        r.prototype.drShiftTo = function(t, e) {
            for (var r = t; r < this.t; ++r)
                e[r - t] = this[r];
            e.t = Math.max(this.t - t, 0),
                e.s = this.s
        },
        r.prototype.lShiftTo = function(t, e) {
            var r, n = t % this.DB,
                i = this.DB - n,
                a = (1 << i) - 1,
                o = Math.floor(t / this.DB),
                s = this.s << n & this.DM;
            for (r = this.t - 1; r >= 0; --r)
                e[r + o + 1] = this[r] >> i | s,
                s = (this[r] & a) << n;
            for (r = o - 1; r >= 0; --r)
                e[r] = 0;
            e[o] = s,
                e.t = this.t + o + 1,
                e.s = this.s,
                e.clamp()
        },
        r.prototype.rShiftTo = function(t, e) {
            e.s = this.s;
            var r = Math.floor(t / this.DB);
            if (r >= this.t)
                e.t = 0;
            else {
                var n = t % this.DB,
                    i = this.DB - n,
                    a = (1 << n) - 1;
                e[0] = this[r] >> n;
                for (var o = r + 1; o < this.t; ++o)
                    e[o - r - 1] |= (this[o] & a) << i,
                    e[o - r] = this[o] >> n;
                n > 0 && (e[this.t - r - 1] |= (this.s & a) << i),
                    e.t = this.t - r,
                    e.clamp()
            }
        },
        r.prototype.subTo = function(t, e) {
            for (var r = 0, n = 0, i = Math.min(t.t, this.t); r < i;)
                n += this[r] - t[r],
                e[r++] = n & this.DM,
                n >>= this.DB;
            if (t.t < this.t) {
                for (n -= t.s; r < this.t;)
                    n += this[r],
                    e[r++] = n & this.DM,
                    n >>= this.DB;
                n += this.s
            } else {
                for (n += this.s; r < t.t;)
                    n -= t[r],
                    e[r++] = n & this.DM,
                    n >>= this.DB;
                n -= t.s
            }
            e.s = n < 0 ? -1 : 0,
                n < -1 ? e[r++] = this.DV + n : n > 0 && (e[r++] = n),
                e.t = r,
                e.clamp()
        },
        r.prototype.multiplyTo = function(t, e) {
            var n = this.abs(),
                i = t.abs(),
                a = n.t;
            for (e.t = a + i.t; --a >= 0;)
                e[a] = 0;
            for (a = 0; a < i.t; ++a)
                e[a + n.t] = n.am(0, i[a], e, a, 0, n.t);
            e.s = 0,
                e.clamp(),
                this.s != t.s && r.ZERO.subTo(e, e)
        },
        r.prototype.squareTo = function(t) {
            for (var e = this.abs(), r = t.t = 2 * e.t; --r >= 0;)
                t[r] = 0;
            for (r = 0; r < e.t - 1; ++r) {
                var n = e.am(r, e[r], t, 2 * r, 0, 1);
                (t[r + e.t] += e.am(r + 1, 2 * e[r], t, 2 * r + 1, n, e.t - r - 1)) >= e.DV && (t[r + e.t] -= e.DV,
                    t[r + e.t + 1] = 1)
            }
            t.t > 0 && (t[t.t - 1] += e.am(r, e[r], t, 2 * r, 0, 1)),
                t.s = 0,
                t.clamp()
        },
        r.prototype.divRemTo = function(t, e, i) {
            var a = t.abs();
            if (!(a.t <= 0)) {
                var o = this.abs();
                if (o.t < a.t)
                    return null != e && e.fromInt(0),
                        void(null != i && this.copyTo(i));
                null == i && (i = n());
                var s = n(),
                    u = this.s,
                    c = t.s,
                    l = this.DB - h(a[a.t - 1]);
                l > 0 ? (a.lShiftTo(l, s),
                    o.lShiftTo(l, i)) : (a.copyTo(s),
                    o.copyTo(i));
                var f = s.t,
                    d = s[f - 1];
                if (0 != d) {
                    var p = d * (1 << this.F1) + (f > 1 ? s[f - 2] >> this.F2 : 0),
                        m = this.FV / p,
                        g = (1 << this.F1) / p,
                        b = 1 << this.F2,
                        v = i.t,
                        y = v - f,
                        w = null == e ? n() : e;
                    for (s.dlShiftTo(y, w),
                        i.compareTo(w) >= 0 && (i[i.t++] = 1,
                            i.subTo(w, i)),
                        r.ONE.dlShiftTo(f, w),
                        w.subTo(s, s); s.t < f;)
                        s[s.t++] = 0;
                    for (; --y >= 0;) {
                        var _ = i[--v] == d ? this.DM : Math.floor(i[v] * m + (i[v - 1] + b) * g);
                        if ((i[v] += s.am(0, _, i, y, 0, f)) < _)
                            for (s.dlShiftTo(y, w),
                                i.subTo(w, i); i[v] < --_;)
                                i.subTo(w, i)
                    }
                    null != e && (i.drShiftTo(f, e),
                            u != c && r.ZERO.subTo(e, e)),
                        i.t = f,
                        i.clamp(),
                        l > 0 && i.rShiftTo(l, i),
                        u < 0 && r.ZERO.subTo(i, i)
                }
            }
        },
        r.prototype.invDigit = function() {
            if (this.t < 1)
                return 0;
            var t = this[0];
            if (0 == (1 & t))
                return 0;
            var e = 3 & t;
            return (e = (e = (e = (e = e * (2 - (15 & t) * e) & 15) * (2 - (255 & t) * e) & 255) * (2 - ((65535 & t) * e & 65535)) & 65535) * (2 - t * e % this.DV) % this.DV) > 0 ? this.DV - e : -e
        },
        r.prototype.isEven = function() {
            return 0 == (this.t > 0 ? 1 & this[0] : this.s)
        },
        r.prototype.exp = function(t, e) {
            if (t > 4294967295 || t < 1)
                return r.ONE;
            var i = n(),
                a = n(),
                o = e.convert(this),
                s = h(t) - 1;
            for (o.copyTo(i); --s >= 0;)
                if (e.sqrTo(i, a),
                    (t & 1 << s) > 0)
                    e.mulTo(a, o, i);
                else {
                    var u = i;
                    i = a,
                        a = u
                }
            return e.revert(i)
        },
        r.prototype.toString = function(t) {
            if (this.s < 0)
                return "-" + this.negate().toString(t);
            var e;
            if (16 == t)
                e = 4;
            else if (8 == t)
                e = 3;
            else if (2 == t)
                e = 1;
            else if (32 == t)
                e = 5;
            else {
                if (4 != t)
                    return this.toRadix(t);
                e = 2
            }
            var r, n = (1 << e) - 1,
                i = !1,
                a = "",
                o = this.t,
                s = this.DB - o * this.DB % e;
            if (o-- > 0)
                for (s < this.DB && (r = this[o] >> s) > 0 && (i = !0,
                        a = u(r)); o >= 0;)
                    s < e ? (r = (this[o] & (1 << s) - 1) << e - s,
                        r |= this[--o] >> (s += this.DB - e)) : (r = this[o] >> (s -= e) & n,
                        s <= 0 && (s += this.DB,
                            --o)),
                    r > 0 && (i = !0),
                    i && (a += u(r));
            return i ? a : "0"
        },
        r.prototype.negate = function() {
            var t = n();
            return r.ZERO.subTo(this, t),
                t
        },
        r.prototype.abs = function() {
            return this.s < 0 ? this.negate() : this
        },
        r.prototype.compareTo = function(t) {
            var e = this.s - t.s;
            if (0 != e)
                return e;
            var r = this.t;
            if (0 != (e = r - t.t))
                return this.s < 0 ? -e : e;
            for (; --r >= 0;)
                if (0 != (e = this[r] - t[r]))
                    return e;
            return 0
        },
        r.prototype.bitLength = function() {
            return this.t <= 0 ? 0 : this.DB * (this.t - 1) + h(this[this.t - 1] ^ this.s & this.DM)
        },
        r.prototype.mod = function(t) {
            var e = n();
            return this.abs().divRemTo(t, null, e),
                this.s < 0 && e.compareTo(r.ZERO) > 0 && t.subTo(e, e),
                e
        },
        r.prototype.modPowInt = function(t, e) {
            var r;
            return r = t < 256 || e.isEven() ? new f(e) : new d(e),
                this.exp(t, r)
        },
        r.ZERO = l(0),
        r.ONE = l(1),
        w.prototype.convert = _,
        w.prototype.revert = _,
        w.prototype.mulTo = function(t, e, r) {
            t.multiplyTo(e, r)
        },
        w.prototype.sqrTo = function(t, e) {
            t.squareTo(e)
        },
        k.prototype.convert = function(t) {
            if (t.s < 0 || t.t > 2 * this.m.t)
                return t.mod(this.m);
            if (t.compareTo(this.m) < 0)
                return t;
            var e = n();
            return t.copyTo(e),
                this.reduce(e),
                e
        },
        k.prototype.revert = function(t) {
            return t
        },
        k.prototype.reduce = function(t) {
            for (t.drShiftTo(this.m.t - 1, this.r2),
                t.t > this.m.t + 1 && (t.t = this.m.t + 1,
                    t.clamp()),
                this.mu.multiplyUpperTo(this.r2, this.m.t + 1, this.q3),
                this.m.multiplyLowerTo(this.q3, this.m.t + 1, this.r2); t.compareTo(this.r2) < 0;)
                t.dAddOffset(1, this.m.t + 1);
            for (t.subTo(this.r2, t); t.compareTo(this.m) >= 0;)
                t.subTo(this.m, t)
        },
        k.prototype.mulTo = function(t, e, r) {
            t.multiplyTo(e, r),
                this.reduce(r)
        },
        k.prototype.sqrTo = function(t, e) {
            t.squareTo(e),
                this.reduce(e)
        };
    var E, A, x, D = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997],
        S = (1 << 26) / D[D.length - 1];

    function C() {
        var t;
        t = (new Date).getTime(),
            A[x++] ^= 255 & t,
            A[x++] ^= t >> 8 & 255,
            A[x++] ^= t >> 16 & 255,
            A[x++] ^= t >> 24 & 255,
            x >= N && (x -= N)
    }
    if (r.prototype.chunkSize = function(t) {
            return Math.floor(Math.LN2 * this.DB / Math.log(t))
        },
        r.prototype.toRadix = function(t) {
            if (null == t && (t = 10),
                0 == this.signum() || t < 2 || t > 36)
                return "0";
            var e = this.chunkSize(t),
                r = Math.pow(t, e),
                i = l(r),
                a = n(),
                o = n(),
                s = "";
            for (this.divRemTo(i, a, o); a.signum() > 0;)
                s = (r + o.intValue()).toString(t).substr(1) + s,
                a.divRemTo(i, a, o);
            return o.intValue().toString(t) + s
        },
        r.prototype.fromRadix = function(t, e) {
            this.fromInt(0),
                null == e && (e = 10);
            for (var n = this.chunkSize(e), i = Math.pow(e, n), a = !1, o = 0, s = 0, u = 0; u < t.length; ++u) {
                var l = c(t, u);
                l < 0 ? "-" == t.charAt(u) && 0 == this.signum() && (a = !0) : (s = e * s + l,
                    ++o >= n && (this.dMultiply(i),
                        this.dAddOffset(s, 0),
                        o = 0,
                        s = 0))
            }
            o > 0 && (this.dMultiply(Math.pow(e, o)),
                    this.dAddOffset(s, 0)),
                a && r.ZERO.subTo(this, this)
        },
        r.prototype.fromNumber = function(t, e, n) {
            if ("number" == typeof e)
                if (t < 2)
                    this.fromInt(1);
                else
                    for (this.fromNumber(t, n),
                        this.testBit(t - 1) || this.bitwiseTo(r.ONE.shiftLeft(t - 1), m, this),
                        this.isEven() && this.dAddOffset(1, 0); !this.isProbablePrime(e);)
                        this.dAddOffset(2, 0),
                        this.bitLength() > t && this.subTo(r.ONE.shiftLeft(t - 1), this);
            else {
                var i = new Array,
                    a = 7 & t;
                i.length = 1 + (t >> 3),
                    e.nextBytes(i),
                    a > 0 ? i[0] &= (1 << a) - 1 : i[0] = 0,
                    this.fromString(i, 256)
            }
        },
        r.prototype.bitwiseTo = function(t, e, r) {
            var n, i, a = Math.min(t.t, this.t);
            for (n = 0; n < a; ++n)
                r[n] = e(this[n], t[n]);
            if (t.t < this.t) {
                for (i = t.s & this.DM,
                    n = a; n < this.t; ++n)
                    r[n] = e(this[n], i);
                r.t = this.t
            } else {
                for (i = this.s & this.DM,
                    n = a; n < t.t; ++n)
                    r[n] = e(i, t[n]);
                r.t = t.t
            }
            r.s = e(this.s, t.s),
                r.clamp()
        },
        r.prototype.changeBit = function(t, e) {
            var n = r.ONE.shiftLeft(t);
            return this.bitwiseTo(n, e, n),
                n
        },
        r.prototype.addTo = function(t, e) {
            for (var r = 0, n = 0, i = Math.min(t.t, this.t); r < i;)
                n += this[r] + t[r],
                e[r++] = n & this.DM,
                n >>= this.DB;
            if (t.t < this.t) {
                for (n += t.s; r < this.t;)
                    n += this[r],
                    e[r++] = n & this.DM,
                    n >>= this.DB;
                n += this.s
            } else {
                for (n += this.s; r < t.t;)
                    n += t[r],
                    e[r++] = n & this.DM,
                    n >>= this.DB;
                n += t.s
            }
            e.s = n < 0 ? -1 : 0,
                n > 0 ? e[r++] = n : n < -1 && (e[r++] = this.DV + n),
                e.t = r,
                e.clamp()
        },
        r.prototype.dMultiply = function(t) {
            this[this.t] = this.am(0, t - 1, this, 0, 0, this.t),
                ++this.t,
                this.clamp()
        },
        r.prototype.dAddOffset = function(t, e) {
            if (0 != t) {
                for (; this.t <= e;)
                    this[this.t++] = 0;
                for (this[e] += t; this[e] >= this.DV;)
                    this[e] -= this.DV,
                    ++e >= this.t && (this[this.t++] = 0),
                    ++this[e]
            }
        },
        r.prototype.multiplyLowerTo = function(t, e, r) {
            var n, i = Math.min(this.t + t.t, e);
            for (r.s = 0,
                r.t = i; i > 0;)
                r[--i] = 0;
            for (n = r.t - this.t; i < n; ++i)
                r[i + this.t] = this.am(0, t[i], r, i, 0, this.t);
            for (n = Math.min(t.t, e); i < n; ++i)
                this.am(0, t[i], r, i, 0, e - i);
            r.clamp()
        },
        r.prototype.multiplyUpperTo = function(t, e, r) {
            --e;
            var n = r.t = this.t + t.t - e;
            for (r.s = 0; --n >= 0;)
                r[n] = 0;
            for (n = Math.max(e - this.t, 0); n < t.t; ++n)
                r[this.t + n - e] = this.am(e - n, t[n], r, 0, 0, this.t + n - e);
            r.clamp(),
                r.drShiftTo(1, r)
        },
        r.prototype.modInt = function(t) {
            if (t <= 0)
                return 0;
            var e = this.DV % t,
                r = this.s < 0 ? t - 1 : 0;
            if (this.t > 0)
                if (0 == e)
                    r = this[0] % t;
                else
                    for (var n = this.t - 1; n >= 0; --n)
                        r = (e * r + this[n]) % t;
            return r
        },
        r.prototype.millerRabin = function(t) {
            var e = this.subtract(r.ONE),
                i = e.getLowestSetBit();
            if (i <= 0)
                return !1;
            var a = e.shiftRight(i);
            (t = t + 1 >> 1) > D.length && (t = D.length);
            for (var o = n(), s = 0; s < t; ++s) {
                o.fromInt(D[Math.floor(Math.random() * D.length)]);
                var u = o.modPow(a, this);
                if (0 != u.compareTo(r.ONE) && 0 != u.compareTo(e)) {
                    for (var c = 1; c++ < i && 0 != u.compareTo(e);)
                        if (0 == (u = u.modPowInt(2, this)).compareTo(r.ONE))
                            return !1;
                    if (0 != u.compareTo(e))
                        return !1
                }
            }
            return !0
        },
        r.prototype.clone = function() {
            var t = n();
            return this.copyTo(t),
                t
        },
        r.prototype.intValue = function() {
            if (this.s < 0) {
                if (1 == this.t)
                    return this[0] - this.DV;
                if (0 == this.t)
                    return -1
            } else {
                if (1 == this.t)
                    return this[0];
                if (0 == this.t)
                    return 0
            }
            return (this[1] & (1 << 32 - this.DB) - 1) << this.DB | this[0]
        },
        r.prototype.byteValue = function() {
            return 0 == this.t ? this.s : this[0] << 24 >> 24
        },
        r.prototype.shortValue = function() {
            return 0 == this.t ? this.s : this[0] << 16 >> 16
        },
        r.prototype.signum = function() {
            return this.s < 0 ? -1 : this.t <= 0 || 1 == this.t && this[0] <= 0 ? 0 : 1
        },
        r.prototype.toByteArray = function() {
            var t = this.t,
                e = new Array;
            e[0] = this.s;
            var r, n = this.DB - t * this.DB % 8,
                i = 0;
            if (t-- > 0)
                for (n < this.DB && (r = this[t] >> n) != (this.s & this.DM) >> n && (e[i++] = r | this.s << this.DB - n); t >= 0;)
                    n < 8 ? (r = (this[t] & (1 << n) - 1) << 8 - n,
                        r |= this[--t] >> (n += this.DB - 8)) : (r = this[t] >> (n -= 8) & 255,
                        n <= 0 && (n += this.DB,
                            --t)),
                    0 != (128 & r) && (r |= -256),
                    0 == i && (128 & this.s) != (128 & r) && ++i,
                    (i > 0 || r != this.s) && (e[i++] = r);
            return e
        },
        r.prototype.equals = function(t) {
            return 0 == this.compareTo(t)
        },
        r.prototype.min = function(t) {
            return this.compareTo(t) < 0 ? this : t
        },
        r.prototype.max = function(t) {
            return this.compareTo(t) > 0 ? this : t
        },
        r.prototype.and = function(t) {
            var e = n();
            return this.bitwiseTo(t, p, e),
                e
        },
        r.prototype.or = function(t) {
            var e = n();
            return this.bitwiseTo(t, m, e),
                e
        },
        r.prototype.xor = function(t) {
            var e = n();
            return this.bitwiseTo(t, g, e),
                e
        },
        r.prototype.andNot = function(t) {
            var e = n();
            return this.bitwiseTo(t, b, e),
                e
        },
        r.prototype.not = function() {
            for (var t = n(), e = 0; e < this.t; ++e)
                t[e] = this.DM & ~this[e];
            return t.t = this.t,
                t.s = ~this.s,
                t
        },
        r.prototype.shiftLeft = function(t) {
            var e = n();
            return t < 0 ? this.rShiftTo(-t, e) : this.lShiftTo(t, e),
                e
        },
        r.prototype.shiftRight = function(t) {
            var e = n();
            return t < 0 ? this.lShiftTo(-t, e) : this.rShiftTo(t, e),
                e
        },
        r.prototype.getLowestSetBit = function() {
            for (var t = 0; t < this.t; ++t)
                if (0 != this[t])
                    return t * this.DB + v(this[t]);
            return this.s < 0 ? this.t * this.DB : -1
        },
        r.prototype.bitCount = function() {
            for (var t = 0, e = this.s & this.DM, r = 0; r < this.t; ++r)
                t += y(this[r] ^ e);
            return t
        },
        r.prototype.testBit = function(t) {
            var e = Math.floor(t / this.DB);
            return e >= this.t ? 0 != this.s : 0 != (this[e] & 1 << t % this.DB)
        },
        r.prototype.setBit = function(t) {
            return this.changeBit(t, m)
        },
        r.prototype.clearBit = function(t) {
            return this.changeBit(t, b)
        },
        r.prototype.flipBit = function(t) {
            return this.changeBit(t, g)
        },
        r.prototype.add = function(t) {
            var e = n();
            return this.addTo(t, e),
                e
        },
        r.prototype.subtract = function(t) {
            var e = n();
            return this.subTo(t, e),
                e
        },
        r.prototype.multiply = function(t) {
            var e = n();
            return this.multiplyTo(t, e),
                e
        },
        r.prototype.divide = function(t) {
            var e = n();
            return this.divRemTo(t, e, null),
                e
        },
        r.prototype.remainder = function(t) {
            var e = n();
            return this.divRemTo(t, null, e),
                e
        },
        r.prototype.divideAndRemainder = function(t) {
            var e = n(),
                r = n();
            return this.divRemTo(t, e, r),
                new Array(e, r)
        },
        r.prototype.modPow = function(t, e) {

            var r, i, a = t.bitLength(),
                o = l(1);
            if (a <= 0)
                return o;
            r = a < 18 ? 1 : a < 48 ? 3 : a < 144 ? 4 : a < 768 ? 5 : 6,
                i = a < 8 ? new f(e) : e.isEven() ? new k(e) : new d(e);
            var s = new Array,
                u = 3,
                c = r - 1,
                p = (1 << r) - 1;
            if (s[1] = i.convert(this),
                r > 1) {
                var m = n();
                for (i.sqrTo(s[1], m); u <= p;)
                    s[u] = n(),
                    i.mulTo(m, s[u - 2], s[u]),
                    u += 2
            }
            var g, b, v = t.t - 1,
                y = !0,
                w = n();
            for (a = h(t[v]) - 1; v >= 0;) {
                for (a >= c ? g = t[v] >> a - c & p : (g = (t[v] & (1 << a + 1) - 1) << c - a,
                        v > 0 && (g |= t[v - 1] >> this.DB + a - c)),
                    u = r; 0 == (1 & g);)
                    g >>= 1,
                    --u;
                if ((a -= u) < 0 && (a += this.DB,
                        --v),
                    y)
                    s[g].copyTo(o),
                    y = !1;
                else {
                    for (; u > 1;)
                        i.sqrTo(o, w),
                        i.sqrTo(w, o),
                        u -= 2;
                    u > 0 ? i.sqrTo(o, w) : (b = o,
                            o = w,
                            w = b),
                        i.mulTo(w, s[g], o)
                }
                for (; v >= 0 && 0 == (t[v] & 1 << a);)
                    i.sqrTo(o, w),
                    b = o,
                    o = w,
                    w = b,
                    --a < 0 && (a = this.DB - 1,
                        --v)
            }
            return i.revert(o)
        },
        r.prototype.modInverse = function(t) {
            var e = t.isEven();
            if (this.isEven() && e || 0 == t.signum())
                return r.ZERO;
            for (var n = t.clone(), i = this.clone(), a = l(1), o = l(0), s = l(0), u = l(1); 0 != n.signum();) {
                for (; n.isEven();)
                    n.rShiftTo(1, n),
                    e ? (a.isEven() && o.isEven() || (a.addTo(this, a),
                            o.subTo(t, o)),
                        a.rShiftTo(1, a)) : o.isEven() || o.subTo(t, o),
                    o.rShiftTo(1, o);
                for (; i.isEven();)
                    i.rShiftTo(1, i),
                    e ? (s.isEven() && u.isEven() || (s.addTo(this, s),
                            u.subTo(t, u)),
                        s.rShiftTo(1, s)) : u.isEven() || u.subTo(t, u),
                    u.rShiftTo(1, u);
                n.compareTo(i) >= 0 ? (n.subTo(i, n),
                    e && a.subTo(s, a),
                    o.subTo(u, o)) : (i.subTo(n, i),
                    e && s.subTo(a, s),
                    u.subTo(o, u))
            }
            return 0 != i.compareTo(r.ONE) ? r.ZERO : u.compareTo(t) >= 0 ? u.subtract(t) : u.signum() < 0 ? (u.addTo(t, u),
                u.signum() < 0 ? u.add(t) : u) : u
        },
        r.prototype.pow = function(t) {
            return this.exp(t, new w)
        },
        r.prototype.gcd = function(t) {
            var e = this.s < 0 ? this.negate() : this.clone(),
                r = t.s < 0 ? t.negate() : t.clone();
            if (e.compareTo(r) < 0) {
                var n = e;
                e = r,
                    r = n
            }
            var i = e.getLowestSetBit(),
                a = r.getLowestSetBit();
            if (a < 0)
                return e;
            for (i < a && (a = i),
                a > 0 && (e.rShiftTo(a, e),
                    r.rShiftTo(a, r)); e.signum() > 0;)
                (i = e.getLowestSetBit()) > 0 && e.rShiftTo(i, e),
                (i = r.getLowestSetBit()) > 0 && r.rShiftTo(i, r),
                e.compareTo(r) >= 0 ? (e.subTo(r, e),
                    e.rShiftTo(1, e)) : (r.subTo(e, r),
                    r.rShiftTo(1, r));
            return a > 0 && r.lShiftTo(a, r),
                r
        },
        r.prototype.isProbablePrime = function(t) {
            var e, r = this.abs();
            if (1 == r.t && r[0] <= D[D.length - 1]) {
                for (e = 0; e < D.length; ++e)
                    if (r[0] == D[e])
                        return !0;
                return !1
            }
            if (r.isEven())
                return !1;
            for (e = 1; e < D.length;) {
                for (var n = D[e], i = e + 1; i < D.length && n < S;)
                    n *= D[i++];
                for (n = r.modInt(n); e < i;)
                    if (n % D[e++] == 0)
                        return !1
            }
            return r.millerRabin(t)
        },
        r.prototype.square = function() {
            var t = n();
            return this.squareTo(t),
                t
        },
        r.prototype.Barrett = k,
        null == A) {
        var T;
        if (A = new Array,
            x = 0,
            "undefined" != typeof window && window.crypto)
            if (window.crypto.getRandomValues) {
                var O = new Uint8Array(32);
                for (window.crypto.getRandomValues(O),
                    T = 0; T < 32; ++T)
                    A[x++] = O[T]
            } else if ("Netscape" == navigator.appName && navigator.appVersion < "5") {
            var B = window.crypto.random(32);
            for (T = 0; T < B.length; ++T)
                A[x++] = 255 & B.charCodeAt(T)
        }
        for (; x < N;)
            T = Math.floor(65536 * Math.random()),
            A[x++] = T >>> 8,
            A[x++] = 255 & T;
        x = 0,
            C()
    }

    function I() {
        if (null == E) {
            for (C(),
                (E = new R).init(A),
                x = 0; x < A.length; ++x)
                A[x] = 0;
            x = 0
        }
        return E.next()
    }

    function L() {}

    function R() {
        this.i = 0,
            this.j = 0,
            this.S = new Array
    }
    L.prototype.nextBytes = function(t) {
            var e;
            for (e = 0; e < t.length; ++e)
                t[e] = I()
        },
        R.prototype.init = function(t) {
            var e, r, n;
            for (e = 0; e < 256; ++e)
                this.S[e] = e;
            for (r = 0,
                e = 0; e < 256; ++e)
                r = r + this.S[e] + t[e % t.length] & 255,
                n = this.S[e],
                this.S[e] = this.S[r],
                this.S[r] = n;
            this.i = 0,
                this.j = 0
        },
        R.prototype.next = function() {
            var t;
            return this.i = this.i + 1 & 255,
                this.j = this.j + this.S[this.i] & 255,
                t = this.S[this.i],
                this.S[this.i] = this.S[this.j],
                this.S[this.j] = t,
                this.S[t + this.S[this.i] & 255]
        };
    var N = 256;
    r.SecureRandom = L;
    r.BigInteger = r;

    function E00(e) {
        return new r.BigInteger(e, 16)
    };

    var t = (crypto.randomBytes(32)).toString('hex');


    var n0 = {"N": {"0": 268435455,"1": 268435455,"2": 103913983,"3": 56398656,"4": 9391604,"5": 231279212,"6": 25624503,"7": 148438492,"8": 62188184,"9": 184920729,"10": 110176213,"11": 75615488,"12": 225845616,"13": 184254909,"14": 13558487,"15": 32903831,"16": 22800365,"17": 62527589,"18": 12821027,"19": 157612553,"20": 6134194,"21": 74770108,"22": 103316569,"23": 33287338,"24": 244251668,"25": 233369490,"26": 197319428,"27": 80645563,"28": 164244180,"29": 228743230,"30": 79041803,"31": 27870851,"32": 183820860,"33": 204632454,"34": 173745817,"35": 161549275,"36": 114788465,"37": 19560574,"38": 18510396,"39": 177344640,"40": 193122592,"41": 265357540,"42": 190577888,"43": 179508285,"44": 262173925,"45": 237014564,"46": 12245318,"47": 124819596,"48": 174153068,"49": 236025207,"50": 186649787,"51": 45187447,"52": 174346783,"53": 120843398,"54": 81294850,"55": 228106374,"56": 19921414,"57": 221177535,"58": 64103962,"59": 102358254,"60": 81807909,"61": 225568969,"62": 215681331,"63": 180312808,"64": 115467463,"65": 158398554,"66": 101481907,"67": 118846928,"68": 252349162,"69": 4558270,"70": 82639749,
	"71": 233950118,"72": 139796907,"73": 84386618,"74": 51842308,"75": 205707987,"76": 240814762,"77": 16865064,"78": 144243205,"79": 22880865,"80": 177564389,"81": 156538830,"82": 135731257,"83": 213870933,"84": 46784043,"85": 252114117,"86": 263570781,"87": 247495208,"88": 187138978,"89": 15228985,"90": 242691096,"91": 216251961,"92": 239480374,"93": 130230533,"94": 147462177,"95": 253183680,"96": 180131844,"97": 12801252,"98": 110521703,"99": 43022089,"100": 45850325,"101": 90310741,"102": 102523635,"103": 231357145,"104": 56974627,"105": 38598136,"106": 104835325,"107": 221882001,"108": 137763925,"109": 5868964,"110": 144794559,"111": 203425739,"112": 216292157,"113": 42362142,"114": 186639945,"115": 37820356,"116": 262516383,"117": 263563417,"118": 233715819,"119": 255880062,"120": 201284790,"121": 58644144,"122": 205711782,"123": 132935492,"124": 91644510,"125": 73287771,"126": 225268162,"127": 83759958,"128": 39785527,"129": 45131487,"130": 172170032,"131": 26950867,"132": 81653653,"133": 127460160,"134": 38881800,"135": 61946290,"136": 34324134,"137": 108840768,"138": 38668426,"139": 30216848
	,"140": 42696924,"141": 55331942,"142": 35743938,"143": 210828714,"144": 268435455,"145": 268435455,"146": 255,"t": 147,"s": 0},"g": {"0": 5,"t": 1,"s": 0}};


    var r0 = n0.g;
    var i0 = n0.N;

    var r02 = new r.BigInteger();
    var i02 = new r.BigInteger();
    for (var key in r0) {
        r02[key] = r0[key];
    }
    for (var key in i0) {
        i02[key] = i0[key];
    }

    var bigA = I00(r02.modPow(E00(t), i02));
    var littleA = t;
    var auth_response = await getauth(session, bigA);
    auth_response = JSON.parse(auth_response);
    var srpxkey = await extract_user_key(credentials, start_response);
    var bigB = auth_response.userB;
    var auth = {
        "params": start_response.userAuth
    };
    auth["srpX"] = srpxkey;
    var inpt = {
        "auth": auth,
        "littleA": littleA,
        "bigA": bigA,
        "bigB": bigB,
        "sessionId": session
    };
    var computedKey = computeRawKey(inpt, r02, i02, E00, r.BigInteger.ZERO, r.BigInteger.ONE);
    //MEXRI EDW FAINETAI OK
    var sessionHMAC = await importSessionKey(session, computedKey);


    return {
        "computedKey": computedKey,
        "session": session,
        "sessionHMAC": sessionHMAC
    };
}

function getMACMessage(session, method, url, counter) {

    var extraletter = "?";
    if (url.indexOf("?") > -1) {
        extraletter = "";
    }
    return session + "|" + method + "|" + url + extraletter + "|" + "v1" + "|" + counter;
}

function w001(e) {
    return e < 26 ? e + 65 : e < 52 ? e + 71 : e < 62 ? e - 4 : 62 === e ? 45 : 95
}

function bytesToBase64url(e) {
    for (var t = "", n = void 0, r = e.length, i = 0, o = 0; o < r; o++)
        n = o % 3,
        i |= e[o] << (16 >>> n & 24),
        2 !== n && r - o != 1 || (t += String.fromCharCode(w001(i >>> 18 & 63), w001(i >>> 12 & 63), w001(i >>> 6 & 63), w001(63 & i)),
            i = 0);
    var u = (3 - e.length % 3) % 3;
    return 0 === u ? t : t.slice(0, -u)
}

function createMACHeaderValue(message, counter, sessionhmac) {
    var i = new Uint8Array(fromBits(sessionhmac.encrypt(message)));
    var o = bytesToBase64url(i.subarray(0, 12));
    return ["v1", counter, o].join("|")
}

function partial(t, e, r) {
    return 32 === t ? e : (r ? 0 | e : e << 32 - t) + 1099511627776 * t
}


function utf8_toBits(t) {
    t = unescape(encodeURIComponent(t));
    var e, r = [],
        n = 0;
    for (e = 0; e < t.length; e++)
        n = n << 8 | t.charCodeAt(e),
        3 == (3 & e) && (r.push(n),
            n = 0);
    return 3 & e && r.push(partial(8 * (3 & e), n)),
        r
}

function base64_toBits(t, e) {
    t = t.replace(/\s|=/g, "");
    var r, n, a = [],
        o = 0,
        s = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        u = 0;
    for (e && (s = s.substr(0, 62) + "-_"),
        r = 0; r < t.length; r++) {
        if (0 > (n = s.indexOf(t.charAt(r))))
            throw "exception";
        26 < o ? (o -= 26,
            a.push(u ^ n >>> o),
            u = n << 32 - o) : u ^= n << 32 - (o += 6)
    }
    return 56 & o && a.push(partial(56 & o, u, 1)),
        a
}

async function createSessionHMAC(e) {

    var t = "He never wears a Mac, in the pouring rain. Very strange.";

    var n = sjcl.codec.base64.toBits(e, 1),
        r = sjcl.codec.utf8String.toBits(t);
    var i = (new sjcl.misc.hmac(n, sjcl.hash.sha256));
    var j = i.encrypt(r);
    var j2 = new sjcl.misc.hmac(j, sjcl.hash.sha256)

    return j2


}
async function importSessionKey(session, computedKey) {

    var key = await subtle.importKey("raw", computedKey, {
        "name": "AES-GCM",
        "length": 256
    }, !0, ["encrypt", "decrypt"]);
    var exportedKey = await exportKey(session, key);
    var sessionHMAC = await createSessionHMAC(exportedKey);
    return (sessionHMAC);
}
async function exportKey(session, key) {
    var exported = await subtle.exportKey("jwk", key);

    return (exported.k);
}

async function getoverview(mac, session) {

    return new Promise((resolve, reject) => {
        var options = {
            'method': 'GET',
            'url': 'https://my.1password.com/api/v2/overview',
            'headers': {
                'op-user-agent': '1|B|1349|zox7j7itsarhhyxua2whrjpkzq|||Chrome|105.0.0.0|Windows|10.0|',
                'accept-language': 'en',
                'accept': '*/*',
                'Content-Type': 'text/plain',
                "x-agilebits-mac": mac,
                "x-agilebits-session-id": session
            },
            body: null

        };
        request(options, function(error, response) {
            if (error) throw new Error(error);
            resolve(response.body);
        });

    })

}

async function getsession(deviceUuid, skid, skformat, email) {
    return new Promise((resolve, reject) => {
        var options = {
            'method': 'POST',
            'url': 'https://my.1password.com/api/v3/auth/start',
            'headers': {
                'op-user-agent': '1|B|1349|zox7j7itsarhhyxua2whrjpkzq|||Chrome|105.0.0.0|Windows|10.0|',
                'accept-language': 'en',
                'accept': '*/*',
                'Content-Type': 'text/plain'
            },
            body: '{"email":"' + email + '","skFormat":"' + skformat + '","skid":"' + skid + '","deviceUuid":"' + deviceUuid + '","userUuid":""}'

        };
        request(options, function(error, response) {
            if (error) throw new Error(error);
            resolve(response.body);
        });

    })

}

async function register_device(deviceUuid, session) {
    return new Promise((resolve, reject) => {
        var options = {
            'method': 'POST',
            'url': 'https://my.1password.com/api/v1/device',
            'headers': {
                'op-user-agent': '1|B|1349|zox7j7itsarhhyxua2whrjpkzq|||Chrome|105.0.0.0|Windows|10.0|',
                'accept-language': 'en',
                'accept': '*/*',
                'Content-Type': 'text/plain',
                'x-agilebits-session-id': session
            },
            body: "{\"uuid\":\"" + deviceUuid + "\",\"clientName\":\"1Password for Web\",\"clientVersion\":\"1355\",\"name\":\"Chrome\",\"model\":\"107.0.0.0\",\"osName\":\"Windows\",\"osVersion\":\"10.0\",\"userAgent\":\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36\"}"

        };
        request(options, function(error, response) {
            if (error) throw new Error(error);
            resolve(response.body);
        });

    })

}




async function getauth(session, bigA) {

    return new Promise((resolve, reject) => {
        var options = {
            'method': 'POST',
            'url': 'https://my.1password.com/api/v1/auth',
            'headers': {
                'op-user-agent': '1|B|1349|zox7j7itsarhhyxua2whrjpkzq|||Chrome|105.0.0.0|Windows|10.0|',
                'accept-language': 'en',
                'accept': '*/*',
                'x-agilebits-session-id': session,
                'Content-Type': 'text/plain'
            },
            body: '{"sessionId":"' + session + '","userA":"' + bigA + '"}'

        };
        request(options, function(error, response) {
            if (error) throw new Error(error);
            resolve(response.body);
        });

    })
}


function base64ToBase64url(input) {
    // Replace non-url compatible chars with base64url standard chars and remove leading =
    return input
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/g, '');
}

function calculateClientVerifyHash(secretKeyId, session) {
    var n = (myhash(secretKeyId)).words;
    var r = (myhash(session)).words;
    var i = n.concat(r);
    var o = sjcl.hash.sha256.hash(i);
    var a = new Uint8Array(fromBits(o));
    return bytesToBase64url(a)
}

function generateIV() {
    return bytesToBase64url(new Uint8Array(new Array(12).fill(0).map(function(v) {
        return Math.random() * 256
    })));
}

function generateDeviceUUID() {
    return sjcl.codec.base32.fromBits(bytes_toBits((new Uint8Array(new Array(16).fill(0).map(function(v) {
        return Math.random() * 256
    })))), !0).slice(0, 26).toLowerCase();
}

function transformRecoveryKey(input) {
    input = input.split("-");
    return {
        "format": input[0],
        "id": input[1],
        "key": input.slice(2).join("")
    }
}
async function main(input) {

    const newDevice = input.newDevice;
    if (newDevice == true) {
        var deviceUUID = generateDeviceUUID();
        console.log("new Device UUID is: " + deviceUUID);
    } else {
        var deviceUUID = input.deviceUUID;
    }

    const email = input.email;

    const recoverykey = transformRecoveryKey(input.recoverykey);
    const mypassword = input.password;
    const myvault = input["Vault Name"];
    const website = input.website;
    const user = input.search_username;
    const iv = generateIV();


    const generate_keys = await generateA({
        "email": email,
        "password": mypassword,
        "secretKey": recoverykey
    }, deviceUUID, newDevice);
    const rawKey = generate_keys["computedKey"];
    const sessionHMAC = generate_keys["sessionHMAC"];
    const session = generate_keys["session"];
    const obj1 = {
        "name": 'AES-GCM',
        "iv": Uint8Array.from(Buffer.from(iv, "base64")),
        "tagLength": 128
    };
    const pwUtf8 = new TextEncoder().encode(mypassword);
    const pwHash = await subtle.digest('SHA-256', pwUtf8);
    const key = await subtle.importKey('raw', rawKey, {
        "name": 'AES-GCM',
        "iv": Uint8Array.from(Buffer.from(iv, "base64"))
    }, true, ['encrypt', 'decrypt']);
    var request_counter = 1;
    var verify_response = await verify(session, sessionHMAC, obj1, key, iv, deviceUUID, recoverykey.id);
    var serverVerifyHash = await verify_response["serverVerifyHash"];
    request_counter += 1;

    var keysets_object = await keysets(session, sessionHMAC, obj1, key, iv, request_counter);
    request_counter += 1;
    keysets_object = keysets_object.keysets;

    var extracted_keysets = await keysets_Extract(keysets_object, recoverykey, mypassword, email);
    var extracted_keysets_vaults = extracted_keysets["vaults"];
    var extracted_keysets_roots = extracted_keysets["roots"];

    var vaults_response = await vaults(extracted_keysets_roots, session, sessionHMAC, obj1, key, iv, request_counter);

    request_counter += 1;

    var extracted_keysets_vaults2 = {};
    for (var k = 0; k < vaults_response.length; k++) {
        if (vaults_response[k].hasOwnProperty("extracted_key")) {
            extracted_keysets_vaults2[vaults_response[k]["extracted_key"]["kid"]] = vaults_response[k]["extracted_key"];
        }
    }

    vaults_response = vaults_response.filter(function(v) {
        return v.hasOwnProperty("extracted_attributes") && v.extracted_attributes.name == myvault
    });

    var vault_id = vaults_response[0].extracted_attributes.uuid;
    var opened_vault = await fetch_vault(vault_id, session, sessionHMAC, obj1, key, iv, request_counter);
    request_counter += 1;
    var website_id = "";

    for (var k = 0; k < opened_vault.items.length; k++) {
        opened_vault.items[k] = await decode_vault_item(opened_vault.items[k], extracted_keysets_vaults2, "encOverview");

        if (opened_vault.items[k].hasOwnProperty("extracted_attributes") && opened_vault.items[k]["extracted_attributes"].hasOwnProperty("title") && opened_vault.items[k]["extracted_attributes"]["title"] == website && opened_vault.items[k]["extracted_attributes"].hasOwnProperty("ainfo") && opened_vault.items[k]["extracted_attributes"]["ainfo"] == user) {

            website_id = opened_vault.items[k]["uuid"];

        }
    }

    if (website_id != "") {

        var fetched_website = await fetch_website(vault_id, website_id, session, sessionHMAC, obj1, key, iv, request_counter);
        request_counter += 1;
        var decrypted_fetched_website = await decode_vault_item(fetched_website.item, extracted_keysets_vaults2, "encDetails");
        return( (decrypted_fetched_website.extracted_attributes.fields.filter(function(v){ return v.name=='password'})[0]["value"]));
    } else {

        throw " Credentials not found!";

    }


}

async function verify(session, sessionHMAC, obj1, key, iv, deviceUuid, skid) {
    var url = "my.1password.com/api/v2/auth/verify";
    var counter = 1;
    var method = "POST";

    var fetchedMACmessage = getMACMessage(session, method, url, counter);
    var macHeader = createMACHeaderValue(fetchedMACmessage, counter, sessionHMAC);
    var clientVerifyHash = calculateClientVerifyHash(skid, session)
    var request = '{"sessionId":"' + session + '","clientVerifyHash":"' + clientVerifyHash + '","client":"1Password Extension/20221","device":{"uuid":"' + deviceUuid + '","clientName":"1Password Extension","clientVersion":"20221","name":"Chrome","model":"105.0.0.0","osName":"Windows","osVersion":"10.0","userAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36","fromDeviceInit":true}}'
    var encrypted = await subtle.encrypt(obj1, key, request);
    encrypted = base64ToBase64url(btoa(String.fromCharCode(...new Uint8Array(encrypted))));
    var request_object = {
        "cty": "b5+jwk+json",
        "data": encrypted,
        "enc": "A256GCM",
        "iv": iv,
        "kid": session
    }

    var get_verify_response = await custom_fetch(JSON.stringify(request_object), macHeader, session, url, method);
    get_verify_response = JSON.parse(get_verify_response);
    var obj2 = {
        "name": 'AES-GCM',
        "iv": Uint8Array.from(Buffer.from(get_verify_response.iv, "base64")),
        "tagLength": 128
    };
    var decrypted = await subtle.decrypt(obj2, key, Uint8Array.from(Buffer.from(get_verify_response.data, "base64")));
    var decoded_result = (new TextDecoder().decode(decrypted));
    return (JSON.parse(decoded_result));
}


async function fetch_account(session, sessionHMAC, obj1, key, iv, request_counter) {
    var url = "my.1password.com/api/v3/account?attrs=account-flags,billing,counts,invite,me,me.memberships,meta,promotions,settings,tier,user-flags,groups";
    var counter = request_counter;
    var method = "GET";

    var fetchedMACmessage = getMACMessage(session, method, url, counter);
    var macHeader = createMACHeaderValue(fetchedMACmessage, counter, sessionHMAC);

    var get_overview_response = await custom_fetch(null, macHeader, session, url, method);
    get_overview_response = JSON.parse(get_overview_response);
    var obj2 = {
        "name": 'AES-GCM',
        "iv": Uint8Array.from(Buffer.from(get_overview_response.iv, "base64")),
        "tagLength": 128
    };
    var decrypted = await subtle.decrypt(obj2, key, Uint8Array.from(Buffer.from(get_overview_response.data, "base64")));
    var decoded_result = (new TextDecoder().decode(decrypted));
    return (JSON.parse(decoded_result));
}



async function keysets(session, sessionHMAC, obj1, key, iv, request_counter) {
    var url = "my.1password.com/api/v2/account/keysets";
    var counter = request_counter;
    var method = "GET";

    var fetchedMACmessage = getMACMessage(session, method, url, counter);
    var macHeader = createMACHeaderValue(fetchedMACmessage, counter, sessionHMAC);

    var get_overview_response = await custom_fetch(null, macHeader, session, url, method);
    get_overview_response = JSON.parse(get_overview_response);
    var obj2 = {
        "name": 'AES-GCM',
        "iv": Uint8Array.from(Buffer.from(get_overview_response.iv, "base64")),
        "tagLength": 128
    };
    var decrypted = await subtle.decrypt(obj2, key, Uint8Array.from(Buffer.from(get_overview_response.data, "base64")));
    var decoded_result = (new TextDecoder().decode(decrypted));
    return (JSON.parse(decoded_result));
}

async function vaults(roots, session, sessionHMAC, obj1, key, iv, request_counter) {
    var url = "my.1password.com/api/v1/vaults";
    var counter = request_counter;
    var method = "GET";

    var fetchedMACmessage = getMACMessage(session, method, url, counter);
    var macHeader = createMACHeaderValue(fetchedMACmessage, counter, sessionHMAC);

    var get_overview_response = await custom_fetch(null, macHeader, session, url, method);
    get_overview_response = JSON.parse(get_overview_response);
    var obj2 = {
        "name": 'AES-GCM',
        "iv": Uint8Array.from(Buffer.from(get_overview_response.iv, "base64")),
        "tagLength": 128
    };
    var decrypted = await subtle.decrypt(obj2, key, Uint8Array.from(Buffer.from(get_overview_response.data, "base64")));
    var decoded_result = (new TextDecoder().decode(decrypted));
    decoded_result = JSON.parse(decoded_result);

    for (var k = 0; k < decoded_result.length; k++) {

        decoded_result[k] = await decode_item(decoded_result[k], roots);
    }

    return decoded_result;
}

async function decode_vault_item(decoded_result, keysets, attribute) {

    var masterKey = keysets[decoded_result["encryptedBy"]];
    var encOverview = (decoded_result[attribute]);

    var importedKey = await subtle.importKey(
        "jwk",
        masterKey, {
            "name": "AES-GCM"
        },
        true,
        ["encrypt", "decrypt"]
    );

    var obj = {
        "name": 'AES-GCM',
        "iv": Uint8Array.from(Buffer.from(encOverview["iv"], "base64")),
        "tagLength": 128
    };
    var decrypted = await subtle.decrypt(obj, importedKey, Uint8Array.from(Buffer.from(encOverview["data"], "base64")));

    decrypted = (new TextDecoder().decode(decrypted));
    decrypted = JSON.parse(decrypted);
    decoded_result["extracted_attributes"] = decrypted;
    return decoded_result
}


async function decode_item(decoded_result, roots) {
    if (roots.hasOwnProperty(decoded_result.access[0]["encryptedBy"])) {
        var masterKey = roots[decoded_result.access[0]["encryptedBy"]]
        var encVaultKey = (decoded_result.access[0]["encVaultKey"]);
        var algoDec = {
            name: 'RSA-OAEP',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: {
                name: "SHA-1"
            }
        };

        var decrypted = await subtle.decrypt({
                name: "RSA-OAEP",

            },
            masterKey,
            Uint8Array.from(Buffer.from(encVaultKey.data, "base64"))
        );
        decrypted = (new TextDecoder().decode(decrypted));
        decrypted = JSON.parse(decrypted);
        decoded_result["extracted_key"] = decrypted;


        var importedKey = await subtle.importKey(
            "jwk",
            decrypted, {
                "name": "AES-GCM"
            },
            true,
            ["encrypt", "decrypt"]
        );

        var obj = {
            "name": 'AES-GCM',
            "iv": Uint8Array.from(Buffer.from(decoded_result["encAttrs"]["iv"], "base64")),
            "tagLength": 128
        };
        var decrypted = await subtle.decrypt(obj, importedKey, Uint8Array.from(Buffer.from(decoded_result["encAttrs"]["data"], "base64")));

        decrypted = (new TextDecoder().decode(decrypted));
        decrypted = JSON.parse(decrypted);
        decoded_result["extracted_attributes"] = decrypted;
    }
    return decoded_result
}
async function overview(session, sessionHMAC, obj1, key, iv, request_counter) {
    var url = "my.1password.com/api/v2/overview";
    var counter = request_counter;
    var method = "GET";

    var fetchedMACmessage = getMACMessage(session, method, url, counter);
    var macHeader = createMACHeaderValue(fetchedMACmessage, counter, sessionHMAC);

    var get_overview_response = await custom_fetch(null, macHeader, session, url, method);
    get_overview_response = JSON.parse(get_overview_response);
    var obj2 = {
        "name": 'AES-GCM',
        "iv": Uint8Array.from(Buffer.from(get_overview_response.iv, "base64")),
        "tagLength": 128
    };
    var decrypted = await subtle.decrypt(obj2, key, Uint8Array.from(Buffer.from(get_overview_response.data, "base64")));
    var decoded_result = (new TextDecoder().decode(decrypted));
    return (JSON.parse(decoded_result));
}

async function fetch_website(vaultid, websiteid, session, sessionHMAC, obj1, key, iv, request_counter) {
    var url = "my.1password.com/api/v1/vault/" + vaultid + "/item/" + websiteid;
    var counter = request_counter;
    var method = "GET";

    var fetchedMACmessage = getMACMessage(session, method, url, counter);
    var macHeader = createMACHeaderValue(fetchedMACmessage, counter, sessionHMAC);

    var get_overview_response = await custom_fetch(null, macHeader, session, url, method);
    get_overview_response = JSON.parse(get_overview_response);
    var obj2 = {
        "name": 'AES-GCM',
        "iv": Uint8Array.from(Buffer.from(get_overview_response.iv, "base64")),
        "tagLength": 128
    };
    var decrypted = await subtle.decrypt(obj2, key, Uint8Array.from(Buffer.from(get_overview_response.data, "base64")));
    var decoded_result = (new TextDecoder().decode(decrypted));
    return (JSON.parse(decoded_result));
}

async function fetch_vault(vaultid, session, sessionHMAC, obj1, key, iv, request_counter) {

    var url = "my.1password.com/api/v1/vault/" + vaultid + "/items/overviews";
    var counter = request_counter;
    var method = "GET";

    var fetchedMACmessage = getMACMessage(session, method, url, counter);
    var macHeader = createMACHeaderValue(fetchedMACmessage, counter, sessionHMAC);

    var get_overview_response = await custom_fetch(null, macHeader, session, url, method);
    get_overview_response = JSON.parse(get_overview_response);
    var obj2 = {
        "name": 'AES-GCM',
        "iv": Uint8Array.from(Buffer.from(get_overview_response.iv, "base64")),
        "tagLength": 128
    };
    var decrypted = await subtle.decrypt(obj2, key, Uint8Array.from(Buffer.from(get_overview_response.data, "base64")));
    var decoded_result = (new TextDecoder().decode(decrypted));
    return (JSON.parse(decoded_result));
}

async function custom_fetch(body, macheader, session, url, method) {
    return new Promise((resolve, reject) => {
        var options = {
            'method': method,
            'url': "https://" + url,
            'headers': {
                'op-user-agent': '1|B|1349|zox7j7itsarhhyxua2whrjpkzq|||Chrome|105.0.0.0|Windows|10.0|',
                'accept-language': 'en',
                'accept': '*/*',
                'x-agilebits-session-id': session,
                'x-agilebits-mac': macheader,
                'Content-Type': 'application/json'
            },
            body: body

        };

        request(options, function(error, response) {
            if (error) throw new Error(error);
            resolve(response.body);
        });

    })

}

function HKDF(e, t, n, r, u) {
    var a, c;
    if ("SHA256" === e.toUpperCase())
        a = sjcl.hash.sha256,
        c = 32;
    else {
        if ("SHA512" !== e.toUpperCase()) {
            var s = new Error("Invalid hash function name");
            throw console.error(s, e),
                s
        }
        a = sjcl.hash.sha512,
            c = 64
    }
    var l = new sjcl.misc.hmac(bytes_toBits(r), a);
    l.update(bytes_toBits(t));
    for (var f = l.digest(), d = Math.ceil(u / c), p = sjcl.codec.hex.toBits(""), y = "", h = bytes_toBits(n), v = 0; v < d; v++) {
        var m = new sjcl.misc.hmac(f, a);
        var g0 = p.concat(h);
        var g1 = sjcl.codec.utf8String.toBits(String.fromCharCode(v + 1))
        var g = g0.concat(g1);
        m.update(g),
            p = m.digest(),
            y += sjcl.codec.hex.fromBits(p)
    }
    var b = sjcl.bitArray.clamp(sjcl.codec.hex.toBits(y), 8 * u);
    return new Uint8Array(fromBits(b))
}


async function h_afterHKDF(e, t, n, r, a) {

    var c, s = a;
    if ("SHA-512" === r)
        c = function(e) {
            function t(t) {
                return e.call(this, t, sjcl.hash.sha512) || this
            }
            return u(t, e),
                t
        }(sjcl.misc.hmac);
    else {
        if ("SHA-256" !== r)
            return "Unknown hashname";
        c = function(e) {
            function t(t) {
                return e.call(this, t, sjcl.hash.sha256) || this
            }
            return u(t, e),
                t
        }(sjcl.misc.hmac)
    }
    var l = bytes_toBits(t),
        f = sjcl.misc.pbkdf2(e, l, n, s, c),
        d = new Uint8Array(sjcl.codec.bytes.fromBits(f));
    return d


}
async function m_afterHKDF(d, t, n, r, i) {

    var key0 = await subtle.importKey("raw", str2ab(d), {
        "name": "PBKDF2"
    }, !1, ["deriveBits"]);

    var l = {
        name: "PBKDF2",
        salt: t,
        iterations: n,
        hash: {
            name: r
        }
    }

    var key1 = await subtle.deriveBits(l, key0, 256)

    return new Uint8Array(key1)
}

function dddd(e, t, n, r, u) {
    var a, c;
    if ("SHA256" === e.toUpperCase())
        a = i.hash.sha256,
        c = 32;
    else {
        if ("SHA512" !== e.toUpperCase()) {
            var s = new Error("Invalid hash function name");
            throw console.error(s, e),
                s
        }
        a = i.hash.sha512,
            c = 64
    }
    var l = new i.misc.hmac(o.bytesToBits(r), a);
    l.update(o.bytesToBits(t));
    for (var f = l.digest(), d = Math.ceil(u / c), p = i.codec.hex.toBits(""), y = "", h = o.bytesToBits(n), v = 0; v < d; v++) {
        var m = new i.misc.hmac(f, a),
            g = i.bitArray.concat(i.bitArray.concat(p, h), i.codec.utf8String.toBits(String.fromCharCode(v + 1)));
        m.update(g),
            p = m.digest(),
            y += i.codec.hex.fromBits(p)
    }
    var b = i.bitArray.clamp(i.codec.hex.toBits(y), 8 * u);
    return new Uint8Array(i.codec.bytes.fromBits(b))
}


async function keysets_Extract(keysets, recoverykey, u_password, n_email) {


    var f_email_tolower = n_email.trim().toLowerCase();
    var y_transformed_email = str2ab(f_email_tolower);
    var d_normalized_password = (u_password).trim().normalize("NFKD");
    var p_transformed_password = sjcl.codec.base64url.fromBits(sjcl.hash.sha256.hash(u_password)).replace(/=+$/, "");


    var root_keysets = keysets.filter(function(v) {
        return v.encryptedBy == "mp"
    });
    var vault_keysets = keysets.filter(function(v) {
        return v.encryptedBy != "mp"
    });

    var root_keysets_obj = {};
    var vault_keysets_obj = {};
    for (var k = 0; k < root_keysets.length; k++) {

        var root_name = root_keysets[k]["uuid"];
        var l_root_salt = root_keysets[k]["encSymKey"]["p2s"];
        var c_root_iterations = root_keysets[k]["encSymKey"]["p2c"];
        var a_root_algorithm = root_keysets[k]["encSymKey"]["alg"];
        var root_iv = root_keysets[k]["encSymKey"]["iv"];
        var root_data = root_keysets[k]["encSymKey"]["data"];
        var root_priv_iv = root_keysets[k]["encPriKey"]["iv"];
        var root_priv_data = root_keysets[k]["encPriKey"]["data"];
        var h_transformed_root_algorithm = str2ab(a_root_algorithm);
        var v_hkdf_result = HKDF("sha256", fromBits(sjcl.codec.base64url.toBits(l_root_salt)), h_transformed_root_algorithm, y_transformed_email, 32);
        var v_hkdf_result_2 = await m_afterHKDF(d_normalized_password, v_hkdf_result, c_root_iterations, "SHA-256", 256);
        var v_hkdf_result_3 = combineWithBytes(v_hkdf_result_2, recoverykey);
        var root_sym_key = await subtle.importKey('raw', Uint8Array.from(v_hkdf_result_3), {
            "name": 'AES-GCM',
            "iv": Uint8Array.from(Buffer.from(root_iv, "base64"))
        }, true, ['encrypt', 'decrypt']);

        var alg = {
            "name": 'AES-GCM',
            "iv": Uint8Array.from(Buffer.from(root_iv, "base64")),
            "tagLength": 128
        };
        var decrypted_master_key = await subtle.decrypt(alg, root_sym_key, Uint8Array.from(Buffer.from(root_data, "base64")));
        var decrypted_master_key = (new TextDecoder().decode(decrypted_master_key));
        decrypted_master_key = JSON.parse(decrypted_master_key);

        var imported_master_key = await subtle.importKey(
            "jwk",
            decrypted_master_key, {
                "name": "AES-GCM"
            },
            true,
            ["encrypt", "decrypt"]
        )

        var alg2 = {
            "name": 'AES-GCM',
            "iv": Uint8Array.from(Buffer.from(root_priv_iv, "base64")),
            "tagLength": 128
        };
        var decrypted_master_private_key = await subtle.decrypt(alg2, imported_master_key, Uint8Array.from(Buffer.from(root_priv_data, "base64")));
        var decrypted_master_private_key = (new TextDecoder().decode(decrypted_master_private_key));
        decrypted_master_private_key = JSON.parse(decrypted_master_private_key);

        var algoDec = {
            name: 'RSA-OAEP',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: {
                name: "SHA-1"
            }
        };
        var master_private_key = await subtle.importKey('jwk', decrypted_master_private_key, algoDec, true, ['decrypt']);
        root_keysets_obj[root_name] = master_private_key;
    }
    for (var k = 0; k < vault_keysets.length; k++) {
        if (root_keysets_obj.hasOwnProperty(vault_keysets[k]["encryptedBy"])) {
            var masterKey = root_keysets_obj[vault_keysets[k]["encryptedBy"]];

            var decrypted_vault_symmetrickey = await DecryptVaultSymKey_RSAOAEP(masterKey, vault_keysets[k]["encSymKey"]["data"]);
            var decrypted_vault_privatekey = await DecryptVaultPrivKey_AESGCM(decrypted_vault_symmetrickey, vault_keysets[k]["encPriKey"]["data"], vault_keysets[k]["encPriKey"]["iv"])

            vault_keysets_obj[vault_keysets[k]["uuid"]] = {
                "privateKey": decrypted_vault_privatekey,
                "publicKey": vault_keysets[k]["pubKey"]
            };
        }
    }

    return {
        "vaults": vault_keysets_obj,
        "roots": root_keysets_obj
    }
}


async function DecryptVaultSymKey_RSAOAEP(masterPrivkey, data) {
    var decrypted = await subtle.decrypt({
            name: "RSA-OAEP",

        },
        masterPrivkey,
        Uint8Array.from(Buffer.from(data, "base64"))
    );
    decrypted = (new TextDecoder().decode(decrypted));
    decrypted = JSON.parse(decrypted);
    return (decrypted);

}

async function DecryptVaultPrivKey_AESGCM(key, data, iv) {
    var importedKey = await subtle.importKey(
        "jwk",
        key, {
            "name": "AES-GCM"
        },
        true,
        ["encrypt", "decrypt"]
    );

    var obj = {
        "name": 'AES-GCM',
        "iv": Uint8Array.from(Buffer.from(iv, "base64")),
        "tagLength": 128
    };
    var decrypted = await subtle.decrypt(obj, importedKey, Uint8Array.from(Buffer.from(data, "base64")));

    decrypted = (new TextDecoder().decode(decrypted));
    decrypted = JSON.parse(decrypted);
    return (decrypted);

}


function HKDF2(e, t, n, r, u) {
    var a, c;
    if ("SHA256" === e.toUpperCase())
        a = sjcl.hash.sha256,
        c = 32;
    else {
        if ("SHA512" !== e.toUpperCase()) {
            var s = new Error("Invalid hash function name");
            throw console.error(s, e),
                s
        }
        a = sjcl.hash.sha512,
            c = 64
    }
    var l = new sjcl.misc.hmac(bytes_toBits(r), a);
    l.update(bytes_toBits(t));
    for (var f = l.digest(), d = Math.ceil(u / c), p = sjcl.codec.hex.toBits(""), y = "", h = bytes_toBits(n), v = 0; v < d; v++) {
        var m = new sjcl.misc.hmac(f, a),
            g = sjcl.bitArray.concat(sjcl.bitArray.concat(p, h), sjcl.codec.utf8String.toBits(String.fromCharCode(v + 1)));
        m.update(g),
            p = m.digest(),
            y += sjcl.codec.hex.fromBits(p)
    }
    var b = sjcl.bitArray.clamp(sjcl.codec.hex.toBits(y), 8 * u);
    return new Uint8Array(fromBits(b))
}

function u002(e, t) {
    var n = "function" == typeof Symbol && e[Symbol.iterator];
    if (!n)
        return e;
    var r, i, o = n.call(e),
        u = [];
    try {
        for (;
            (void 0 === t || t-- > 0) && !(r = o.next()).done;)
            u.push(r.value)
    } catch (e) {
        i = {
            error: e
        }
    } finally {
        try {
            r && !r.done && (n = o.return) && n.call(o)
        } finally {
            if (i)
                throw i.error
        }
    }
    return u
}

function combineWithBytes(e, t) {
    var n, r, a = (0,
            str2ab)(t.key),
        c = (0,
            str2ab)(t.format),
        s = (0,
            str2ab)(t.id),
        l = HKDF2("sha256", a, c, s, e.length),
        f = new Uint8Array(e.length);
    try {
        for (var d = function(e) {
                var t = "function" == typeof Symbol && Symbol.iterator,
                    n = t && e[t],
                    r = 0;
                if (n)
                    return n.call(e);
                if (e && "number" == typeof e.length)
                    return {
                        next: function() {
                            return e && r >= e.length && (e = void 0), {
                                value: e && e[r++],
                                done: !e
                            }
                        }
                    };
                throw new TypeError(t ? "Object is not iterable." : "Symbol.iterator is not defined.")
            }(e.entries()), p = d.next(); !p.done; p = d.next()) {
            var y = u002(p.value, 2),
                h = y[0],
                v = y[1],
                m = l[h];
            if (void 0 === m)
                throw new Error("combineWithBytes: personalByte undefined");
            f[h] = v ^ m
        }
    } catch (e) {
        n = {
            error: e
        }
    } finally {
        try {
            p && !p.done && (r = d.return) && r.call(d)
        } finally {
            if (n)
                throw n.error
        }
    }
    return f
}

async function extract_user_key(credentials, authresponse) {
    var t = authresponse.userAuth;
    var n = credentials;
    var r = n.email;
    var i = n.secretKey;
    var o = n.password;

    var u = fromBits(sjcl.codec.base64url.toBits(t.salt));
    var a = str2ab(r);
    var f = str2ab(t.method);
    var d = HKDF2("sha256", u, f, a, 32);
    var p = await m_afterHKDF(o, d, t.iterations, "SHA-256", 256);
    var y = combineWithBytes(p, i);
    var result = sjcl.codec.hex.fromBits(bytes_toBits(y));
    return (result);

}
