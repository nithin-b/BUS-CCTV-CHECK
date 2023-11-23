(() => {
  var r = {
      452: function (e, t, r) {
        e.exports = (function (e) {
          for (
            var t = e,
              r,
              n = t.lib.BlockCipher,
              i = t.algo,
              l = [],
              a = [],
              _ = [],
              o = [],
              c = [],
              s = [],
              f = [],
              u = [],
              h = [],
              p = [],
              d = [],
              P = 0;
            P < 256;
            P++
          )
            if (P < 128) d[P] = P << 1;
            else d[P] = (P << 1) ^ 283;
          for (var v = 0, E = 0, P = 0; P < 256; P++) {
            var R = E ^ (E << 1) ^ (E << 2) ^ (E << 3) ^ (E << 4);
            R = (R >>> 8) ^ (R & 255) ^ 99;
            l[v] = R;
            a[R] = v;
            var T = d[v];
            var A = d[T];
            var m = d[A];
            var O = (d[R] * 257) ^ (R * 16843008);
            _[v] = (O << 24) | (O >>> 8);
            o[v] = (O << 16) | (O >>> 16);
            c[v] = (O << 8) | (O >>> 24);
            s[v] = O;
            var O = (m * 16843009) ^ (A * 65537) ^ (T * 257) ^ (v * 16843008);
            f[R] = (O << 24) | (O >>> 8);
            u[R] = (O << 16) | (O >>> 16);
            h[R] = (O << 8) | (O >>> 24);
            p[R] = O;
            if (!v) v = E = 1;
            else {
              v = T ^ d[d[d[m ^ T]]];
              E ^= d[d[E]];
            }
          }
          var g = [0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54],
            y = (i.AES = n.extend({
              _doReset: function () {
                var e;
                if (this._nRounds && this._keyPriorReset === this._key) return;
                var t = (this._keyPriorReset = this._key);
                var r = t.words;
                var n = t.sigBytes / 4;
                var i = (this._nRounds = n + 6);
                var a = (i + 1) * 4;
                var _ = (this._keySchedule = []);
                for (var o = 0; o < a; o++)
                  if (o < n) _[o] = r[o];
                  else {
                    e = _[o - 1];
                    if (!(o % n)) {
                      e = (e << 8) | (e >>> 24);
                      e =
                        (l[e >>> 24] << 24) |
                        (l[(e >>> 16) & 255] << 16) |
                        (l[(e >>> 8) & 255] << 8) |
                        l[e & 255];
                      e ^= g[(o / n) | 0] << 24;
                    } else if (n > 6 && o % n == 4)
                      e =
                        (l[e >>> 24] << 24) |
                        (l[(e >>> 16) & 255] << 16) |
                        (l[(e >>> 8) & 255] << 8) |
                        l[e & 255];
                    _[o] = _[o - n] ^ e;
                  }
                var c = (this._invKeySchedule = []);
                for (var s = 0; s < a; s++) {
                  var o = a - s;
                  if (s % 4) var e = _[o];
                  else var e = _[o - 4];
                  if (s < 4 || o <= 4) c[s] = e;
                  else
                    c[s] =
                      f[l[e >>> 24]] ^
                      u[l[(e >>> 16) & 255]] ^
                      h[l[(e >>> 8) & 255]] ^
                      p[l[e & 255]];
                }
              },
              encryptBlock: function (e, t) {
                this._doCryptBlock(e, t, this._keySchedule, _, o, c, s, l);
              },
              decryptBlock: function (e, t) {
                var r = e[t + 1];
                e[t + 1] = e[t + 3];
                e[t + 3] = r;
                this._doCryptBlock(e, t, this._invKeySchedule, f, u, h, p, a);
                var r = e[t + 1];
                e[t + 1] = e[t + 3];
                e[t + 3] = r;
              },
              _doCryptBlock: function (e, t, r, n, i, a, _, o) {
                var c = this._nRounds;
                var s = e[t] ^ r[0];
                var l = e[t + 1] ^ r[1];
                var f = e[t + 2] ^ r[2];
                var u = e[t + 3] ^ r[3];
                var h = 4;
                for (var p = 1; p < c; p++) {
                  var d =
                    n[s >>> 24] ^
                    i[(l >>> 16) & 255] ^
                    a[(f >>> 8) & 255] ^
                    _[u & 255] ^
                    r[h++];
                  var P =
                    n[l >>> 24] ^
                    i[(f >>> 16) & 255] ^
                    a[(u >>> 8) & 255] ^
                    _[s & 255] ^
                    r[h++];
                  var v =
                    n[f >>> 24] ^
                    i[(u >>> 16) & 255] ^
                    a[(s >>> 8) & 255] ^
                    _[l & 255] ^
                    r[h++];
                  var E =
                    n[u >>> 24] ^
                    i[(s >>> 16) & 255] ^
                    a[(l >>> 8) & 255] ^
                    _[f & 255] ^
                    r[h++];
                  s = d;
                  l = P;
                  f = v;
                  u = E;
                }
                var d =
                  ((o[s >>> 24] << 24) |
                    (o[(l >>> 16) & 255] << 16) |
                    (o[(f >>> 8) & 255] << 8) |
                    o[u & 255]) ^
                  r[h++];
                var P =
                  ((o[l >>> 24] << 24) |
                    (o[(f >>> 16) & 255] << 16) |
                    (o[(u >>> 8) & 255] << 8) |
                    o[s & 255]) ^
                  r[h++];
                var v =
                  ((o[f >>> 24] << 24) |
                    (o[(u >>> 16) & 255] << 16) |
                    (o[(s >>> 8) & 255] << 8) |
                    o[l & 255]) ^
                  r[h++];
                var E =
                  ((o[u >>> 24] << 24) |
                    (o[(s >>> 16) & 255] << 16) |
                    (o[(l >>> 8) & 255] << 8) |
                    o[f & 255]) ^
                  r[h++];
                e[t] = d;
                e[t + 1] = P;
                e[t + 2] = v;
                e[t + 3] = E;
              },
              keySize: 256 / 32,
            }));
          return (t.AES = n._createHelper(y)), e.AES;
        })(r(249), (r(269), r(214), r(888), r(109)));
      },
      109: function (e, t, r) {
        var n, _, i, a, o, c, s, l, f, u, h, p;
        e.exports =
          ((e = r(249)),
          r(888),
          void (
            e.lib.Cipher ||
            ((r = (e = e).lib),
            (n = r.Base),
            (_ = r.WordArray),
            (i = r.BufferedBlockAlgorithm),
            (f = e.enc).Utf8,
            (a = f.Base64),
            (o = e.algo.EvpKDF),
            (c = r.Cipher =
              i.extend({
                cfg: n.extend(),
                createEncryptor: function (e, t) {
                  return this.create(this._ENC_XFORM_MODE, e, t);
                },
                createDecryptor: function (e, t) {
                  return this.create(this._DEC_XFORM_MODE, e, t);
                },
                init: function (e, t, r) {
                  (this.cfg = this.cfg.extend(r)),
                    (this._xformMode = e),
                    (this._key = t),
                    this.reset();
                },
                reset: function () {
                  i.reset.call(this), this._doReset();
                },
                process: function (e) {
                  return this._append(e), this._process();
                },
                finalize: function (e) {
                  return e && this._append(e), this._doFinalize();
                },
                keySize: 4,
                ivSize: 4,
                _ENC_XFORM_MODE: 1,
                _DEC_XFORM_MODE: 2,
                _createHelper: (function () {
                  function i(e) {
                    return "string" == typeof e ? p : u;
                  }
                  return function (n) {
                    return {
                      encrypt: function (e, t, r) {
                        return i(t).encrypt(n, e, t, r);
                      },
                      decrypt: function (e, t, r) {
                        return i(t).decrypt(n, e, t, r);
                      },
                    };
                  };
                })(),
              })),
            (r.StreamCipher = c.extend({
              _doFinalize: function () {
                return this._process(!0);
              },
              blockSize: 1,
            })),
            (f = e.mode = {}),
            (s = r.BlockCipherMode =
              n.extend({
                createEncryptor: function (e, t) {
                  return this.Encryptor.create(e, t);
                },
                createDecryptor: function (e, t) {
                  return this.Decryptor.create(e, t);
                },
                init: function (e, t) {
                  (this._cipher = e), (this._iv = t);
                },
              })),
            (f = f.CBC =
              (function () {
                var e = s.extend();
                function a(e, t, r) {
                  var n,
                    i = this._iv;
                  i ? ((n = i), (this._iv = void 0)) : (n = this._prevBlock);
                  for (var a = 0; a < r; a++) e[t + a] ^= n[a];
                }
                return (
                  (e.Encryptor = e.extend({
                    processBlock: function (e, t) {
                      var r = this._cipher,
                        n = r.blockSize;
                      a.call(this, e, t, n),
                        r.encryptBlock(e, t),
                        (this._prevBlock = e.slice(t, t + n));
                    },
                  })),
                  (e.Decryptor = e.extend({
                    processBlock: function (e, t) {
                      var r = this._cipher,
                        n = r.blockSize,
                        i = e.slice(t, t + n);
                      r.decryptBlock(e, t),
                        a.call(this, e, t, n),
                        (this._prevBlock = i);
                    },
                  })),
                  e
                );
              })()),
            (h = (e.pad = {}).Pkcs7 =
              {
                pad: function (e, t) {
                  for (
                    var t = 4 * t,
                      r = t - (e.sigBytes % t),
                      n = (r << 24) | (r << 16) | (r << 8) | r,
                      i = [],
                      a = 0;
                    a < r;
                    a += 4
                  )
                    i.push(n);
                  t = _.create(i, r);
                  e.concat(t);
                },
                unpad: function (e) {
                  var t = 255 & e.words[(e.sigBytes - 1) >>> 2];
                  e.sigBytes -= t;
                },
              }),
            (r.BlockCipher = c.extend({
              cfg: c.cfg.extend({ mode: f, padding: h }),
              reset: function () {
                c.reset.call(this);
                var e,
                  t = this.cfg,
                  r = t.iv,
                  t = t.mode;
                this._xformMode == this._ENC_XFORM_MODE
                  ? (e = t.createEncryptor)
                  : ((e = t.createDecryptor), (this._minBufferSize = 1)),
                  this._mode && this._mode.__creator == e
                    ? this._mode.init(this, r && r.words)
                    : ((this._mode = e.call(t, this, r && r.words)),
                      (this._mode.__creator = e));
              },
              _doProcessBlock: function (e, t) {
                this._mode.processBlock(e, t);
              },
              _doFinalize: function () {
                var e,
                  t = this.cfg.padding;
                return (
                  this._xformMode == this._ENC_XFORM_MODE
                    ? (t.pad(this._data, this.blockSize),
                      (e = this._process(!0)))
                    : ((e = this._process(!0)), t.unpad(e)),
                  e
                );
              },
              blockSize: 4,
            })),
            (l = r.CipherParams =
              n.extend({
                init: function (e) {
                  this.mixIn(e);
                },
                toString: function (e) {
                  return (e || this.formatter).stringify(this);
                },
              })),
            (f = (e.format = {}).OpenSSL =
              {
                stringify: function (e) {
                  var t = e.ciphertext,
                    e = e.salt,
                    e = e
                      ? _.create([1398893684, 1701076831]).concat(e).concat(t)
                      : t;
                  return e.toString(a);
                },
                parse: function (e) {
                  var t,
                    e = a.parse(e),
                    r = e.words;
                  return (
                    1398893684 == r[0] &&
                      1701076831 == r[1] &&
                      ((t = _.create(r.slice(2, 4))),
                      r.splice(0, 4),
                      (e.sigBytes -= 16)),
                    l.create({ ciphertext: e, salt: t })
                  );
                },
              }),
            (u = r.SerializableCipher =
              n.extend({
                cfg: n.extend({ format: f }),
                encrypt: function (e, t, r, n) {
                  n = this.cfg.extend(n);
                  var i = e.createEncryptor(r, n),
                    t = i.finalize(t),
                    i = i.cfg;
                  return l.create({
                    ciphertext: t,
                    key: r,
                    iv: i.iv,
                    algorithm: e,
                    mode: i.mode,
                    padding: i.padding,
                    blockSize: e.blockSize,
                    formatter: n.format,
                  });
                },
                decrypt: function (e, t, r, n) {
                  return (
                    (n = this.cfg.extend(n)),
                    (t = this._parse(t, n.format)),
                    e.createDecryptor(r, n).finalize(t.ciphertext)
                  );
                },
                _parse: function (e, t) {
                  return "string" == typeof e ? t.parse(e, this) : e;
                },
              })),
            (h = (e.kdf = {}).OpenSSL =
              {
                execute: function (e, t, r, n) {
                  n = n || _.random(8);
                  (e = o.create({ keySize: t + r }).compute(e, n)),
                    (r = _.create(e.words.slice(t), 4 * r));
                  return (
                    (e.sigBytes = 4 * t), l.create({ key: e, iv: r, salt: n })
                  );
                },
              }),
            (p = r.PasswordBasedCipher =
              u.extend({
                cfg: u.cfg.extend({ kdf: h }),
                encrypt: function (e, t, r, n) {
                  (r = (n = this.cfg.extend(n)).kdf.execute(
                    r,
                    e.keySize,
                    e.ivSize
                  )),
                    (n.iv = r.iv),
                    (e = u.encrypt.call(this, e, t, r.key, n));
                  return e.mixIn(r), e;
                },
                decrypt: function (e, t, r, n) {
                  (n = this.cfg.extend(n)), (t = this._parse(t, n.format));
                  r = n.kdf.execute(r, e.keySize, e.ivSize, t.salt);
                  return (n.iv = r.iv), u.decrypt.call(this, e, t, r.key, n);
                },
              })))
          ));
      },
      249: function (e, t, p) {
        e.exports =
          ((e = (function (s) {
            var n;
            if (
              ("undefined" != typeof window &&
                window.crypto &&
                (n = window.crypto),
              "undefined" != typeof self && self.crypto && (n = self.crypto),
              !(n =
                !(n =
                  !(n =
                    "undefined" != typeof globalThis && globalThis.crypto
                      ? globalThis.crypto
                      : n) &&
                  "undefined" != typeof window &&
                  window.msCrypto
                    ? window.msCrypto
                    : n) &&
                void 0 !== p.g &&
                p.g.crypto
                  ? p.g.crypto
                  : n))
            )
              try {
                n = p(480);
              } catch (e) {}
            var r =
              Object.create ||
              function (e) {
                return (
                  (t.prototype = e), (e = new t()), (t.prototype = null), e
                );
              };
            function t() {}
            var e = {},
              i = (e.lib = {}),
              a = (i.Base = {
                extend: function (e) {
                  var t = r(this);
                  return (
                    e && t.mixIn(e),
                    (t.hasOwnProperty("init") && this.init !== t.init) ||
                      (t.init = function () {
                        t.$super.init.apply(this, arguments);
                      }),
                    ((t.init.prototype = t).$super = this),
                    t
                  );
                },
                create: function () {
                  var e = this.extend();
                  return e.init.apply(e, arguments), e;
                },
                init: function () {},
                mixIn: function (e) {
                  for (var t in e) e.hasOwnProperty(t) && (this[t] = e[t]);
                  e.hasOwnProperty("toString") && (this.toString = e.toString);
                },
                clone: function () {
                  return this.init.prototype.extend(this);
                },
              }),
              l = (i.WordArray = a.extend({
                init: function (e, t) {
                  (e = this.words = e || []),
                    (this.sigBytes = null != t ? t : 4 * e.length);
                },
                toString: function (e) {
                  return (e || o).stringify(this);
                },
                concat: function (e) {
                  var t = this.words,
                    r = e.words,
                    n = this.sigBytes,
                    i = e.sigBytes;
                  if ((this.clamp(), n % 4))
                    for (var a = 0; a < i; a++) {
                      var _ = (r[a >>> 2] >>> (24 - (a % 4) * 8)) & 255;
                      t[(n + a) >>> 2] |= _ << (24 - ((n + a) % 4) * 8);
                    }
                  else
                    for (var o = 0; o < i; o += 4)
                      t[(n + o) >>> 2] = r[o >>> 2];
                  return (this.sigBytes += i), this;
                },
                clamp: function () {
                  var e = this.words,
                    t = this.sigBytes;
                  (e[t >>> 2] &= 4294967295 << (32 - (t % 4) * 8)),
                    (e.length = s.ceil(t / 4));
                },
                clone: function () {
                  var e = a.clone.call(this);
                  return (e.words = this.words.slice(0)), e;
                },
                random: function (e) {
                  for (var t = [], r = 0; r < e; r += 4)
                    t.push(
                      (function () {
                        if (n) {
                          if ("function" == typeof n.getRandomValues)
                            try {
                              return n.getRandomValues(new Uint32Array(1))[0];
                            } catch (e) {}
                          if ("function" == typeof n.randomBytes)
                            try {
                              return n.randomBytes(4).readInt32LE();
                            } catch (e) {}
                        }
                        throw new Error(
                          "Native crypto module could not be used to get secure random number."
                        );
                      })()
                    );
                  return new l.init(t, e);
                },
              })),
              _ = (e.enc = {}),
              o = (_.Hex = {
                stringify: function (e) {
                  for (
                    var t = e.words, r = e.sigBytes, n = [], i = 0;
                    i < r;
                    i++
                  ) {
                    var a = (t[i >>> 2] >>> (24 - (i % 4) * 8)) & 255;
                    n.push((a >>> 4).toString(16)),
                      n.push((15 & a).toString(16));
                  }
                  return n.join("");
                },
                parse: function (e) {
                  for (var t = e.length, r = [], n = 0; n < t; n += 2)
                    r[n >>> 3] |=
                      parseInt(e.substr(n, 2), 16) << (24 - (n % 8) * 4);
                  return new l.init(r, t / 2);
                },
              }),
              c = (_.Latin1 = {
                stringify: function (e) {
                  for (
                    var t = e.words, r = e.sigBytes, n = [], i = 0;
                    i < r;
                    i++
                  ) {
                    var a = (t[i >>> 2] >>> (24 - (i % 4) * 8)) & 255;
                    n.push(String.fromCharCode(a));
                  }
                  return n.join("");
                },
                parse: function (e) {
                  for (var t = e.length, r = [], n = 0; n < t; n++)
                    r[n >>> 2] |= (255 & e.charCodeAt(n)) << (24 - (n % 4) * 8);
                  return new l.init(r, t);
                },
              }),
              f = (_.Utf8 = {
                stringify: function (e) {
                  try {
                    return decodeURIComponent(escape(c.stringify(e)));
                  } catch (e) {
                    throw new Error("Malformed UTF-8 data");
                  }
                },
                parse: function (e) {
                  return c.parse(unescape(encodeURIComponent(e)));
                },
              }),
              u = (i.BufferedBlockAlgorithm = a.extend({
                reset: function () {
                  (this._data = new l.init()), (this._nDataBytes = 0);
                },
                _append: function (e) {
                  "string" == typeof e && (e = f.parse(e)),
                    this._data.concat(e),
                    (this._nDataBytes += e.sigBytes);
                },
                _process: function (e) {
                  var t,
                    r = this._data,
                    n = r.words,
                    i = r.sigBytes,
                    a = this.blockSize,
                    _ = i / (4 * a),
                    o =
                      (_ = e
                        ? s.ceil(_)
                        : s.max((0 | _) - this._minBufferSize, 0)) * a,
                    e = s.min(4 * o, i);
                  if (o) {
                    for (var c = 0; c < o; c += a) this._doProcessBlock(n, c);
                    (t = n.splice(0, o)), (r.sigBytes -= e);
                  }
                  return new l.init(t, e);
                },
                clone: function () {
                  var e = a.clone.call(this);
                  return (e._data = this._data.clone()), e;
                },
                _minBufferSize: 0,
              })),
              h =
                ((i.Hasher = u.extend({
                  cfg: a.extend(),
                  init: function (e) {
                    (this.cfg = this.cfg.extend(e)), this.reset();
                  },
                  reset: function () {
                    u.reset.call(this), this._doReset();
                  },
                  update: function (e) {
                    return this._append(e), this._process(), this;
                  },
                  finalize: function (e) {
                    return e && this._append(e), this._doFinalize();
                  },
                  blockSize: 16,
                  _createHelper: function (r) {
                    return function (e, t) {
                      return new r.init(t).finalize(e);
                    };
                  },
                  _createHmacHelper: function (r) {
                    return function (e, t) {
                      return new h.HMAC.init(r, t).finalize(e);
                    };
                  },
                })),
                (e.algo = {}));
            return e;
          })(Math)),
          e);
      },
      269: function (e, t, r) {
        function _(e, t, r) {
          for (var n, i, a = [], _ = 0, o = 0; o < t; o++)
            o % 4 &&
              ((n = r[e.charCodeAt(o - 1)] << ((o % 4) * 2)),
              (i = r[e.charCodeAt(o)] >>> (6 - (o % 4) * 2)),
              (a[_ >>> 2] |= (n | i) << (24 - (_ % 4) * 8)),
              _++);
          return c.create(a, _);
        }
        var c;
        e.exports =
          ((e = r(249)),
          (c = e.lib.WordArray),
          (e.enc.Base64 = {
            stringify: function (e) {
              for (
                var t = e.words,
                  r = e.sigBytes,
                  n = this._map,
                  i = (e.clamp(), []),
                  a = 0;
                a < r;
                a += 3
              )
                for (
                  var _ =
                      (((t[a >>> 2] >>> (24 - (a % 4) * 8)) & 255) << 16) |
                      (((t[(a + 1) >>> 2] >>> (24 - ((a + 1) % 4) * 8)) &
                        255) <<
                        8) |
                      ((t[(a + 2) >>> 2] >>> (24 - ((a + 2) % 4) * 8)) & 255),
                    o = 0;
                  o < 4 && a + 0.75 * o < r;
                  o++
                )
                  i.push(n.charAt((_ >>> (6 * (3 - o))) & 63));
              var c = n.charAt(64);
              if (c) for (; i.length % 4; ) i.push(c);
              return i.join("");
            },
            parse: function (e) {
              var t = e.length,
                r = this._map;
              if (!(n = this._reverseMap))
                for (var n = (this._reverseMap = []), i = 0; i < r.length; i++)
                  n[r.charCodeAt(i)] = i;
              var a = r.charAt(64);
              return a && -1 !== (a = e.indexOf(a)) && (t = a), _(e, t, n);
            },
            _map: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
          }),
          e.enc.Base64);
      },
      786: function (e, t, r) {
        function _(e, t, r) {
          for (var n, i, a = [], _ = 0, o = 0; o < t; o++)
            o % 4 &&
              ((n = r[e.charCodeAt(o - 1)] << ((o % 4) * 2)),
              (i = r[e.charCodeAt(o)] >>> (6 - (o % 4) * 2)),
              (a[_ >>> 2] |= (n | i) << (24 - (_ % 4) * 8)),
              _++);
          return c.create(a, _);
        }
        var c;
        e.exports =
          ((e = r(249)),
          (c = e.lib.WordArray),
          (e.enc.Base64url = {
            stringify: function (e, t = !0) {
              for (
                var r = e.words,
                  n = e.sigBytes,
                  i = t ? this._safe_map : this._map,
                  a = (e.clamp(), []),
                  _ = 0;
                _ < n;
                _ += 3
              )
                for (
                  var o =
                      (((r[_ >>> 2] >>> (24 - (_ % 4) * 8)) & 255) << 16) |
                      (((r[(_ + 1) >>> 2] >>> (24 - ((_ + 1) % 4) * 8)) &
                        255) <<
                        8) |
                      ((r[(_ + 2) >>> 2] >>> (24 - ((_ + 2) % 4) * 8)) & 255),
                    c = 0;
                  c < 4 && _ + 0.75 * c < n;
                  c++
                )
                  a.push(i.charAt((o >>> (6 * (3 - c))) & 63));
              var s = i.charAt(64);
              if (s) for (; a.length % 4; ) a.push(s);
              return a.join("");
            },
            parse: function (e, t = !0) {
              var r = e.length,
                n = t ? this._safe_map : this._map;
              if (!(i = this._reverseMap))
                for (var i = (this._reverseMap = []), a = 0; a < n.length; a++)
                  i[n.charCodeAt(a)] = a;
              var t = n.charAt(64);
              return t && -1 !== (t = e.indexOf(t)) && (r = t), _(e, r, i);
            },
            _map: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
            _safe_map:
              "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
          }),
          e.enc.Base64url);
      },
      298: function (e, t, r) {
        function _(e) {
          return ((e << 8) & 4278255360) | ((e >>> 8) & 16711935);
        }
        var i;
        e.exports =
          ((e = r(249)),
          (i = e.lib.WordArray),
          ((r = e.enc).Utf16 = r.Utf16BE =
            {
              stringify: function (e) {
                for (
                  var t = e.words, r = e.sigBytes, n = [], i = 0;
                  i < r;
                  i += 2
                ) {
                  var a = (t[i >>> 2] >>> (16 - (i % 4) * 8)) & 65535;
                  n.push(String.fromCharCode(a));
                }
                return n.join("");
              },
              parse: function (e) {
                for (var t = e.length, r = [], n = 0; n < t; n++)
                  r[n >>> 1] |= e.charCodeAt(n) << (16 - (n % 2) * 16);
                return i.create(r, 2 * t);
              },
            }),
          (r.Utf16LE = {
            stringify: function (e) {
              for (
                var t = e.words, r = e.sigBytes, n = [], i = 0;
                i < r;
                i += 2
              ) {
                var a = _((t[i >>> 2] >>> (16 - (i % 4) * 8)) & 65535);
                n.push(String.fromCharCode(a));
              }
              return n.join("");
            },
            parse: function (e) {
              for (var t = e.length, r = [], n = 0; n < t; n++)
                r[n >>> 1] |= _(e.charCodeAt(n) << (16 - (n % 2) * 16));
              return i.create(r, 2 * t);
            },
          }),
          e.enc.Utf16);
      },
      888: function (e, t, r) {
        var n, l, i, a, _;
        e.exports =
          ((e = r(249)),
          r(783),
          r(824),
          (i = (r = e).lib),
          (n = i.Base),
          (l = i.WordArray),
          (i = r.algo),
          (a = i.MD5),
          (_ = i.EvpKDF =
            n.extend({
              cfg: n.extend({ keySize: 4, hasher: a, iterations: 1 }),
              init: function (e) {
                this.cfg = this.cfg.extend(e);
              },
              compute: function (e, t) {
                for (
                  var r,
                    n = this.cfg,
                    i = n.hasher.create(),
                    a = l.create(),
                    _ = a.words,
                    o = n.keySize,
                    c = n.iterations;
                  _.length < o;

                ) {
                  r && i.update(r), (r = i.update(e).finalize(t)), i.reset();
                  for (var s = 1; s < c; s++) (r = i.finalize(r)), i.reset();
                  a.concat(r);
                }
                return (a.sigBytes = 4 * o), a;
              },
            })),
          (r.EvpKDF = function (e, t, r) {
            return _.create(r).compute(e, t);
          }),
          e.EvpKDF);
      },
      209: function (e, t, r) {
        var n, i;
        e.exports =
          ((e = r(249)),
          r(109),
          (n = e.lib.CipherParams),
          (i = e.enc.Hex),
          (e.format.Hex = {
            stringify: function (e) {
              return e.ciphertext.toString(i);
            },
            parse: function (e) {
              e = i.parse(e);
              return n.create({ ciphertext: e });
            },
          }),
          e.format.Hex);
      },
      824: function (e, t, r) {
        var o;
        e.exports =
          ((e = r(249)),
          (r = e.lib.Base),
          (o = e.enc.Utf8),
          void (e.algo.HMAC = r.extend({
            init: function (e, t) {
              (e = this._hasher = new e.init()),
                "string" == typeof t && (t = o.parse(t));
              for (
                var r = e.blockSize,
                  n = 4 * r,
                  e =
                    ((t = t.sigBytes > n ? e.finalize(t) : t).clamp(),
                    (this._oKey = t.clone())),
                  t = (this._iKey = t.clone()),
                  i = e.words,
                  a = t.words,
                  _ = 0;
                _ < r;
                _++
              )
                (i[_] ^= 1549556828), (a[_] ^= 909522486);
              (e.sigBytes = t.sigBytes = n), this.reset();
            },
            reset: function () {
              var e = this._hasher;
              e.reset(), e.update(this._iKey);
            },
            update: function (e) {
              return this._hasher.update(e), this;
            },
            finalize: function (e) {
              var t = this._hasher,
                e = t.finalize(e);
              return t.reset(), t.finalize(this._oKey.clone().concat(e));
            },
          })));
      },
      354: function (e, t, r) {
        e.exports =
          ((e = r(249)),
          r(938),
          r(433),
          r(298),
          r(269),
          r(786),
          r(214),
          r(783),
          r(153),
          r(792),
          r(34),
          r(460),
          r(327),
          r(706),
          r(824),
          r(112),
          r(888),
          r(109),
          r(568),
          r(242),
          r(968),
          r(660),
          r(148),
          r(615),
          r(807),
          r(77),
          r(475),
          r(991),
          r(209),
          r(452),
          r(253),
          r(857),
          r(454),
          r(974),
          e);
      },
      433: function (e, t, r) {
        var n;
        e.exports =
          ((n = r(249)),
          (function () {
            var e, i;
            "function" == typeof ArrayBuffer &&
              ((e = n.lib.WordArray),
              (i = e.init),
              ((e.init = function (e) {
                if (
                  (e =
                    (e =
                      e instanceof ArrayBuffer
                        ? new Uint8Array(e)
                        : e) instanceof Int8Array ||
                    ("undefined" != typeof Uint8ClampedArray &&
                      e instanceof Uint8ClampedArray) ||
                    e instanceof Int16Array ||
                    e instanceof Uint16Array ||
                    e instanceof Int32Array ||
                    e instanceof Uint32Array ||
                    e instanceof Float32Array ||
                    e instanceof Float64Array
                      ? new Uint8Array(e.buffer, e.byteOffset, e.byteLength)
                      : e) instanceof Uint8Array
                ) {
                  for (var t = e.byteLength, r = [], n = 0; n < t; n++)
                    r[n >>> 2] |= e[n] << (24 - (n % 4) * 8);
                  i.call(this, r, t);
                } else i.apply(this, arguments);
              }).prototype = e));
          })(),
          n.lib.WordArray);
      },
      214: function (e, t, r) {
        e.exports = (function (e) {
          for (
            var l = Math,
              t = e,
              r = t.lib,
              n = r.WordArray,
              i = r.Hasher,
              a = t.algo,
              C = [],
              _ = 0;
            _ < 64;
            _++
          )
            C[_] = (l.abs(l.sin(_ + 1)) * 4294967296) | 0;
          var o = (a.MD5 = i.extend({
            _doReset: function () {
              this._hash = new n.init([
                1732584193, 4023233417, 2562383102, 271733878,
              ]);
            },
            _doProcessBlock: function (e, t) {
              for (var r = 0; r < 16; r++) {
                var n = t + r;
                var i = e[n];
                e[n] =
                  (((i << 8) | (i >>> 24)) & 16711935) |
                  (((i << 24) | (i >>> 8)) & 4278255360);
              }
              var a = this._hash.words;
              var _ = e[t + 0];
              var o = e[t + 1];
              var c = e[t + 2];
              var s = e[t + 3];
              var l = e[t + 4];
              var f = e[t + 5];
              var u = e[t + 6];
              var h = e[t + 7];
              var p = e[t + 8];
              var d = e[t + 9];
              var P = e[t + 10];
              var v = e[t + 11];
              var E = e[t + 12];
              var R = e[t + 13];
              var T = e[t + 14];
              var A = e[t + 15];
              var m = a[0];
              var O = a[1];
              var g = a[2];
              var y = a[3];
              m = M(m, O, g, y, _, 7, C[0]);
              y = M(y, m, O, g, o, 12, C[1]);
              g = M(g, y, m, O, c, 17, C[2]);
              O = M(O, g, y, m, s, 22, C[3]);
              m = M(m, O, g, y, l, 7, C[4]);
              y = M(y, m, O, g, f, 12, C[5]);
              g = M(g, y, m, O, u, 17, C[6]);
              O = M(O, g, y, m, h, 22, C[7]);
              m = M(m, O, g, y, p, 7, C[8]);
              y = M(y, m, O, g, d, 12, C[9]);
              g = M(g, y, m, O, P, 17, C[10]);
              O = M(O, g, y, m, v, 22, C[11]);
              m = M(m, O, g, y, E, 7, C[12]);
              y = M(y, m, O, g, R, 12, C[13]);
              g = M(g, y, m, O, T, 17, C[14]);
              O = M(O, g, y, m, A, 22, C[15]);
              m = I(m, O, g, y, o, 5, C[16]);
              y = I(y, m, O, g, u, 9, C[17]);
              g = I(g, y, m, O, v, 14, C[18]);
              O = I(O, g, y, m, _, 20, C[19]);
              m = I(m, O, g, y, f, 5, C[20]);
              y = I(y, m, O, g, P, 9, C[21]);
              g = I(g, y, m, O, A, 14, C[22]);
              O = I(O, g, y, m, l, 20, C[23]);
              m = I(m, O, g, y, d, 5, C[24]);
              y = I(y, m, O, g, T, 9, C[25]);
              g = I(g, y, m, O, s, 14, C[26]);
              O = I(O, g, y, m, p, 20, C[27]);
              m = I(m, O, g, y, R, 5, C[28]);
              y = I(y, m, O, g, c, 9, C[29]);
              g = I(g, y, m, O, h, 14, C[30]);
              O = I(O, g, y, m, E, 20, C[31]);
              m = S(m, O, g, y, f, 4, C[32]);
              y = S(y, m, O, g, p, 11, C[33]);
              g = S(g, y, m, O, v, 16, C[34]);
              O = S(O, g, y, m, T, 23, C[35]);
              m = S(m, O, g, y, o, 4, C[36]);
              y = S(y, m, O, g, l, 11, C[37]);
              g = S(g, y, m, O, h, 16, C[38]);
              O = S(O, g, y, m, P, 23, C[39]);
              m = S(m, O, g, y, R, 4, C[40]);
              y = S(y, m, O, g, _, 11, C[41]);
              g = S(g, y, m, O, s, 16, C[42]);
              O = S(O, g, y, m, u, 23, C[43]);
              m = S(m, O, g, y, d, 4, C[44]);
              y = S(y, m, O, g, E, 11, C[45]);
              g = S(g, y, m, O, A, 16, C[46]);
              O = S(O, g, y, m, c, 23, C[47]);
              m = w(m, O, g, y, _, 6, C[48]);
              y = w(y, m, O, g, h, 10, C[49]);
              g = w(g, y, m, O, T, 15, C[50]);
              O = w(O, g, y, m, f, 21, C[51]);
              m = w(m, O, g, y, E, 6, C[52]);
              y = w(y, m, O, g, s, 10, C[53]);
              g = w(g, y, m, O, P, 15, C[54]);
              O = w(O, g, y, m, o, 21, C[55]);
              m = w(m, O, g, y, p, 6, C[56]);
              y = w(y, m, O, g, A, 10, C[57]);
              g = w(g, y, m, O, u, 15, C[58]);
              O = w(O, g, y, m, R, 21, C[59]);
              m = w(m, O, g, y, l, 6, C[60]);
              y = w(y, m, O, g, v, 10, C[61]);
              g = w(g, y, m, O, c, 15, C[62]);
              O = w(O, g, y, m, d, 21, C[63]);
              a[0] = (a[0] + m) | 0;
              a[1] = (a[1] + O) | 0;
              a[2] = (a[2] + g) | 0;
              a[3] = (a[3] + y) | 0;
            },
            _doFinalize: function () {
              var e = this._data;
              var t = e.words;
              var r = this._nDataBytes * 8;
              var n = e.sigBytes * 8;
              t[n >>> 5] |= 128 << (24 - (n % 32));
              var i = l.floor(r / 4294967296);
              var a = r;
              t[(((n + 64) >>> 9) << 4) + 15] =
                (((i << 8) | (i >>> 24)) & 16711935) |
                (((i << 24) | (i >>> 8)) & 4278255360);
              t[(((n + 64) >>> 9) << 4) + 14] =
                (((a << 8) | (a >>> 24)) & 16711935) |
                (((a << 24) | (a >>> 8)) & 4278255360);
              e.sigBytes = (t.length + 1) * 4;
              this._process();
              var _ = this._hash;
              var o = _.words;
              for (var c = 0; c < 4; c++) {
                var s = o[c];
                o[c] =
                  (((s << 8) | (s >>> 24)) & 16711935) |
                  (((s << 24) | (s >>> 8)) & 4278255360);
              }
              return _;
            },
            clone: function () {
              var e = i.clone.call(this);
              e._hash = this._hash.clone();
              return e;
            },
          }));
          function M(e, t, r, n, i, a, _) {
            var o = e + ((t & r) | (~t & n)) + i + _;
            return ((o << a) | (o >>> (32 - a))) + t;
          }
          function I(e, t, r, n, i, a, _) {
            var o = e + ((t & n) | (r & ~n)) + i + _;
            return ((o << a) | (o >>> (32 - a))) + t;
          }
          function S(e, t, r, n, i, a, _) {
            var o = e + (t ^ r ^ n) + i + _;
            return ((o << a) | (o >>> (32 - a))) + t;
          }
          function w(e, t, r, n, i, a, _) {
            var o = e + (r ^ (t | ~n)) + i + _;
            return ((o << a) | (o >>> (32 - a))) + t;
          }
          return (
            (t.MD5 = i._createHelper(o)),
            (t.HmacMD5 = i._createHmacHelper(o)),
            e.MD5
          );
        })(r(249));
      },
      568: function (e, t, r) {
        var n;
        e.exports =
          ((n = r(249)),
          r(109),
          (n.mode.CFB = (function () {
            var e = n.lib.BlockCipherMode.extend();
            function a(e, t, r, n) {
              var i,
                a = this._iv;
              a
                ? ((i = a.slice(0)), (this._iv = void 0))
                : (i = this._prevBlock),
                n.encryptBlock(i, 0);
              for (var _ = 0; _ < r; _++) e[t + _] ^= i[_];
            }
            return (
              (e.Encryptor = e.extend({
                processBlock: function (e, t) {
                  var r = this._cipher,
                    n = r.blockSize;
                  a.call(this, e, t, n, r),
                    (this._prevBlock = e.slice(t, t + n));
                },
              })),
              (e.Decryptor = e.extend({
                processBlock: function (e, t) {
                  var r = this._cipher,
                    n = r.blockSize,
                    i = e.slice(t, t + n);
                  a.call(this, e, t, n, r), (this._prevBlock = i);
                },
              })),
              e
            );
          })()),
          n.mode.CFB);
      },
      968: function (e, t, r) {
        var n;
        e.exports =
          ((n = r(249)),
          r(109),
          /** @preserve
           * Counter block mode compatible with  Dr Brian Gladman fileenc.c
           * derived from CryptoJS.mode.CTR
           * Jan Hruby jhruby.web@gmail.com
           */
          (n.mode.CTRGladman = (function () {
            var e = n.lib.BlockCipherMode.extend();
            function c(e) {
              var t, r, n;
              return (
                255 == ((e >> 24) & 255)
                  ? ((r = (e >> 8) & 255),
                    (n = 255 & e),
                    255 === (t = (e >> 16) & 255)
                      ? ((t = 0),
                        255 === r ? ((r = 0), 255 === n ? (n = 0) : ++n) : ++r)
                      : ++t,
                    (e = 0),
                    (e = (e += t << 16) + (r << 8) + n))
                  : (e += 1 << 24),
                e
              );
            }
            var t = (e.Encryptor = e.extend({
              processBlock: function (e, t) {
                var r = this._cipher,
                  n = r.blockSize,
                  i = this._iv,
                  a = this._counter,
                  _ =
                    (i &&
                      ((a = this._counter = i.slice(0)), (this._iv = void 0)),
                    0 === ((i = a)[0] = c(i[0])) && (i[1] = c(i[1])),
                    a.slice(0));
                r.encryptBlock(_, 0);
                for (var o = 0; o < n; o++) e[t + o] ^= _[o];
              },
            }));
            return (e.Decryptor = t), e;
          })()),
          n.mode.CTRGladman);
      },
      242: function (e, t, r) {
        var n;
        e.exports =
          ((n = r(249)),
          r(109),
          (n.mode.CTR = (function () {
            var e = n.lib.BlockCipherMode.extend(),
              t = (e.Encryptor = e.extend({
                processBlock: function (e, t) {
                  var r = this._cipher,
                    n = r.blockSize,
                    i = this._iv,
                    a = this._counter,
                    _ =
                      (i &&
                        ((a = this._counter = i.slice(0)), (this._iv = void 0)),
                      a.slice(0));
                  r.encryptBlock(_, 0), (a[n - 1] = (a[n - 1] + 1) | 0);
                  for (var o = 0; o < n; o++) e[t + o] ^= _[o];
                },
              }));
            return (e.Decryptor = t), e;
          })()),
          n.mode.CTR);
      },
      148: function (e, t, r) {
        var n;
        e.exports =
          ((n = r(249)),
          r(109),
          (n.mode.ECB = (function () {
            var e = n.lib.BlockCipherMode.extend();
            return (
              (e.Encryptor = e.extend({
                processBlock: function (e, t) {
                  this._cipher.encryptBlock(e, t);
                },
              })),
              (e.Decryptor = e.extend({
                processBlock: function (e, t) {
                  this._cipher.decryptBlock(e, t);
                },
              })),
              e
            );
          })()),
          n.mode.ECB);
      },
      660: function (e, t, r) {
        var n;
        e.exports =
          ((n = r(249)),
          r(109),
          (n.mode.OFB = (function () {
            var e = n.lib.BlockCipherMode.extend(),
              t = (e.Encryptor = e.extend({
                processBlock: function (e, t) {
                  var r = this._cipher,
                    n = r.blockSize,
                    i = this._iv,
                    a = this._keystream;
                  i &&
                    ((a = this._keystream = i.slice(0)), (this._iv = void 0)),
                    r.encryptBlock(a, 0);
                  for (var _ = 0; _ < n; _++) e[t + _] ^= a[_];
                },
              }));
            return (e.Decryptor = t), e;
          })()),
          n.mode.OFB);
      },
      615: function (e, t, r) {
        e.exports =
          ((e = r(249)),
          r(109),
          (e.pad.AnsiX923 = {
            pad: function (e, t) {
              var r = e.sigBytes,
                t = 4 * t,
                t = t - (r % t),
                r = r + t - 1;
              e.clamp(),
                (e.words[r >>> 2] |= t << (24 - (r % 4) * 8)),
                (e.sigBytes += t);
            },
            unpad: function (e) {
              var t = 255 & e.words[(e.sigBytes - 1) >>> 2];
              e.sigBytes -= t;
            },
          }),
          e.pad.Ansix923);
      },
      807: function (e, t, r) {
        var n;
        e.exports =
          ((n = r(249)),
          r(109),
          (n.pad.Iso10126 = {
            pad: function (e, t) {
              (t *= 4), (t -= e.sigBytes % t);
              e.concat(n.lib.WordArray.random(t - 1)).concat(
                n.lib.WordArray.create([t << 24], 1)
              );
            },
            unpad: function (e) {
              var t = 255 & e.words[(e.sigBytes - 1) >>> 2];
              e.sigBytes -= t;
            },
          }),
          n.pad.Iso10126);
      },
      77: function (e, t, r) {
        var n;
        e.exports =
          ((n = r(249)),
          r(109),
          (n.pad.Iso97971 = {
            pad: function (e, t) {
              e.concat(n.lib.WordArray.create([2147483648], 1)),
                n.pad.ZeroPadding.pad(e, t);
            },
            unpad: function (e) {
              n.pad.ZeroPadding.unpad(e), e.sigBytes--;
            },
          }),
          n.pad.Iso97971);
      },
      991: function (e, t, r) {
        e.exports =
          ((e = r(249)),
          r(109),
          (e.pad.NoPadding = { pad: function () {}, unpad: function () {} }),
          e.pad.NoPadding);
      },
      475: function (e, t, r) {
        e.exports =
          ((e = r(249)),
          r(109),
          (e.pad.ZeroPadding = {
            pad: function (e, t) {
              t *= 4;
              e.clamp(), (e.sigBytes += t - (e.sigBytes % t || t));
            },
            unpad: function (e) {
              for (
                var t = e.words, r = e.sigBytes - 1, r = e.sigBytes - 1;
                0 <= r;
                r--
              )
                if ((t[r >>> 2] >>> (24 - (r % 4) * 8)) & 255) {
                  e.sigBytes = r + 1;
                  break;
                }
            },
          }),
          e.pad.ZeroPadding);
      },
      112: function (e, t, r) {
        var n, v, i, a, E, _;
        e.exports =
          ((e = r(249)),
          r(783),
          r(824),
          (i = (r = e).lib),
          (n = i.Base),
          (v = i.WordArray),
          (i = r.algo),
          (a = i.SHA1),
          (E = i.HMAC),
          (_ = i.PBKDF2 =
            n.extend({
              cfg: n.extend({ keySize: 4, hasher: a, iterations: 1 }),
              init: function (e) {
                this.cfg = this.cfg.extend(e);
              },
              compute: function (e, t) {
                for (
                  var r = this.cfg,
                    n = E.create(r.hasher, e),
                    i = v.create(),
                    a = v.create([1]),
                    _ = i.words,
                    o = a.words,
                    c = r.keySize,
                    s = r.iterations;
                  _.length < c;

                ) {
                  for (
                    var l = n.update(t).finalize(a),
                      f = (n.reset(), l.words),
                      u = f.length,
                      h = l,
                      p = 1;
                    p < s;
                    p++
                  ) {
                    (h = n.finalize(h)), n.reset();
                    for (var d = h.words, P = 0; P < u; P++) f[P] ^= d[P];
                  }
                  i.concat(l), o[0]++;
                }
                return (i.sigBytes = 4 * c), i;
              },
            })),
          (r.PBKDF2 = function (e, t, r) {
            return _.create(r).compute(e, t);
          }),
          e.PBKDF2);
      },
      974: function (e, t, r) {
        function o() {
          for (var e = this._X, t = this._C, r = 0; r < 8; r++) _[r] = t[r];
          (t[0] = (t[0] + 1295307597 + this._b) | 0),
            (t[1] =
              (t[1] + 3545052371 + (t[0] >>> 0 < _[0] >>> 0 ? 1 : 0)) | 0),
            (t[2] = (t[2] + 886263092 + (t[1] >>> 0 < _[1] >>> 0 ? 1 : 0)) | 0),
            (t[3] =
              (t[3] + 1295307597 + (t[2] >>> 0 < _[2] >>> 0 ? 1 : 0)) | 0),
            (t[4] =
              (t[4] + 3545052371 + (t[3] >>> 0 < _[3] >>> 0 ? 1 : 0)) | 0),
            (t[5] = (t[5] + 886263092 + (t[4] >>> 0 < _[4] >>> 0 ? 1 : 0)) | 0),
            (t[6] =
              (t[6] + 1295307597 + (t[5] >>> 0 < _[5] >>> 0 ? 1 : 0)) | 0),
            (t[7] =
              (t[7] + 3545052371 + (t[6] >>> 0 < _[6] >>> 0 ? 1 : 0)) | 0),
            (this._b = t[7] >>> 0 < _[7] >>> 0 ? 1 : 0);
          for (r = 0; r < 8; r++) {
            var n = e[r] + t[r],
              i = 65535 & n,
              a = n >>> 16;
            c[r] =
              (((((i * i) >>> 17) + i * a) >>> 15) + a * a) ^
              ((((4294901760 & n) * n) | 0) + (((65535 & n) * n) | 0));
          }
          (e[0] =
            (c[0] +
              ((c[7] << 16) | (c[7] >>> 16)) +
              ((c[6] << 16) | (c[6] >>> 16))) |
            0),
            (e[1] = (c[1] + ((c[0] << 8) | (c[0] >>> 24)) + c[7]) | 0),
            (e[2] =
              (c[2] +
                ((c[1] << 16) | (c[1] >>> 16)) +
                ((c[0] << 16) | (c[0] >>> 16))) |
              0),
            (e[3] = (c[3] + ((c[2] << 8) | (c[2] >>> 24)) + c[1]) | 0),
            (e[4] =
              (c[4] +
                ((c[3] << 16) | (c[3] >>> 16)) +
                ((c[2] << 16) | (c[2] >>> 16))) |
              0),
            (e[5] = (c[5] + ((c[4] << 8) | (c[4] >>> 24)) + c[3]) | 0),
            (e[6] =
              (c[6] +
                ((c[5] << 16) | (c[5] >>> 16)) +
                ((c[4] << 16) | (c[4] >>> 16))) |
              0),
            (e[7] = (c[7] + ((c[6] << 8) | (c[6] >>> 24)) + c[5]) | 0);
        }
        var n, i, _, c, a;
        e.exports =
          ((e = r(249)),
          r(269),
          r(214),
          r(888),
          r(109),
          (n = (r = e).lib.StreamCipher),
          (a = r.algo),
          (i = []),
          (_ = []),
          (c = []),
          (a = a.RabbitLegacy =
            n.extend({
              _doReset: function () {
                for (
                  var e = this._key.words,
                    t = this.cfg.iv,
                    r = (this._X = [
                      e[0],
                      (e[3] << 16) | (e[2] >>> 16),
                      e[1],
                      (e[0] << 16) | (e[3] >>> 16),
                      e[2],
                      (e[1] << 16) | (e[0] >>> 16),
                      e[3],
                      (e[2] << 16) | (e[1] >>> 16),
                    ]),
                    n = (this._C = [
                      (e[2] << 16) | (e[2] >>> 16),
                      (4294901760 & e[0]) | (65535 & e[1]),
                      (e[3] << 16) | (e[3] >>> 16),
                      (4294901760 & e[1]) | (65535 & e[2]),
                      (e[0] << 16) | (e[0] >>> 16),
                      (4294901760 & e[2]) | (65535 & e[3]),
                      (e[1] << 16) | (e[1] >>> 16),
                      (4294901760 & e[3]) | (65535 & e[0]),
                    ]),
                    i = (this._b = 0);
                  i < 4;
                  i++
                )
                  o.call(this);
                for (i = 0; i < 8; i++) n[i] ^= r[(i + 4) & 7];
                if (t) {
                  var e = t.words,
                    t = e[0],
                    e = e[1],
                    t =
                      (16711935 & ((t << 8) | (t >>> 24))) |
                      (4278255360 & ((t << 24) | (t >>> 8))),
                    e =
                      (16711935 & ((e << 8) | (e >>> 24))) |
                      (4278255360 & ((e << 24) | (e >>> 8))),
                    a = (t >>> 16) | (4294901760 & e),
                    _ = (e << 16) | (65535 & t);
                  (n[0] ^= t),
                    (n[1] ^= a),
                    (n[2] ^= e),
                    (n[3] ^= _),
                    (n[4] ^= t),
                    (n[5] ^= a),
                    (n[6] ^= e),
                    (n[7] ^= _);
                  for (i = 0; i < 4; i++) o.call(this);
                }
              },
              _doProcessBlock: function (e, t) {
                var r = this._X;
                o.call(this),
                  (i[0] = r[0] ^ (r[5] >>> 16) ^ (r[3] << 16)),
                  (i[1] = r[2] ^ (r[7] >>> 16) ^ (r[5] << 16)),
                  (i[2] = r[4] ^ (r[1] >>> 16) ^ (r[7] << 16)),
                  (i[3] = r[6] ^ (r[3] >>> 16) ^ (r[1] << 16));
                for (var n = 0; n < 4; n++)
                  (i[n] =
                    (16711935 & ((i[n] << 8) | (i[n] >>> 24))) |
                    (4278255360 & ((i[n] << 24) | (i[n] >>> 8)))),
                    (e[t + n] ^= i[n]);
              },
              blockSize: 4,
              ivSize: 2,
            })),
          (r.RabbitLegacy = n._createHelper(a)),
          e.RabbitLegacy);
      },
      454: function (e, t, r) {
        function c() {
          for (var e = this._X, t = this._C, r = 0; r < 8; r++) _[r] = t[r];
          (t[0] = (t[0] + 1295307597 + this._b) | 0),
            (t[1] =
              (t[1] + 3545052371 + (t[0] >>> 0 < _[0] >>> 0 ? 1 : 0)) | 0),
            (t[2] = (t[2] + 886263092 + (t[1] >>> 0 < _[1] >>> 0 ? 1 : 0)) | 0),
            (t[3] =
              (t[3] + 1295307597 + (t[2] >>> 0 < _[2] >>> 0 ? 1 : 0)) | 0),
            (t[4] =
              (t[4] + 3545052371 + (t[3] >>> 0 < _[3] >>> 0 ? 1 : 0)) | 0),
            (t[5] = (t[5] + 886263092 + (t[4] >>> 0 < _[4] >>> 0 ? 1 : 0)) | 0),
            (t[6] =
              (t[6] + 1295307597 + (t[5] >>> 0 < _[5] >>> 0 ? 1 : 0)) | 0),
            (t[7] =
              (t[7] + 3545052371 + (t[6] >>> 0 < _[6] >>> 0 ? 1 : 0)) | 0),
            (this._b = t[7] >>> 0 < _[7] >>> 0 ? 1 : 0);
          for (r = 0; r < 8; r++) {
            var n = e[r] + t[r],
              i = 65535 & n,
              a = n >>> 16;
            o[r] =
              (((((i * i) >>> 17) + i * a) >>> 15) + a * a) ^
              ((((4294901760 & n) * n) | 0) + (((65535 & n) * n) | 0));
          }
          (e[0] =
            (o[0] +
              ((o[7] << 16) | (o[7] >>> 16)) +
              ((o[6] << 16) | (o[6] >>> 16))) |
            0),
            (e[1] = (o[1] + ((o[0] << 8) | (o[0] >>> 24)) + o[7]) | 0),
            (e[2] =
              (o[2] +
                ((o[1] << 16) | (o[1] >>> 16)) +
                ((o[0] << 16) | (o[0] >>> 16))) |
              0),
            (e[3] = (o[3] + ((o[2] << 8) | (o[2] >>> 24)) + o[1]) | 0),
            (e[4] =
              (o[4] +
                ((o[3] << 16) | (o[3] >>> 16)) +
                ((o[2] << 16) | (o[2] >>> 16))) |
              0),
            (e[5] = (o[5] + ((o[4] << 8) | (o[4] >>> 24)) + o[3]) | 0),
            (e[6] =
              (o[6] +
                ((o[5] << 16) | (o[5] >>> 16)) +
                ((o[4] << 16) | (o[4] >>> 16))) |
              0),
            (e[7] = (o[7] + ((o[6] << 8) | (o[6] >>> 24)) + o[5]) | 0);
        }
        var n, i, _, o, a;
        e.exports =
          ((e = r(249)),
          r(269),
          r(214),
          r(888),
          r(109),
          (n = (r = e).lib.StreamCipher),
          (a = r.algo),
          (i = []),
          (_ = []),
          (o = []),
          (a = a.Rabbit =
            n.extend({
              _doReset: function () {
                for (
                  var e = this._key.words, t = this.cfg.iv, r = 0;
                  r < 4;
                  r++
                )
                  e[r] =
                    (16711935 & ((e[r] << 8) | (e[r] >>> 24))) |
                    (4278255360 & ((e[r] << 24) | (e[r] >>> 8)));
                for (
                  var n = (this._X = [
                      e[0],
                      (e[3] << 16) | (e[2] >>> 16),
                      e[1],
                      (e[0] << 16) | (e[3] >>> 16),
                      e[2],
                      (e[1] << 16) | (e[0] >>> 16),
                      e[3],
                      (e[2] << 16) | (e[1] >>> 16),
                    ]),
                    i = (this._C = [
                      (e[2] << 16) | (e[2] >>> 16),
                      (4294901760 & e[0]) | (65535 & e[1]),
                      (e[3] << 16) | (e[3] >>> 16),
                      (4294901760 & e[1]) | (65535 & e[2]),
                      (e[0] << 16) | (e[0] >>> 16),
                      (4294901760 & e[2]) | (65535 & e[3]),
                      (e[1] << 16) | (e[1] >>> 16),
                      (4294901760 & e[3]) | (65535 & e[0]),
                    ]),
                    r = (this._b = 0);
                  r < 4;
                  r++
                )
                  c.call(this);
                for (r = 0; r < 8; r++) i[r] ^= n[(r + 4) & 7];
                if (t) {
                  var t = t.words,
                    a = t[0],
                    t = t[1],
                    a =
                      (16711935 & ((a << 8) | (a >>> 24))) |
                      (4278255360 & ((a << 24) | (a >>> 8))),
                    t =
                      (16711935 & ((t << 8) | (t >>> 24))) |
                      (4278255360 & ((t << 24) | (t >>> 8))),
                    _ = (a >>> 16) | (4294901760 & t),
                    o = (t << 16) | (65535 & a);
                  (i[0] ^= a),
                    (i[1] ^= _),
                    (i[2] ^= t),
                    (i[3] ^= o),
                    (i[4] ^= a),
                    (i[5] ^= _),
                    (i[6] ^= t),
                    (i[7] ^= o);
                  for (r = 0; r < 4; r++) c.call(this);
                }
              },
              _doProcessBlock: function (e, t) {
                var r = this._X;
                c.call(this),
                  (i[0] = r[0] ^ (r[5] >>> 16) ^ (r[3] << 16)),
                  (i[1] = r[2] ^ (r[7] >>> 16) ^ (r[5] << 16)),
                  (i[2] = r[4] ^ (r[1] >>> 16) ^ (r[7] << 16)),
                  (i[3] = r[6] ^ (r[3] >>> 16) ^ (r[1] << 16));
                for (var n = 0; n < 4; n++)
                  (i[n] =
                    (16711935 & ((i[n] << 8) | (i[n] >>> 24))) |
                    (4278255360 & ((i[n] << 24) | (i[n] >>> 8)))),
                    (e[t + n] ^= i[n]);
              },
              blockSize: 4,
              ivSize: 2,
            })),
          (r.Rabbit = n._createHelper(a)),
          e.Rabbit);
      },
      857: function (e, t, r) {
        function n() {
          for (
            var e = this._S, t = this._i, r = this._j, n = 0, i = 0;
            i < 4;
            i++
          ) {
            var r = (r + e[(t = (t + 1) % 256)]) % 256,
              a = e[t];
            (e[t] = e[r]),
              (e[r] = a),
              (n |= e[(e[t] + e[r]) % 256] << (24 - 8 * i));
          }
          return (this._i = t), (this._j = r), n;
        }
        var i, a, _;
        e.exports =
          ((e = r(249)),
          r(269),
          r(214),
          r(888),
          r(109),
          (i = (r = e).lib.StreamCipher),
          (_ = r.algo),
          (a = _.RC4 =
            i.extend({
              _doReset: function () {
                for (
                  var e = this._key,
                    t = e.words,
                    r = e.sigBytes,
                    n = (this._S = []),
                    i = 0;
                  i < 256;
                  i++
                )
                  n[i] = i;
                for (var i = 0, a = 0; i < 256; i++) {
                  var _ = i % r,
                    _ = (t[_ >>> 2] >>> (24 - (_ % 4) * 8)) & 255,
                    a = (a + n[i] + _) % 256,
                    _ = n[i];
                  (n[i] = n[a]), (n[a] = _);
                }
                this._i = this._j = 0;
              },
              _doProcessBlock: function (e, t) {
                e[t] ^= n.call(this);
              },
              keySize: 8,
              ivSize: 0,
            })),
          (r.RC4 = i._createHelper(a)),
          (_ = _.RC4Drop =
            a.extend({
              cfg: a.cfg.extend({ drop: 192 }),
              _doReset: function () {
                a._doReset.call(this);
                for (var e = this.cfg.drop; 0 < e; e--) n.call(this);
              },
            })),
          (r.RC4Drop = i._createHelper(_)),
          e.RC4);
      },
      706: function (e, t, r) {
        function O(e, t, r) {
          return (e & t) | (~e & r);
        }
        function g(e, t, r) {
          return (e & r) | (t & ~r);
        }
        function y(e, t) {
          return (e << t) | (e >>> (32 - t));
        }
        var n, i, C, M, I, S, w, x, a;
        e.exports =
          ((e = r(249)),
          Math,
          (a = (r = e).lib),
          (n = a.WordArray),
          (i = a.Hasher),
          (a = r.algo),
          (C = n.create([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1,
            10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1,
            2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15,
            14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
          ])),
          (M = n.create([
            5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7,
            0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9,
            11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13,
            9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
          ])),
          (I = n.create([
            11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13,
            11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13,
            15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14,
            5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8,
            5, 6,
          ])),
          (S = n.create([
            8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15,
            7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6,
            14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9,
            12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13,
            11, 11,
          ])),
          (w = n.create([0, 1518500249, 1859775393, 2400959708, 2840853838])),
          (x = n.create([1352829926, 1548603684, 1836072691, 2053994217, 0])),
          (a = a.RIPEMD160 =
            i.extend({
              _doReset: function () {
                this._hash = n.create([
                  1732584193, 4023233417, 2562383102, 271733878, 3285377520,
                ]);
              },
              _doProcessBlock: function (e, t) {
                for (var r = 0; r < 16; r++) {
                  var n = t + r,
                    i = e[n];
                  e[n] =
                    (16711935 & ((i << 8) | (i >>> 24))) |
                    (4278255360 & ((i << 24) | (i >>> 8)));
                }
                for (
                  var a,
                    _,
                    o,
                    c,
                    s,
                    l,
                    f = this._hash.words,
                    u = w.words,
                    h = x.words,
                    p = C.words,
                    d = M.words,
                    P = I.words,
                    v = S.words,
                    E = (a = f[0]),
                    R = (_ = f[1]),
                    T = (o = f[2]),
                    A = (c = f[3]),
                    m = (s = f[4]),
                    r = 0;
                  r < 80;
                  r += 1
                )
                  (l =
                    ((l = y(
                      (l =
                        ((l = (a + e[t + p[r]]) | 0) +
                          (r < 16
                            ? (_ ^ o ^ c) + u[0]
                            : r < 32
                            ? O(_, o, c) + u[1]
                            : r < 48
                            ? ((_ | ~o) ^ c) + u[2]
                            : r < 64
                            ? g(_, o, c) + u[3]
                            : (_ ^ (o | ~c)) + u[4])) |
                        0),
                      P[r]
                    )) +
                      s) |
                    0),
                    (a = s),
                    (s = c),
                    (c = y(o, 10)),
                    (o = _),
                    (_ = l),
                    (l =
                      ((l = y(
                        (l =
                          ((l = (E + e[t + d[r]]) | 0) +
                            (r < 16
                              ? (R ^ (T | ~A)) + h[0]
                              : r < 32
                              ? g(R, T, A) + h[1]
                              : r < 48
                              ? ((R | ~T) ^ A) + h[2]
                              : r < 64
                              ? O(R, T, A) + h[3]
                              : (R ^ T ^ A) + h[4])) |
                          0),
                        v[r]
                      )) +
                        m) |
                      0),
                    (E = m),
                    (m = A),
                    (A = y(T, 10)),
                    (T = R),
                    (R = l);
                (l = (f[1] + o + A) | 0),
                  (f[1] = (f[2] + c + m) | 0),
                  (f[2] = (f[3] + s + E) | 0),
                  (f[3] = (f[4] + a + R) | 0),
                  (f[4] = (f[0] + _ + T) | 0),
                  (f[0] = l);
              },
              _doFinalize: function () {
                for (
                  var e = this._data,
                    t = e.words,
                    r = 8 * this._nDataBytes,
                    n = 8 * e.sigBytes,
                    n =
                      ((t[n >>> 5] |= 128 << (24 - (n % 32))),
                      (t[14 + (((64 + n) >>> 9) << 4)] =
                        (16711935 & ((r << 8) | (r >>> 24))) |
                        (4278255360 & ((r << 24) | (r >>> 8)))),
                      (e.sigBytes = 4 * (t.length + 1)),
                      this._process(),
                      this._hash),
                    i = n.words,
                    a = 0;
                  a < 5;
                  a++
                ) {
                  var _ = i[a];
                  i[a] =
                    (16711935 & ((_ << 8) | (_ >>> 24))) |
                    (4278255360 & ((_ << 24) | (_ >>> 8)));
                }
                return n;
              },
              clone: function () {
                var e = i.clone.call(this);
                return (e._hash = this._hash.clone()), e;
              },
            })),
          (r.RIPEMD160 = i._createHelper(a)),
          (r.HmacRIPEMD160 = i._createHmacHelper(a)),
          e.RIPEMD160);
      },
      783: function (e, t, r) {
        var n, i, l, a;
        e.exports =
          ((e = r(249)),
          (a = (r = e).lib),
          (n = a.WordArray),
          (i = a.Hasher),
          (a = r.algo),
          (l = []),
          (a = a.SHA1 =
            i.extend({
              _doReset: function () {
                this._hash = new n.init([
                  1732584193, 4023233417, 2562383102, 271733878, 3285377520,
                ]);
              },
              _doProcessBlock: function (e, t) {
                for (
                  var r = this._hash.words,
                    n = r[0],
                    i = r[1],
                    a = r[2],
                    _ = r[3],
                    o = r[4],
                    c = 0;
                  c < 80;
                  c++
                ) {
                  c < 16
                    ? (l[c] = 0 | e[t + c])
                    : ((s = l[c - 3] ^ l[c - 8] ^ l[c - 14] ^ l[c - 16]),
                      (l[c] = (s << 1) | (s >>> 31)));
                  var s = ((n << 5) | (n >>> 27)) + o + l[c];
                  (s +=
                    c < 20
                      ? 1518500249 + ((i & a) | (~i & _))
                      : c < 40
                      ? 1859775393 + (i ^ a ^ _)
                      : c < 60
                      ? ((i & a) | (i & _) | (a & _)) - 1894007588
                      : (i ^ a ^ _) - 899497514),
                    (o = _),
                    (_ = a),
                    (a = (i << 30) | (i >>> 2)),
                    (i = n),
                    (n = s);
                }
                (r[0] = (r[0] + n) | 0),
                  (r[1] = (r[1] + i) | 0),
                  (r[2] = (r[2] + a) | 0),
                  (r[3] = (r[3] + _) | 0),
                  (r[4] = (r[4] + o) | 0);
              },
              _doFinalize: function () {
                var e = this._data,
                  t = e.words,
                  r = 8 * this._nDataBytes,
                  n = 8 * e.sigBytes;
                return (
                  (t[n >>> 5] |= 128 << (24 - (n % 32))),
                  (t[14 + (((64 + n) >>> 9) << 4)] = Math.floor(
                    r / 4294967296
                  )),
                  (t[15 + (((64 + n) >>> 9) << 4)] = r),
                  (e.sigBytes = 4 * t.length),
                  this._process(),
                  this._hash
                );
              },
              clone: function () {
                var e = i.clone.call(this);
                return (e._hash = this._hash.clone()), e;
              },
            })),
          (r.SHA1 = i._createHelper(a)),
          (r.HmacSHA1 = i._createHmacHelper(a)),
          e.SHA1);
      },
      792: function (e, t, r) {
        var n, i, a;
        e.exports =
          ((e = r(249)),
          r(153),
          (n = (r = e).lib.WordArray),
          (a = r.algo),
          (i = a.SHA256),
          (a = a.SHA224 =
            i.extend({
              _doReset: function () {
                this._hash = new n.init([
                  3238371032, 914150663, 812702999, 4144912697, 4290775857,
                  1750603025, 1694076839, 3204075428,
                ]);
              },
              _doFinalize: function () {
                var e = i._doFinalize.call(this);
                return (e.sigBytes -= 4), e;
              },
            })),
          (r.SHA224 = i._createHelper(a)),
          (r.HmacSHA224 = i._createHmacHelper(a)),
          e.SHA224);
      },
      153: function (e, t, r) {
        e.exports = (function (e) {
          var i = Math,
            t = e,
            r = t.lib,
            n = r.WordArray,
            a = r.Hasher,
            _ = t.algo,
            o = [],
            m = [];
          function c(e) {
            var t = i.sqrt(e);
            for (var r = 2; r <= t; r++) if (!(e % r)) return false;
            return true;
          }
          function s(e) {
            return ((e - (e | 0)) * 4294967296) | 0;
          }
          var l = 2,
            f = 0;
          while (f < 64) {
            if (c(l)) {
              if (f < 8) o[f] = s(i.pow(l, 1 / 2));
              m[f] = s(i.pow(l, 1 / 3));
              f++;
            }
            l++;
          }
          var O = [],
            u = (_.SHA256 = a.extend({
              _doReset: function () {
                this._hash = new n.init(o.slice(0));
              },
              _doProcessBlock: function (e, t) {
                var r = this._hash.words;
                var n = r[0];
                var i = r[1];
                var a = r[2];
                var _ = r[3];
                var o = r[4];
                var c = r[5];
                var s = r[6];
                var l = r[7];
                for (var f = 0; f < 64; f++) {
                  if (f < 16) O[f] = e[t + f] | 0;
                  else {
                    var u = O[f - 15];
                    var h =
                      ((u << 25) | (u >>> 7)) ^
                      ((u << 14) | (u >>> 18)) ^
                      (u >>> 3);
                    var p = O[f - 2];
                    var d =
                      ((p << 15) | (p >>> 17)) ^
                      ((p << 13) | (p >>> 19)) ^
                      (p >>> 10);
                    O[f] = h + O[f - 7] + d + O[f - 16];
                  }
                  var P = (o & c) ^ (~o & s);
                  var v = (n & i) ^ (n & a) ^ (i & a);
                  var E =
                    ((n << 30) | (n >>> 2)) ^
                    ((n << 19) | (n >>> 13)) ^
                    ((n << 10) | (n >>> 22));
                  var R =
                    ((o << 26) | (o >>> 6)) ^
                    ((o << 21) | (o >>> 11)) ^
                    ((o << 7) | (o >>> 25));
                  var T = l + R + P + m[f] + O[f];
                  var A = E + v;
                  l = s;
                  s = c;
                  c = o;
                  o = (_ + T) | 0;
                  _ = a;
                  a = i;
                  i = n;
                  n = (T + A) | 0;
                }
                r[0] = (r[0] + n) | 0;
                r[1] = (r[1] + i) | 0;
                r[2] = (r[2] + a) | 0;
                r[3] = (r[3] + _) | 0;
                r[4] = (r[4] + o) | 0;
                r[5] = (r[5] + c) | 0;
                r[6] = (r[6] + s) | 0;
                r[7] = (r[7] + l) | 0;
              },
              _doFinalize: function () {
                var e = this._data;
                var t = e.words;
                var r = this._nDataBytes * 8;
                var n = e.sigBytes * 8;
                t[n >>> 5] |= 128 << (24 - (n % 32));
                t[(((n + 64) >>> 9) << 4) + 14] = i.floor(r / 4294967296);
                t[(((n + 64) >>> 9) << 4) + 15] = r;
                e.sigBytes = t.length * 4;
                this._process();
                return this._hash;
              },
              clone: function () {
                var e = a.clone.call(this);
                e._hash = this._hash.clone();
                return e;
              },
            }));
          return (
            (t.SHA256 = a._createHelper(u)),
            (t.HmacSHA256 = a._createHmacHelper(u)),
            e.SHA256
          );
        })(r(249));
      },
      327: function (e, t, r) {
        e.exports = (function (e) {
          for (
            var h = Math,
              t = e,
              r = t.lib,
              p = r.WordArray,
              n = r.Hasher,
              i,
              a = t.x64.Word,
              _ = t.algo,
              S = [],
              w = [],
              x = [],
              o = 1,
              c = 0,
              s = 0;
            s < 24;
            s++
          ) {
            S[o + 5 * c] = (((s + 1) * (s + 2)) / 2) % 64;
            var l = c % 5;
            var f = (2 * o + 3 * c) % 5;
            o = l;
            c = f;
          }
          for (var o = 0; o < 5; o++)
            for (var c = 0; c < 5; c++)
              w[o + 5 * c] = c + ((2 * o + 3 * c) % 5) * 5;
          for (var u = 1, d = 0; d < 24; d++) {
            var P = 0;
            var v = 0;
            for (var E = 0; E < 7; E++) {
              if (u & 1) {
                var R = (1 << E) - 1;
                if (R < 32) v ^= 1 << R;
                else P ^= 1 << (R - 32);
              }
              if (u & 128) u = (u << 1) ^ 113;
              else u <<= 1;
            }
            x[d] = a.create(P, v);
          }
          for (var N = [], T = 0; T < 25; T++) N[T] = a.create();
          var A = (_.SHA3 = n.extend({
            cfg: n.cfg.extend({ outputLength: 512 }),
            _doReset: function () {
              var e = (this._state = []);
              for (var t = 0; t < 25; t++) e[t] = new a.init();
              this.blockSize = (1600 - 2 * this.cfg.outputLength) / 32;
            },
            _doProcessBlock: function (e, t) {
              var r = this._state;
              var n = this.blockSize / 2;
              for (var i = 0; i < n; i++) {
                var a = e[t + 2 * i];
                var _ = e[t + 2 * i + 1];
                a =
                  (((a << 8) | (a >>> 24)) & 16711935) |
                  (((a << 24) | (a >>> 8)) & 4278255360);
                _ =
                  (((_ << 8) | (_ >>> 24)) & 16711935) |
                  (((_ << 24) | (_ >>> 8)) & 4278255360);
                var o = r[i];
                o.high ^= _;
                o.low ^= a;
              }
              for (var c = 0; c < 24; c++) {
                for (var s = 0; s < 5; s++) {
                  var l = 0,
                    f = 0;
                  for (var u = 0; u < 5; u++) {
                    var o = r[s + 5 * u];
                    l ^= o.high;
                    f ^= o.low;
                  }
                  var h = N[s];
                  h.high = l;
                  h.low = f;
                }
                for (var s = 0; s < 5; s++) {
                  var p = N[(s + 4) % 5];
                  var d = N[(s + 1) % 5];
                  var P = d.high;
                  var v = d.low;
                  var l = p.high ^ ((P << 1) | (v >>> 31));
                  var f = p.low ^ ((v << 1) | (P >>> 31));
                  for (var u = 0; u < 5; u++) {
                    var o = r[s + 5 * u];
                    o.high ^= l;
                    o.low ^= f;
                  }
                }
                for (var E = 1; E < 25; E++) {
                  var l;
                  var f;
                  var o = r[E];
                  var R = o.high;
                  var T = o.low;
                  var A = S[E];
                  if (A < 32) {
                    l = (R << A) | (T >>> (32 - A));
                    f = (T << A) | (R >>> (32 - A));
                  } else {
                    l = (T << (A - 32)) | (R >>> (64 - A));
                    f = (R << (A - 32)) | (T >>> (64 - A));
                  }
                  var m = N[w[E]];
                  m.high = l;
                  m.low = f;
                }
                var O = N[0];
                var g = r[0];
                O.high = g.high;
                O.low = g.low;
                for (var s = 0; s < 5; s++)
                  for (var u = 0; u < 5; u++) {
                    var E = s + 5 * u;
                    var o = r[E];
                    var y = N[E];
                    var C = N[((s + 1) % 5) + 5 * u];
                    var M = N[((s + 2) % 5) + 5 * u];
                    o.high = y.high ^ (~C.high & M.high);
                    o.low = y.low ^ (~C.low & M.low);
                  }
                var o = r[0];
                var I = x[c];
                o.high ^= I.high;
                o.low ^= I.low;
              }
            },
            _doFinalize: function () {
              var e = this._data;
              var t = e.words;
              var r = this._nDataBytes * 8;
              var n = e.sigBytes * 8;
              var i = this.blockSize * 32;
              t[n >>> 5] |= 1 << (24 - (n % 32));
              t[((h.ceil((n + 1) / i) * i) >>> 5) - 1] |= 128;
              e.sigBytes = t.length * 4;
              this._process();
              var a = this._state;
              var _ = this.cfg.outputLength / 8;
              var o = _ / 8;
              var c = [];
              for (var s = 0; s < o; s++) {
                var l = a[s];
                var f = l.high;
                var u = l.low;
                f =
                  (((f << 8) | (f >>> 24)) & 16711935) |
                  (((f << 24) | (f >>> 8)) & 4278255360);
                u =
                  (((u << 8) | (u >>> 24)) & 16711935) |
                  (((u << 24) | (u >>> 8)) & 4278255360);
                c.push(u);
                c.push(f);
              }
              return new p.init(c, _);
            },
            clone: function () {
              var e = n.clone.call(this);
              var t = (e._state = this._state.slice(0));
              for (var r = 0; r < 25; r++) t[r] = t[r].clone();
              return e;
            },
          }));
          return (
            (t.SHA3 = n._createHelper(A)),
            (t.HmacSHA3 = n._createHmacHelper(A)),
            e.SHA3
          );
        })(r(249), r(938));
      },
      460: function (e, t, r) {
        var n, i, a, _;
        e.exports =
          ((e = r(249)),
          r(938),
          r(34),
          (_ = (r = e).x64),
          (n = _.Word),
          (i = _.WordArray),
          (_ = r.algo),
          (a = _.SHA512),
          (_ = _.SHA384 =
            a.extend({
              _doReset: function () {
                this._hash = new i.init([
                  new n.init(3418070365, 3238371032),
                  new n.init(1654270250, 914150663),
                  new n.init(2438529370, 812702999),
                  new n.init(355462360, 4144912697),
                  new n.init(1731405415, 4290775857),
                  new n.init(2394180231, 1750603025),
                  new n.init(3675008525, 1694076839),
                  new n.init(1203062813, 3204075428),
                ]);
              },
              _doFinalize: function () {
                var e = a._doFinalize.call(this);
                return (e.sigBytes -= 16), e;
              },
            })),
          (r.SHA384 = a._createHelper(_)),
          (r.HmacSHA384 = a._createHmacHelper(_)),
          e.SHA384);
      },
      34: function (e, t, r) {
        e.exports = (function (e) {
          var t = e,
            r,
            n = t.lib.Hasher,
            i = t.x64,
            a = i.Word,
            _ = i.WordArray,
            o = t.algo;
          function c() {
            return a.create.apply(a, arguments);
          }
          for (
            var ge = [
                c(1116352408, 3609767458),
                c(1899447441, 602891725),
                c(3049323471, 3964484399),
                c(3921009573, 2173295548),
                c(961987163, 4081628472),
                c(1508970993, 3053834265),
                c(2453635748, 2937671579),
                c(2870763221, 3664609560),
                c(3624381080, 2734883394),
                c(310598401, 1164996542),
                c(607225278, 1323610764),
                c(1426881987, 3590304994),
                c(1925078388, 4068182383),
                c(2162078206, 991336113),
                c(2614888103, 633803317),
                c(3248222580, 3479774868),
                c(3835390401, 2666613458),
                c(4022224774, 944711139),
                c(264347078, 2341262773),
                c(604807628, 2007800933),
                c(770255983, 1495990901),
                c(1249150122, 1856431235),
                c(1555081692, 3175218132),
                c(1996064986, 2198950837),
                c(2554220882, 3999719339),
                c(2821834349, 766784016),
                c(2952996808, 2566594879),
                c(3210313671, 3203337956),
                c(3336571891, 1034457026),
                c(3584528711, 2466948901),
                c(113926993, 3758326383),
                c(338241895, 168717936),
                c(666307205, 1188179964),
                c(773529912, 1546045734),
                c(1294757372, 1522805485),
                c(1396182291, 2643833823),
                c(1695183700, 2343527390),
                c(1986661051, 1014477480),
                c(2177026350, 1206759142),
                c(2456956037, 344077627),
                c(2730485921, 1290863460),
                c(2820302411, 3158454273),
                c(3259730800, 3505952657),
                c(3345764771, 106217008),
                c(3516065817, 3606008344),
                c(3600352804, 1432725776),
                c(4094571909, 1467031594),
                c(275423344, 851169720),
                c(430227734, 3100823752),
                c(506948616, 1363258195),
                c(659060556, 3750685593),
                c(883997877, 3785050280),
                c(958139571, 3318307427),
                c(1322822218, 3812723403),
                c(1537002063, 2003034995),
                c(1747873779, 3602036899),
                c(1955562222, 1575990012),
                c(2024104815, 1125592928),
                c(2227730452, 2716904306),
                c(2361852424, 442776044),
                c(2428436474, 593698344),
                c(2756734187, 3733110249),
                c(3204031479, 2999351573),
                c(3329325298, 3815920427),
                c(3391569614, 3928383900),
                c(3515267271, 566280711),
                c(3940187606, 3454069534),
                c(4118630271, 4000239992),
                c(116418474, 1914138554),
                c(174292421, 2731055270),
                c(289380356, 3203993006),
                c(460393269, 320620315),
                c(685471733, 587496836),
                c(852142971, 1086792851),
                c(1017036298, 365543100),
                c(1126000580, 2618297676),
                c(1288033470, 3409855158),
                c(1501505948, 4234509866),
                c(1607167915, 987167468),
                c(1816402316, 1246189591),
              ],
              ye = [],
              s = 0;
            s < 80;
            s++
          )
            ye[s] = c();
          var l = (o.SHA512 = n.extend({
            _doReset: function () {
              this._hash = new _.init([
                new a.init(1779033703, 4089235720),
                new a.init(3144134277, 2227873595),
                new a.init(1013904242, 4271175723),
                new a.init(2773480762, 1595750129),
                new a.init(1359893119, 2917565137),
                new a.init(2600822924, 725511199),
                new a.init(528734635, 4215389547),
                new a.init(1541459225, 327033209),
              ]);
            },
            _doProcessBlock: function (b, U) {
              var e = this._hash.words;
              var t = e[0];
              var r = e[1];
              var n = e[2];
              var i = e[3];
              var a = e[4];
              var _ = e[5];
              var o = e[6];
              var c = e[7];
              var F = t.high;
              var s = t.low;
              var B = r.high;
              var l = r.low;
              var H = n.high;
              var f = n.low;
              var Y = i.high;
              var u = i.low;
              var V = a.high;
              var h = a.low;
              var X = _.high;
              var p = _.low;
              var K = o.high;
              var z = o.low;
              var G = c.high;
              var q = c.low;
              var d = F;
              var P = s;
              var v = B;
              var E = l;
              var R = H;
              var T = f;
              var Q = Y;
              var A = u;
              var m = V;
              var O = h;
              var W = X;
              var g = p;
              var j = K;
              var y = z;
              var Z = G;
              var C = q;
              for (var M = 0; M < 80; M++) {
                var I;
                var S;
                var J = ye[M];
                if (M < 16) {
                  S = J.high = b[U + M * 2] | 0;
                  I = J.low = b[U + M * 2 + 1] | 0;
                } else {
                  var $ = ye[M - 15];
                  var w = $.high;
                  var x = $.low;
                  var ee =
                    ((w >>> 1) | (x << 31)) ^
                    ((w >>> 8) | (x << 24)) ^
                    (w >>> 7);
                  var te =
                    ((x >>> 1) | (w << 31)) ^
                    ((x >>> 8) | (w << 24)) ^
                    ((x >>> 7) | (w << 25));
                  var re = ye[M - 2];
                  var N = re.high;
                  var D = re.low;
                  var ne =
                    ((N >>> 19) | (D << 13)) ^
                    ((N << 3) | (D >>> 29)) ^
                    (N >>> 6);
                  var ie =
                    ((D >>> 19) | (N << 13)) ^
                    ((D << 3) | (N >>> 29)) ^
                    ((D >>> 6) | (N << 26));
                  var ae = ye[M - 7];
                  var _e = ae.high;
                  var oe = ae.low;
                  var ce = ye[M - 16];
                  var se = ce.high;
                  var le = ce.low;
                  I = te + oe;
                  S = ee + _e + (I >>> 0 < te >>> 0 ? 1 : 0);
                  I = I + ie;
                  S = S + ne + (I >>> 0 < ie >>> 0 ? 1 : 0);
                  I = I + le;
                  S = S + se + (I >>> 0 < le >>> 0 ? 1 : 0);
                  J.high = S;
                  J.low = I;
                }
                var fe = (m & W) ^ (~m & j);
                var ue = (O & g) ^ (~O & y);
                var he = (d & v) ^ (d & R) ^ (v & R);
                var pe = (P & E) ^ (P & T) ^ (E & T);
                var de =
                  ((d >>> 28) | (P << 4)) ^
                  ((d << 30) | (P >>> 2)) ^
                  ((d << 25) | (P >>> 7));
                var Pe =
                  ((P >>> 28) | (d << 4)) ^
                  ((P << 30) | (d >>> 2)) ^
                  ((P << 25) | (d >>> 7));
                var ve =
                  ((m >>> 14) | (O << 18)) ^
                  ((m >>> 18) | (O << 14)) ^
                  ((m << 23) | (O >>> 9));
                var Ee =
                  ((O >>> 14) | (m << 18)) ^
                  ((O >>> 18) | (m << 14)) ^
                  ((O << 23) | (m >>> 9));
                var Re = ge[M];
                var Te = Re.high;
                var Ae = Re.low;
                var k = C + Ee;
                var L = Z + ve + (k >>> 0 < C >>> 0 ? 1 : 0);
                var k = k + ue;
                var L = L + fe + (k >>> 0 < ue >>> 0 ? 1 : 0);
                var k = k + Ae;
                var L = L + Te + (k >>> 0 < Ae >>> 0 ? 1 : 0);
                var k = k + I;
                var L = L + S + (k >>> 0 < I >>> 0 ? 1 : 0);
                var me = Pe + pe;
                var Oe = de + he + (me >>> 0 < Pe >>> 0 ? 1 : 0);
                Z = j;
                C = y;
                j = W;
                y = g;
                W = m;
                g = O;
                O = (A + k) | 0;
                m = (Q + L + (O >>> 0 < A >>> 0 ? 1 : 0)) | 0;
                Q = R;
                A = T;
                R = v;
                T = E;
                v = d;
                E = P;
                P = (k + me) | 0;
                d = (L + Oe + (P >>> 0 < k >>> 0 ? 1 : 0)) | 0;
              }
              s = t.low = s + P;
              t.high = F + d + (s >>> 0 < P >>> 0 ? 1 : 0);
              l = r.low = l + E;
              r.high = B + v + (l >>> 0 < E >>> 0 ? 1 : 0);
              f = n.low = f + T;
              n.high = H + R + (f >>> 0 < T >>> 0 ? 1 : 0);
              u = i.low = u + A;
              i.high = Y + Q + (u >>> 0 < A >>> 0 ? 1 : 0);
              h = a.low = h + O;
              a.high = V + m + (h >>> 0 < O >>> 0 ? 1 : 0);
              p = _.low = p + g;
              _.high = X + W + (p >>> 0 < g >>> 0 ? 1 : 0);
              z = o.low = z + y;
              o.high = K + j + (z >>> 0 < y >>> 0 ? 1 : 0);
              q = c.low = q + C;
              c.high = G + Z + (q >>> 0 < C >>> 0 ? 1 : 0);
            },
            _doFinalize: function () {
              var e = this._data;
              var t = e.words;
              var r = this._nDataBytes * 8;
              var n = e.sigBytes * 8;
              t[n >>> 5] |= 128 << (24 - (n % 32));
              t[(((n + 128) >>> 10) << 5) + 30] = Math.floor(r / 4294967296);
              t[(((n + 128) >>> 10) << 5) + 31] = r;
              e.sigBytes = t.length * 4;
              this._process();
              var i = this._hash.toX32();
              return i;
            },
            clone: function () {
              var e = n.clone.call(this);
              e._hash = this._hash.clone();
              return e;
            },
            blockSize: 1024 / 32,
          }));
          return (
            (t.SHA512 = n._createHelper(l)),
            (t.HmacSHA512 = n._createHmacHelper(l)),
            e.SHA512
          );
        })(r(249), r(938));
      },
      253: function (e, t, r) {
        function l(e, t) {
          t = ((this._lBlock >>> e) ^ this._rBlock) & t;
          (this._rBlock ^= t), (this._lBlock ^= t << e);
        }
        function f(e, t) {
          t = ((this._rBlock >>> e) ^ this._lBlock) & t;
          (this._lBlock ^= t), (this._rBlock ^= t << e);
        }
        var n, i, s, u, h, p, d, a, _;
        e.exports =
          ((e = r(249)),
          r(269),
          r(214),
          r(888),
          r(109),
          (i = (r = e).lib),
          (n = i.WordArray),
          (i = i.BlockCipher),
          (_ = r.algo),
          (s = [
            57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51,
            43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28,
            20, 12, 4,
          ]),
          (u = [
            14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33,
            48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
          ]),
          (h = [1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28]),
          (p = [
            {
              0: 8421888,
              268435456: 32768,
              536870912: 8421378,
              805306368: 2,
              1073741824: 512,
              1342177280: 8421890,
              1610612736: 8389122,
              1879048192: 8388608,
              2147483648: 514,
              2415919104: 8389120,
              2684354560: 33280,
              2952790016: 8421376,
              3221225472: 32770,
              3489660928: 8388610,
              3758096384: 0,
              4026531840: 33282,
              134217728: 0,
              402653184: 8421890,
              671088640: 33282,
              939524096: 32768,
              1207959552: 8421888,
              1476395008: 512,
              1744830464: 8421378,
              2013265920: 2,
              2281701376: 8389120,
              2550136832: 33280,
              2818572288: 8421376,
              3087007744: 8389122,
              3355443200: 8388610,
              3623878656: 32770,
              3892314112: 514,
              4160749568: 8388608,
              1: 32768,
              268435457: 2,
              536870913: 8421888,
              805306369: 8388608,
              1073741825: 8421378,
              1342177281: 33280,
              1610612737: 512,
              1879048193: 8389122,
              2147483649: 8421890,
              2415919105: 8421376,
              2684354561: 8388610,
              2952790017: 33282,
              3221225473: 514,
              3489660929: 8389120,
              3758096385: 32770,
              4026531841: 0,
              134217729: 8421890,
              402653185: 8421376,
              671088641: 8388608,
              939524097: 512,
              1207959553: 32768,
              1476395009: 8388610,
              1744830465: 2,
              2013265921: 33282,
              2281701377: 32770,
              2550136833: 8389122,
              2818572289: 514,
              3087007745: 8421888,
              3355443201: 8389120,
              3623878657: 0,
              3892314113: 33280,
              4160749569: 8421378,
            },
            {
              0: 1074282512,
              16777216: 16384,
              33554432: 524288,
              50331648: 1074266128,
              67108864: 1073741840,
              83886080: 1074282496,
              100663296: 1073758208,
              117440512: 16,
              134217728: 540672,
              150994944: 1073758224,
              167772160: 1073741824,
              184549376: 540688,
              201326592: 524304,
              218103808: 0,
              234881024: 16400,
              251658240: 1074266112,
              8388608: 1073758208,
              25165824: 540688,
              41943040: 16,
              58720256: 1073758224,
              75497472: 1074282512,
              92274688: 1073741824,
              109051904: 524288,
              125829120: 1074266128,
              142606336: 524304,
              159383552: 0,
              176160768: 16384,
              192937984: 1074266112,
              209715200: 1073741840,
              226492416: 540672,
              243269632: 1074282496,
              260046848: 16400,
              268435456: 0,
              285212672: 1074266128,
              301989888: 1073758224,
              318767104: 1074282496,
              335544320: 1074266112,
              352321536: 16,
              369098752: 540688,
              385875968: 16384,
              402653184: 16400,
              419430400: 524288,
              436207616: 524304,
              452984832: 1073741840,
              469762048: 540672,
              486539264: 1073758208,
              503316480: 1073741824,
              520093696: 1074282512,
              276824064: 540688,
              293601280: 524288,
              310378496: 1074266112,
              327155712: 16384,
              343932928: 1073758208,
              360710144: 1074282512,
              377487360: 16,
              394264576: 1073741824,
              411041792: 1074282496,
              427819008: 1073741840,
              444596224: 1073758224,
              461373440: 524304,
              478150656: 0,
              494927872: 16400,
              511705088: 1074266128,
              528482304: 540672,
            },
            {
              0: 260,
              1048576: 0,
              2097152: 67109120,
              3145728: 65796,
              4194304: 65540,
              5242880: 67108868,
              6291456: 67174660,
              7340032: 67174400,
              8388608: 67108864,
              9437184: 67174656,
              10485760: 65792,
              11534336: 67174404,
              12582912: 67109124,
              13631488: 65536,
              14680064: 4,
              15728640: 256,
              524288: 67174656,
              1572864: 67174404,
              2621440: 0,
              3670016: 67109120,
              4718592: 67108868,
              5767168: 65536,
              6815744: 65540,
              7864320: 260,
              8912896: 4,
              9961472: 256,
              11010048: 67174400,
              12058624: 65796,
              13107200: 65792,
              14155776: 67109124,
              15204352: 67174660,
              16252928: 67108864,
              16777216: 67174656,
              17825792: 65540,
              18874368: 65536,
              19922944: 67109120,
              20971520: 256,
              22020096: 67174660,
              23068672: 67108868,
              24117248: 0,
              25165824: 67109124,
              26214400: 67108864,
              27262976: 4,
              28311552: 65792,
              29360128: 67174400,
              30408704: 260,
              31457280: 65796,
              32505856: 67174404,
              17301504: 67108864,
              18350080: 260,
              19398656: 67174656,
              20447232: 0,
              21495808: 65540,
              22544384: 67109120,
              23592960: 256,
              24641536: 67174404,
              25690112: 65536,
              26738688: 67174660,
              27787264: 65796,
              28835840: 67108868,
              29884416: 67109124,
              30932992: 67174400,
              31981568: 4,
              33030144: 65792,
            },
            {
              0: 2151682048,
              65536: 2147487808,
              131072: 4198464,
              196608: 2151677952,
              262144: 0,
              327680: 4198400,
              393216: 2147483712,
              458752: 4194368,
              524288: 2147483648,
              589824: 4194304,
              655360: 64,
              720896: 2147487744,
              786432: 2151678016,
              851968: 4160,
              917504: 4096,
              983040: 2151682112,
              32768: 2147487808,
              98304: 64,
              163840: 2151678016,
              229376: 2147487744,
              294912: 4198400,
              360448: 2151682112,
              425984: 0,
              491520: 2151677952,
              557056: 4096,
              622592: 2151682048,
              688128: 4194304,
              753664: 4160,
              819200: 2147483648,
              884736: 4194368,
              950272: 4198464,
              1015808: 2147483712,
              1048576: 4194368,
              1114112: 4198400,
              1179648: 2147483712,
              1245184: 0,
              1310720: 4160,
              1376256: 2151678016,
              1441792: 2151682048,
              1507328: 2147487808,
              1572864: 2151682112,
              1638400: 2147483648,
              1703936: 2151677952,
              1769472: 4198464,
              1835008: 2147487744,
              1900544: 4194304,
              1966080: 64,
              2031616: 4096,
              1081344: 2151677952,
              1146880: 2151682112,
              1212416: 0,
              1277952: 4198400,
              1343488: 4194368,
              1409024: 2147483648,
              1474560: 2147487808,
              1540096: 64,
              1605632: 2147483712,
              1671168: 4096,
              1736704: 2147487744,
              1802240: 2151678016,
              1867776: 4160,
              1933312: 2151682048,
              1998848: 4194304,
              2064384: 4198464,
            },
            {
              0: 128,
              4096: 17039360,
              8192: 262144,
              12288: 536870912,
              16384: 537133184,
              20480: 16777344,
              24576: 553648256,
              28672: 262272,
              32768: 16777216,
              36864: 537133056,
              40960: 536871040,
              45056: 553910400,
              49152: 553910272,
              53248: 0,
              57344: 17039488,
              61440: 553648128,
              2048: 17039488,
              6144: 553648256,
              10240: 128,
              14336: 17039360,
              18432: 262144,
              22528: 537133184,
              26624: 553910272,
              30720: 536870912,
              34816: 537133056,
              38912: 0,
              43008: 553910400,
              47104: 16777344,
              51200: 536871040,
              55296: 553648128,
              59392: 16777216,
              63488: 262272,
              65536: 262144,
              69632: 128,
              73728: 536870912,
              77824: 553648256,
              81920: 16777344,
              86016: 553910272,
              90112: 537133184,
              94208: 16777216,
              98304: 553910400,
              102400: 553648128,
              106496: 17039360,
              110592: 537133056,
              114688: 262272,
              118784: 536871040,
              122880: 0,
              126976: 17039488,
              67584: 553648256,
              71680: 16777216,
              75776: 17039360,
              79872: 537133184,
              83968: 536870912,
              88064: 17039488,
              92160: 128,
              96256: 553910272,
              100352: 262272,
              104448: 553910400,
              108544: 0,
              112640: 553648128,
              116736: 16777344,
              120832: 262144,
              124928: 537133056,
              129024: 536871040,
            },
            {
              0: 268435464,
              256: 8192,
              512: 270532608,
              768: 270540808,
              1024: 268443648,
              1280: 2097152,
              1536: 2097160,
              1792: 268435456,
              2048: 0,
              2304: 268443656,
              2560: 2105344,
              2816: 8,
              3072: 270532616,
              3328: 2105352,
              3584: 8200,
              3840: 270540800,
              128: 270532608,
              384: 270540808,
              640: 8,
              896: 2097152,
              1152: 2105352,
              1408: 268435464,
              1664: 268443648,
              1920: 8200,
              2176: 2097160,
              2432: 8192,
              2688: 268443656,
              2944: 270532616,
              3200: 0,
              3456: 270540800,
              3712: 2105344,
              3968: 268435456,
              4096: 268443648,
              4352: 270532616,
              4608: 270540808,
              4864: 8200,
              5120: 2097152,
              5376: 268435456,
              5632: 268435464,
              5888: 2105344,
              6144: 2105352,
              6400: 0,
              6656: 8,
              6912: 270532608,
              7168: 8192,
              7424: 268443656,
              7680: 270540800,
              7936: 2097160,
              4224: 8,
              4480: 2105344,
              4736: 2097152,
              4992: 268435464,
              5248: 268443648,
              5504: 8200,
              5760: 270540808,
              6016: 270532608,
              6272: 270540800,
              6528: 270532616,
              6784: 8192,
              7040: 2105352,
              7296: 2097160,
              7552: 0,
              7808: 268435456,
              8064: 268443656,
            },
            {
              0: 1048576,
              16: 33555457,
              32: 1024,
              48: 1049601,
              64: 34604033,
              80: 0,
              96: 1,
              112: 34603009,
              128: 33555456,
              144: 1048577,
              160: 33554433,
              176: 34604032,
              192: 34603008,
              208: 1025,
              224: 1049600,
              240: 33554432,
              8: 34603009,
              24: 0,
              40: 33555457,
              56: 34604032,
              72: 1048576,
              88: 33554433,
              104: 33554432,
              120: 1025,
              136: 1049601,
              152: 33555456,
              168: 34603008,
              184: 1048577,
              200: 1024,
              216: 34604033,
              232: 1,
              248: 1049600,
              256: 33554432,
              272: 1048576,
              288: 33555457,
              304: 34603009,
              320: 1048577,
              336: 33555456,
              352: 34604032,
              368: 1049601,
              384: 1025,
              400: 34604033,
              416: 1049600,
              432: 1,
              448: 0,
              464: 34603008,
              480: 33554433,
              496: 1024,
              264: 1049600,
              280: 33555457,
              296: 34603009,
              312: 1,
              328: 33554432,
              344: 1048576,
              360: 1025,
              376: 34604032,
              392: 33554433,
              408: 34603008,
              424: 0,
              440: 34604033,
              456: 1049601,
              472: 1024,
              488: 33555456,
              504: 1048577,
            },
            {
              0: 134219808,
              1: 131072,
              2: 134217728,
              3: 32,
              4: 131104,
              5: 134350880,
              6: 134350848,
              7: 2048,
              8: 134348800,
              9: 134219776,
              10: 133120,
              11: 134348832,
              12: 2080,
              13: 0,
              14: 134217760,
              15: 133152,
              2147483648: 2048,
              2147483649: 134350880,
              2147483650: 134219808,
              2147483651: 134217728,
              2147483652: 134348800,
              2147483653: 133120,
              2147483654: 133152,
              2147483655: 32,
              2147483656: 134217760,
              2147483657: 2080,
              2147483658: 131104,
              2147483659: 134350848,
              2147483660: 0,
              2147483661: 134348832,
              2147483662: 134219776,
              2147483663: 131072,
              16: 133152,
              17: 134350848,
              18: 32,
              19: 2048,
              20: 134219776,
              21: 134217760,
              22: 134348832,
              23: 131072,
              24: 0,
              25: 131104,
              26: 134348800,
              27: 134219808,
              28: 134350880,
              29: 133120,
              30: 2080,
              31: 134217728,
              2147483664: 131072,
              2147483665: 2048,
              2147483666: 134348832,
              2147483667: 133152,
              2147483668: 32,
              2147483669: 134348800,
              2147483670: 134217728,
              2147483671: 134219808,
              2147483672: 134350880,
              2147483673: 134217760,
              2147483674: 134219776,
              2147483675: 0,
              2147483676: 133120,
              2147483677: 2080,
              2147483678: 131104,
              2147483679: 134350848,
            },
          ]),
          (d = [
            4160749569, 528482304, 33030144, 2064384, 129024, 8064, 504,
            2147483679,
          ]),
          (a = _.DES =
            i.extend({
              _doReset: function () {
                for (var e = this._key.words, t = [], r = 0; r < 56; r++) {
                  var n = s[r] - 1;
                  t[r] = (e[n >>> 5] >>> (31 - (n % 32))) & 1;
                }
                for (var i = (this._subKeys = []), a = 0; a < 16; a++) {
                  for (var _ = (i[a] = []), o = h[a], r = 0; r < 24; r++)
                    (_[(r / 6) | 0] |=
                      t[(u[r] - 1 + o) % 28] << (31 - (r % 6))),
                      (_[4 + ((r / 6) | 0)] |=
                        t[28 + ((u[r + 24] - 1 + o) % 28)] << (31 - (r % 6)));
                  _[0] = (_[0] << 1) | (_[0] >>> 31);
                  for (r = 1; r < 7; r++) _[r] = _[r] >>> (4 * (r - 1) + 3);
                  _[7] = (_[7] << 5) | (_[7] >>> 27);
                }
                for (var c = (this._invSubKeys = []), r = 0; r < 16; r++)
                  c[r] = i[15 - r];
              },
              encryptBlock: function (e, t) {
                this._doCryptBlock(e, t, this._subKeys);
              },
              decryptBlock: function (e, t) {
                this._doCryptBlock(e, t, this._invSubKeys);
              },
              _doCryptBlock: function (e, t, r) {
                (this._lBlock = e[t]),
                  (this._rBlock = e[t + 1]),
                  l.call(this, 4, 252645135),
                  l.call(this, 16, 65535),
                  f.call(this, 2, 858993459),
                  f.call(this, 8, 16711935),
                  l.call(this, 1, 1431655765);
                for (var n = 0; n < 16; n++) {
                  for (
                    var i = r[n],
                      a = this._lBlock,
                      _ = this._rBlock,
                      o = 0,
                      c = 0;
                    c < 8;
                    c++
                  )
                    o |= p[c][((_ ^ i[c]) & d[c]) >>> 0];
                  (this._lBlock = _), (this._rBlock = a ^ o);
                }
                var s = this._lBlock;
                (this._lBlock = this._rBlock),
                  (this._rBlock = s),
                  l.call(this, 1, 1431655765),
                  f.call(this, 8, 16711935),
                  f.call(this, 2, 858993459),
                  l.call(this, 16, 65535),
                  l.call(this, 4, 252645135),
                  (e[t] = this._lBlock),
                  (e[t + 1] = this._rBlock);
              },
              keySize: 2,
              ivSize: 2,
              blockSize: 2,
            })),
          (r.DES = i._createHelper(a)),
          (_ = _.TripleDES =
            i.extend({
              _doReset: function () {
                var e = this._key.words;
                if (2 !== e.length && 4 !== e.length && e.length < 6)
                  throw new Error(
                    "Invalid key length - 3DES requires the key length to be 64, 128, 192 or >192."
                  );
                var t = e.slice(0, 2),
                  r = e.length < 4 ? e.slice(0, 2) : e.slice(2, 4),
                  e = e.length < 6 ? e.slice(0, 2) : e.slice(4, 6);
                (this._des1 = a.createEncryptor(n.create(t))),
                  (this._des2 = a.createEncryptor(n.create(r))),
                  (this._des3 = a.createEncryptor(n.create(e)));
              },
              encryptBlock: function (e, t) {
                this._des1.encryptBlock(e, t),
                  this._des2.decryptBlock(e, t),
                  this._des3.encryptBlock(e, t);
              },
              decryptBlock: function (e, t) {
                this._des3.decryptBlock(e, t),
                  this._des2.encryptBlock(e, t),
                  this._des1.decryptBlock(e, t);
              },
              keySize: 6,
              ivSize: 2,
              blockSize: 2,
            })),
          (r.TripleDES = i._createHelper(_)),
          e.TripleDES);
      },
      938: function (e, t, r) {
        var i, a, n;
        e.exports =
          ((e = r(249)),
          (n = (r = e).lib),
          (i = n.Base),
          (a = n.WordArray),
          ((n = r.x64 = {}).Word = i.extend({
            init: function (e, t) {
              (this.high = e), (this.low = t);
            },
          })),
          (n.WordArray = i.extend({
            init: function (e, t) {
              (e = this.words = e || []),
                (this.sigBytes = null != t ? t : 8 * e.length);
            },
            toX32: function () {
              for (
                var e = this.words, t = e.length, r = [], n = 0;
                n < t;
                n++
              ) {
                var i = e[n];
                r.push(i.high), r.push(i.low);
              }
              return a.create(r, this.sigBytes);
            },
            clone: function () {
              for (
                var e = i.clone.call(this),
                  t = (e.words = this.words.slice(0)),
                  r = t.length,
                  n = 0;
                n < r;
                n++
              )
                t[n] = t[n].clone();
              return e;
            },
          })),
          e);
      },
      480: () => {},
    },
    n = {};
  function I(e) {
    var t = n[e];
    if (void 0 !== t) return t.exports;
    t = n[e] = { exports: {} };
    return r[e].call(t.exports, t, t.exports, I), t.exports;
  }
  (I.n = (e) => {
    var t = e && e.__esModule ? () => e.default : () => e;
    return I.d(t, { a: t }), t;
  }),
    (I.d = (e, t) => {
      for (var r in t)
        I.o(t, r) &&
          !I.o(e, r) &&
          Object.defineProperty(e, r, { enumerable: !0, get: t[r] });
    }),
    (I.g = (function () {
      if ("object" == typeof globalThis) return globalThis;
      try {
        return this || new Function("return this")();
      } catch (e) {
        if ("object" == typeof window) return window;
      }
    })()),
    (I.o = (e, t) => Object.prototype.hasOwnProperty.call(e, t));
  (() => {
    "use strict";
    var e = I(354),
      e = I.n(e);
    const t = {};
    let n = parseInt("FF000000", 16),
      i = parseInt("FF0000", 16),
      a = parseInt("FF00", 16),
      o = parseInt("FF", 16);
    (t.hdr_len = 32),
      (t.iot_cmd = {
        IOT_LINK_CMD_DEV_NONCE_REQ: 0,
        IOT_LINK_CMD_DEV_NONCE_RES: 1,
        IOT_LINK_CMD_DEV_SESSION_REQ: 2,
        IOT_LINK_CMD_DEV_SESSION_RES: 3,
        IOT_LINK_CMD_DEV_LOGIN_REQ: 4,
        IOT_LINK_CMD_DEV_LOGIN_RES: 5,
        IOT_LINK_CMD_HOLE_REQ: 6,
        IOT_LINK_CMD_HOLE_S2D: 7,
        IOT_LINK_CMD_HOLE_D2S: 8,
        IOT_LINK_CMD_HOLE_S2D2: 9,
        IOT_LINK_CMD_HOLE_S2A: 10,
        IOT_LINK_CMD_HOLE_PUNCH: 11,
        IOT_LINK_CMD_TURN_REQ: 12,
        IOT_LINK_CMD_TURN_M2S: 13,
        IOT_LINK_CMD_TURN_S2D: 14,
        IOT_LINK_CMD_TURN_D2S: 15,
        IOT_LINK_CMD_TURN_S2A: 16,
        IOT_LINK_CMD_PING: 17,
        IOT_LINK_CMD_PONG: 18,
        IOT_LINK_CMD_DATA: 19,
        IOT_LINK_CMD_OPEN_REQ: 20,
        IOT_LINK_CMD_OPEN_RES: 21,
        IOT_LINK_CMD_CLOSE_REQ: 22,
        IOT_LINK_CMD_CLOSE_RES: 23,
        IOT_LINK_CMD_TURNTOPROXY_REG: 24,
        IOT_LINK_CMD_TURNTOPROXY_RES: 25,
        IOT_LINK_CMD_TURN_DEVICE_CONN_REG: 26,
        IOT_LINK_CMD_TURN_DEVICE_CONN_RES: 27,
        IOT_LINK_CMD_TURN_DEVICE_DISCONN_REG: 28,
        IOT_LINK_CMD_TURN_DEVICE_DISCONN_RES: 29,
        IOT_LINK_CMD_TURN_CLIENT_CONN_REG: 30,
        IOT_LINK_CMD_TURN_CLIENT_CONN_RES: 31,
        IOT_LINK_CMD_TURN_CLIENT_DISCONN_REG: 32,
        IOT_LINK_CMD_TURN_CLIENT_DISCONN_RES: 33,
        IOT_LINK_CMD_DEVICE_LOGINTURN_REQ: 34,
        IOT_LINK_CMD_DEVICE_LOGINTURN_RES: 35,
        IOT_LINK_CMD_CLIENT_LOGINTURN_REQ: 36,
        IOT_LINK_CMD_CLIENT_LOGINTURN_RES: 37,
        IOT_LINK_CMD_TURN_CLOSE: 38,
        IOT_LINK_CMD_ECHO_REQ: 39,
        IOT_LINK_CMD_ECHO_RES: 40,
        IOT_LINK_CMD_SID_P2S: 41,
        IOT_LINK_CMD_TURN_REQ2: 42,
        IOT_LINK_CMD_DATA_PRIOR: 43,
      }),
      (t.iot_hdr = function (e, t, r, n) {
        let i = 0;
        n && (i = n.length);
        var a = new ArrayBuffer(32 + i);
        let _ = new Uint8Array(a);
        for (let e = 0; e < 32; e++) _[e] = 0;
        (_[0] = parseInt("ab", 16)),
          (_[1] = parseInt("bc", 16)),
          (_[2] = parseInt("cd", 16)),
          (_[3] = parseInt("de", 16)),
          (_[4] = e),
          (_[5] = 0),
          (_[6] = 0),
          (_[7] = 0),
          (_[8] = 0),
          (_[9] = 0),
          (_[10] = 0),
          (_[11] = 1),
          (_[12] = t & o),
          (_[13] = (t >> 8) & o),
          (_[14] = (t >> 16) & o),
          (_[15] = (t >> 24) & o),
          (_[16] = r & o),
          (_[17] = (r >> 8) & o),
          (_[18] = (r >> 16) & o),
          (_[19] = (r >> 24) & o),
          (_[28] = i & o),
          (_[29] = (i >> 8) & o),
          (_[30] = (i >> 16) & o),
          (_[31] = (i >> 24) & o);
        for (let e = 0; e < i; e++) _[e + 32] = n[e];
        return _;
      }),
      (t.arq_open_conn = function (e) {
        var t = new ArrayBuffer(20);
        let r = new Uint8Array(t);
        var n = [
          "d9",
          "ff",
          "cc",
          "02",
          "8c",
          "38",
          "ee",
          "d2",
          "d1",
          "99",
          "ac",
          "60",
          "26",
          "94",
          "7f",
          "ae",
        ];
        for (let e = 0; e < 16; e++) r[e] = parseInt(n[e], 16);
        return (
          (r[16] = e & o),
          (r[17] = (e >> 8) & o),
          (r[18] = (e >> 16) & o),
          (r[19] = (e >> 24) & o),
          r
        );
      }),
      (t.arq_open_conn_res = function () {
        var e = new ArrayBuffer(16);
        let t = new Uint8Array(e);
        var r = [
          "96",
          "d5",
          "39",
          "0d",
          "12",
          "fc",
          "be",
          "8f",
          "47",
          "90",
          "d9",
          "32",
          "cc",
          "d8",
          "49",
          "f3",
        ];
        for (let e = 0; e < 16; e++) t[e] = parseInt(r[e], 16);
        return t;
      }),
      (t.arq_close_conn = function () {
        var e = new ArrayBuffer(16);
        let t = new Uint8Array(e);
        var r = [
          "2f",
          "f1",
          "f2",
          "73",
          "b2",
          "66",
          "21",
          "03",
          "cd",
          "23",
          "07",
          "52",
          "b9",
          "4a",
          "63",
          "e9",
        ];
        for (let e = 0; e < 16; e++) t[e] = parseInt(r[e], 16);
        return t;
      }),
      (t.iot_flow_stats = function () {
        var e = new ArrayBuffer(64);
        let t = new Uint8Array(e);
        for (let e = 0; e < 64; e++) t[e] = 0;
        return t;
      }),
      (t.iot_ping = function (t) {
        var e = new ArrayBuffer(96);
        let r = new Uint8Array(e);
        for (let e = 0; e < 96; e++) r[e] = 0;
        for (let e = 0; e < t.length; e++) r[e] = t.charCodeAt(e);
        return r;
      }),
      (t.iot_pong = function (e) {
        var t = new ArrayBuffer(68);
        let r = new Uint8Array(t);
        (r[0] = e & o),
          (r[1] = (e >> 8) & o),
          (r[2] = (e >> 16) & o),
          (r[3] = (e >> 24) & o);
        for (let e = 4; e < 68; e++) r[e] = 0;
        return r;
      }),
      (t.iot_turn_req = function (t, e, r) {
        var n = new ArrayBuffer(40);
        let i = new Uint8Array(n);
        for (let e = 0; e < 40; e++) i[e] = 0;
        for (let e = 0; e < t.length; e++) i[e] = t.charCodeAt(e);
        return (
          (i[32] = e & o),
          (i[33] = (e >> 8) & o),
          (i[34] = (e >> 16) & o),
          (i[35] = (e >> 24) & o),
          (i[36] = r & o),
          (i[37] = (r >> 8) & o),
          (i[38] = (r >> 16) & o),
          (i[39] = (r >> 24) & o),
          i
        );
      }),
      (t.iot_loginturn = function (e) {
        var t = new ArrayBuffer(4);
        let r = new Uint8Array(t);
        return (
          (r[0] = e & o),
          (r[1] = (e >> 8) & o),
          (r[2] = (e >> 16) & o),
          (r[3] = (e >> 24) & o),
          r
        );
      }),
      (t.iot_open_req = function (e, t) {
        var r = new ArrayBuffer(8);
        let n = new Uint8Array(r);
        return (
          (n[0] = e & o),
          (n[1] = (e >> 8) & o),
          (n[2] = (e >> 16) & o),
          (n[3] = (e >> 24) & o),
          (n[4] = t & o),
          (n[5] = (t >> 8) & o),
          (n[6] = (t >> 16) & o),
          (n[7] = (t >> 24) & o),
          n
        );
      }),
      (t.parse_iot_hdr = function (e) {
        let t = {};
        return (
          (t.magic =
            ((e[0] << 24) & n) |
            ((e[1] << 16) & i) |
            ((e[2] << 8) & a) |
            (e[3] & o)),
          (t.cmd =
            ((e[7] << 24) & n) |
            ((e[6] << 16) & i) |
            ((e[5] << 8) & a) |
            (e[4] & o)),
          (t.version =
            ((e[8] << 24) & n) |
            ((e[9] << 16) & i) |
            ((e[10] << 8) & a) |
            (e[11] & o)),
          (t.ticket =
            ((e[15] << 24) & n) |
            ((e[14] << 16) & i) |
            ((e[13] << 8) & a) |
            (e[12] & o)),
          (t.sid =
            ((e[19] << 24) & n) |
            ((e[18] << 16) & i) |
            ((e[17] << 8) & a) |
            (e[16] & o)),
          (t.transferlog =
            ((e[23] << 24) & n) |
            ((e[22] << 16) & i) |
            ((e[21] << 8) & a) |
            (e[20] & o)),
          (t.ecode =
            ((e[27] << 24) & n) |
            ((e[26] << 16) & i) |
            ((e[25] << 8) & a) |
            (e[24] & o)),
          (t.payload_len =
            ((e[31] << 24) & n) |
            ((e[30] << 16) & i) |
            ((e[29] << 8) & a) |
            (e[28] & o)),
          t
        );
      }),
      (t.parse_iot_turn_s2a = function (t) {
        let r = { uid: "" };
        r.sid =
          ((t[3] << 24) & n) |
          ((t[2] << 16) & i) |
          ((t[1] << 8) & a) |
          (t[0] & o);
        for (let e = 4; e < 32 && 0 != t[e]; e++)
          r.uid = r.uid + String.fromCharCode(t[e]);
        return (
          (r.turntype =
            ((t[39] << 24) & n) |
            ((t[38] << 16) & i) |
            ((t[37] << 8) & a) |
            (t[36] & o)),
          (r.turnsvr_ip =
            String(t[43]) +
            "." +
            String(t[42]) +
            "." +
            String(t[41]) +
            "." +
            String(t[40])),
          (r.turnsvr_ipv6 = ""),
          (r.turnsvr_port =
            ((t[63] << 24) & n) |
            ((t[62] << 16) & i) |
            ((t[61] << 8) & a) |
            (t[60] & o)),
          r
        );
      }),
      (t.parse_iot_login_res = function (e) {
        let t = {};
        return (
          (t.sid =
            ((e[3] << 24) & n) |
            ((e[2] << 16) & i) |
            ((e[1] << 8) & a) |
            (e[0] & o)),
          t
        );
      }),
      (t.parse_iot_open_res = function (e) {
        let t = {};
        return (
          (t.sid =
            ((e[3] << 24) & n) |
            ((e[2] << 16) & i) |
            ((e[1] << 8) & a) |
            (e[0] & o)),
          (t.linktype =
            ((e[7] << 24) & n) |
            ((e[6] << 16) & i) |
            ((e[5] << 8) & a) |
            (e[4] & o)),
          t
        );
      });
    const l = t,
      s = {};
    function _(e) {
      for (var t = 0; t < s.socklist.length; t++)
        if (s.socklist[t].key == e) return s.socklist[t];
      return null;
    }
    function f(e) {
      for (var t = 0; t < s.socklist.length; t++)
        if (s.socklist[t].sock == e) return s.socklist[t];
      return null;
    }
    var u = [
      parseInt("ce", 16),
      parseInt("fa", 16),
      parseInt("ef", 16),
      parseInt("fe", 16),
    ];
    (s.socklist = []),
      (s.onopen = null),
      (s.onclose = null),
      (s.onerror = null),
      (s.ondata = null);
    (s.arq_error_code = {
      ARQ_CONN_SUCCESS: 0,
      ARQ_CONN_FAIL: 1,
      ARQ_CONN_REMOTE_CLOSE: 2,
      ARQ_CONN_CLOSE: 3,
    }),
      (s.init = function (e, t, r, n) {
        (s.onopen = e), (s.onclose = t), (s.onerror = r), (s.ondata = n);
      }),
      (s.connect = function (_, e, t, o, r) {
        var r = (r ? "wss" : "ws") + "://" + e + ":" + t,
          c = {
            key: _,
            ip: e,
            port: t,
            sock: 0,
            timer: 0,
            ctx: o,
            connected: 0,
            firstdata: 0,
            req_timer: 0,
            time: 0,
          };
        (c.sock = new WebSocket(r)),
          c.sock.addEventListener("open", function (e) {
            c.sock.binaryType = "arraybuffer";
            var t = l.arq_open_conn(_);
            c.sock.send(t),
              (c.time = Date.parse(new Date())),
              (c.req_timer = setInterval(function () {
                var e = (Date.parse(new Date()) - c.time) / 1e3;
                10 <= e && c.close();
              }, 1e3));
          }),
          c.sock.addEventListener("close", function (e) {
            var t;
            0 < c.req_timer && (clearInterval(c.req_timer), (c.req_timer = 0)),
              null != s.onclose &&
                null != (t = f(e.target)) &&
                s.onclose(t.key, t.ctx, e.code, e.reason);
          }),
          c.sock.addEventListener("error", function (e) {}),
          c.sock.addEventListener("message", function (e) {
            var t = f(e.target);
            if (null != t) {
              var r = new Uint8Array(e.data),
                n = (new Int8Array(e.data).slice(32), 0);
              if (!(n < 4 && r[n] == u[n])) {
                for (
                  var i = l.arq_open_conn_res(), a = 1, n = 0;
                  n < i.length;
                  n++
                )
                  if (i[n] != r[n]) {
                    a = 0;
                    break;
                  }
                if ((0 == t.connected && t.connected, 0 == t.firstdata))
                  return (
                    0 < c.req_timer &&
                      (clearInterval(c.req_timer), (c.req_timer = 0)),
                    (t.firstdata = 1),
                    void (
                      null != s.onopen &&
                      (1 == a
                        ? s.onopen(_, o, s.arq_error_code.ARQ_CONN_SUCCESS)
                        : s.onopen(_, o, s.arq_error_code.ARQ_CONN_FAIL))
                    )
                  );
                null != s.ondata && s.ondata(_, o, r);
              }
            }
          }),
          s.socklist.push(c);
      }),
      (s.disconnect = function (e) {
        for (
          var t = _(e), r = (null != t && t.sock.close(), e), n = 0;
          n < s.socklist.length;
          n++
        )
          if (s.socklist[n].key == r) return void s.socklist.splice(n, 1);
      }),
      (s.send = function (e, t) {
        e = _(e);
        if (null == e) return 0;
        for (
          var r = new ArrayBuffer(8), n = new Uint8Array(r), i = 0;
          i < 4;
          i++
        )
          n[i] = u[i];
        return (
          (n[4] = t.length & parseInt("ff", 16)),
          (n[5] = (t.length >> 8) & parseInt("ff", 16)),
          (n[6] = (t.length >> 16) & parseInt("ff", 16)),
          (n[7] = (t.length >> 24) & parseInt("ff", 16)),
          e.sock.send(n),
          e.sock.send(t),
          1
        );
      });
    const h = s,
      p = {};
    parseInt("FF00000000000000", 16),
      parseInt("FF000000000000", 16),
      parseInt("FF0000000000", 16),
      parseInt("FF00000000", 16);
    var c = parseInt("FF000000", 16),
      d = parseInt("FF0000", 16),
      P = parseInt("FF00", 16),
      v = parseInt("FF", 16);
    (p.APP_PROTO_MAGIC = parseInt("4b503250", 16)),
      (p.APP_PROTO_VERSION = 1),
      (p.APP_PROTO_AES128_KEY = "~!JUAN*&Vision-="),
      (p.APP_PROTO_PARAM_AUTH_NAME_STRLEN = 32),
      (p.APP_PROTO_PARAM_AUTH_PASSWD_STRLEN = 32),
      (p.APP_PROTO_PARAM_AUTH_NAME_STRLEN2 = 1024),
      (p.APP_PROTO_PARAM_AUTH_PASSWD_STRLEN2 = 1024),
      (p.APP_PROTO_PARAM_NONCE_STRLEN = 64),
      (p.APP_PROTO_PARAM_AUTH_INFO_STRLEN = 64),
      (p.APP_PROTO_PARAM_SIGNATURE_STRLEN = 64),
      (p.APP_PROTO_PARAM_LIVE_CAM_DESC_STRLEN = 32),
      (p.APP_PROTO_PARAM_SETUP_STRLEN = 2048),
      (p.PROC_FRAME_MAGIC = parseInt("4652414d", 16)),
      (p.PROC_FRAME_MAGIC2 = parseInt("4652414E", 16)),
      (p.PROC_FRAME_VERSION = parseInt("01000000", 16)),
      (p.hdr_len = 24),
      (p.p2p_head_len = 48),
      (p.live_head_len = 8),
      (p.live_param_len = 24),
      (p.rec_search_rows = 100),
      (p.p2p_frame_type = { live: 0, replay: 1 }),
      (p.reply_cmd = {
        PROC_REPLAY_CMD_START: 3,
        PROC_REPLAY_CMD_PAUSE: 4,
        PROC_REPLAY_CMD_CONTINUE: 5,
        PROC_REPLAY_CMD_STOP: 2,
      }),
      (p.frame_head_type = {
        PROC_FRAME_HEAD_TYPE_LIVE: 0,
        PROC_FRAME_HEAD_TYPE_REPLAY: 1,
        PROC_FRAME_HEAD_TYPE_VOP2P: 2,
      }),
      (p.frame_type = {
        PROC_FRAME_TYPE_AUDIO: 0,
        PROC_FRAME_TYPE_IFRAME: 1,
        PROC_FRAME_TYPE_PFRAME: 2,
        PROC_FRAME_TYPE_OOB: 15,
      }),
      (p.api_cmd = {
        APP_PROTO_CMD_AUTH_REQ: 10,
        APP_PROTO_CMD_AUTH_RSP: 11,
        APP_PROTO_CMD_NONCE_REQ: 120,
        APP_PROTO_CMD_NONCE_RSP: 121,
        APP_PROTO_CMD_AUTH2_REQ: 130,
        APP_PROTO_CMD_AUTH2_RSP: 131,
        APP_PROTO_CMD_PTZ_REQ: 20,
        APP_PROTO_CMD_PTZ_RSP: 21,
        APP_PROTO_CMD_LIVE_REQ: 30,
        APP_PROTO_CMD_LIVE_RSP: 31,
        APP_PROTO_CMD_FIND_START_REQ: 90,
        APP_PROTO_CMD_FIND_START_RSP: 91,
        APP_PROTO_CMD_FIND_NEXT_REQ: 100,
        APP_PROTO_CMD_FIND_NEXT_RSP: 101,
        APP_PROTO_CMD_FIND_STOP_REQ: 110,
        APP_PROTO_CMD_FIND_STOP_RSP: 111,
        APP_PROTO_CMD_REPLAY_REQ: 40,
        APP_PROTO_CMD_REPLAY_RSP: 41,
        APP_PROTO_CMD_VCON_REQ: 50,
        APP_PROTO_CMD_VCON_RSP: 51,
        APP_PROTO_CMD_VOP2P_REQ: 60,
        APP_PROTO_CMD_VOP2P_RSP: 61,
        APP_PROTO_CMD_ALARM_REQ: 70,
        APP_PROTO_CMD_ALARM_RSP: 71,
        APP_PROTO_CMD_SETUP_REQ: 80,
        APP_PROTO_CMD_SETUP_REQ: 80,
        APP_PROTO_CMD_SETUP_RSP: 81,
        APP_PROTO_CMD_SETUP_RSP: 81,
        APP_PROTO_PARAM_LIVE_CMD_STOP: 1,
        APP_PROTO_PARAM_LIVE_CMD_START: 2,
        APP_PROTO_PARAM_LIVE_CMD_CHANGE_STREAM: 3,
        APP_PROTO_PARAM_REPLAY_CMD_SEARCH: 1,
        APP_PROTO_PARAM_REPLAY_CMD_STOP: 2,
        APP_PROTO_PARAM_REPLAY_CMD_START: 3,
        APP_PROTO_PARAM_REPLAY_CMD_PAUSE: 4,
        APP_PROTO_PARAM_REPLAY_CMD_CONTINUE: 5,
        APP_PROTO_DATA_FIND_FILE_START: 1,
        APP_PROTO_DATA_FIND_FILE_NEXT: 2,
        APP_PROTO_DATA_FIND_FILE_STOP: 3,
        APP_PROTO_PARAM_VCON_CMD_CREATE: 1,
        APP_PROTO_PARAM_VCON_CMD_DATA: 2,
        APP_PROTO_PARAM_VCON_CMD_DESTROY: 3,
        APP_PROTO_PARAM_VCON_APP_NAME_STRLEN: 32,
        APP_PROTO_PARAM_VOP2P_CMD_CALL: 1,
        APP_PROTO_PARAM_VOP2P_CMD_HANGUP: 2,
        APP_PROTO_CMD_SETUP2_REQ: 150,
        APP_PROTO_CMD_SETUP2_RSP: 151,
      }),
      (p.api_err_code = {
        APP_PROTO_SUCCESS: 0,
        APP_PROTO_AUTH_FAILED: -11,
        APP_PROTO_OPEN_STREAM_FAILED: -21,
        APP_PROTO_CLOSE_STREAM_FAILED: -22,
        APP_PROTO_VOP2P_CALL_FAILED: -31,
        APP_PROTO_VOP2P_HANGUP_FAILED: -32,
        APP_PROTO_PTZ_CONTROL_FAILED: -41,
        APP_PROTO_FIND_START_FAILED: -51,
        APP_PROTO_FIND_NEXT_FAILED: -52,
        APP_PROTO_FIND_STOP_FAILED: -53,
        APP_PROTO_REPLAY_SEARCH_FAILED: -61,
        APP_PROTO_REPLAY_STOP_FAILED: -71,
        APP_PROTO_REPLAY_START_FAILED: -72,
        APP_PROTO_REPLAY_PAUSE_FAILED: -73,
        APP_PROTO_REPLAY_RESUME_FAILED: -74,
        APP_PROTO_REMOTE_SETUP_FAILED: -81,
      }),
      (p.api_kp2p_code = {
        KP2P_ERR_SUCCESS: 0,
        KP2P_ERR_TIMEOUT: -2,
        KP2P_ERR_CLOSE_BY_SELF: -10,
        KP2P_ERR_CLOSE_BY_PEER: -11,
        KP2P_ERR_RESOLVE_FAILED: -12,
        KP2P_ERR_CONNECT_FAILED: -13,
        KP2P_ERR_SEND_FAILED: -14,
        KP2P_ERR_P2PSEVER_TIME_OUT: -15,
        KP2P_ERR_AUTH_FAILED: -20,
        KP2P_ERR_GET_NONCE_FAILED: -21,
        KP2P_ERR_AUTH2_FAILED: -22,
        KP2P_ERR_PTZ_CTRL_FAILED: -30,
        KP2P_ERR_OPEN_STREAM_FAILED: -40,
        KP2P_ERR_REC_SEARCH_FAILED: -50,
        KP2P_ERR_REC_PLAY_FAILED: -51,
        KP2P_ERR_VOP2P_CALL_FAILED: -60,
        KP2P_ERR_REMOTE_SETUP_FAILED: -70,
      }),
      (p.connect_type = {
        CONNECT_TYPE_NONE: 0,
        CONNECT_TYPE_IP_UDP: 1,
        CONNECT_TYPE_IP_TCP: 2,
        CONNECT_TYPE_HOLE: 3,
        CONNECT_TYPE_TURN_UDP: 4,
        CONNECT_TYPE_TURN_TCP: 5,
      }),
      (p.ptz_action = {
        KP2P_PTZ_CONTROL_ACTION_STOP: 0,
        KP2P_PTZ_CONTROL_ACTION_AUTO: 1,
        KP2P_PTZ_CONTROL_ACTION_UP: 2,
        KP2P_PTZ_CONTROL_ACTION_DOWN: 3,
        KP2P_PTZ_CONTROL_ACTION_LEFT: 4,
        KP2P_PTZ_CONTROL_ACTION_RIGHT: 5,
        KP2P_PTZ_CONTROL_ACTION_IRIS_OPEN: 6,
        KP2P_PTZ_CONTROL_ACTION_IRIS_CLOSE: 7,
        KP2P_PTZ_CONTROL_ACTION_ZOOM_IN: 8,
        KP2P_PTZ_CONTROL_ACTION_ZOOM_OUT: 9,
        KP2P_PTZ_CONTROL_ACTION_FOCUS_F: 10,
        KP2P_PTZ_CONTROL_ACTION_FOCUS_N: 11,
        KP2P_PTZ_CONTROL_ACTION_AUX: 12,
        KP2P_PTZ_CONTROL_ACTION_PRESET_SET: 13,
        KP2P_PTZ_CONTROL_ACTION_PRESET_GO: 14,
        KP2P_PTZ_CONTROL_ACTION_PRESET_CLEAR: 15,
      }),
      (p.api_hdr = function (e, t, r) {
        for (
          var n = 0,
            n = (r && (n = r.length), new ArrayBuffer(p.hdr_len + n)),
            i = new Uint8Array(n),
            a = 0;
          a < p.hdr_len;
          a++
        )
          i[a] = 0;
        (i[0] = p.APP_PROTO_MAGIC & v),
          (i[1] = (p.APP_PROTO_MAGIC >> 8) & v),
          (i[2] = (p.APP_PROTO_MAGIC >> 16) & v),
          (i[3] = (p.APP_PROTO_MAGIC >> 24) & v),
          (i[4] = p.APP_PROTO_VERSION & v),
          (i[5] = (p.APP_PROTO_VERSION >> 8) & v),
          (i[6] = (p.APP_PROTO_VERSION >> 16) & v),
          (i[7] = (p.APP_PROTO_VERSION >> 24) & v),
          (i[8] = t & v),
          (i[9] = (t >> 8) & v),
          (i[10] = (t >> 16) & v),
          (i[11] = (t >> 24) & v),
          (i[12] = e & v),
          (i[13] = (e >> 8) & v),
          (i[14] = (e >> 16) & v),
          (i[15] = (e >> 24) & v),
          (i[16] = 0),
          (i[17] = 0),
          (i[18] = 0),
          (i[19] = 0),
          (i[20] = r.length & v),
          (i[21] = (r.length >> 8) & v),
          (i[22] = (r.length >> 16) & v),
          (i[23] = (r.length >> 24) & v);
        for (a = 0; a < r.length; a++) i[p.hdr_len + a] = r[a];
        return i;
      }),
      (p.api_hdr_v2 = function (e, t, r) {
        for (
          var n = 0,
            n = (r && (n = r.length), new ArrayBuffer(p.hdr_len + n)),
            i = new Uint8Array(n),
            a = 0;
          a < p.hdr_len;
          a++
        )
          i[a] = 0;
        (i[0] = p.APP_PROTO_MAGIC & v),
          (i[1] = (p.APP_PROTO_MAGIC >> 8) & v),
          (i[2] = (p.APP_PROTO_MAGIC >> 16) & v),
          (i[3] = (p.APP_PROTO_MAGIC >> 24) & v),
          (i[4] = p.APP_PROTO_VERSION_V2 & v),
          (i[5] = (p.APP_PROTO_VERSION_V2 >> 8) & v),
          (i[6] = (p.APP_PROTO_VERSION_V2 >> 16) & v),
          (i[7] = (p.APP_PROTO_VERSION_V2 >> 24) & v),
          (i[8] = t & v),
          (i[9] = (t >> 8) & v),
          (i[10] = (t >> 16) & v),
          (i[11] = (t >> 24) & v),
          (i[12] = e & v),
          (i[13] = (e >> 8) & v),
          (i[14] = (e >> 16) & v),
          (i[15] = (e >> 24) & v),
          (i[16] = 0),
          (i[17] = 0),
          (i[18] = 0),
          (i[19] = 0),
          (i[20] = r.length & v),
          (i[21] = (r.length >> 8) & v),
          (i[22] = (r.length >> 16) & v),
          (i[23] = (r.length >> 24) & v);
        for (var a = 0; a < r.length; a++) i[p.hdr_len + a] = r[a];
        return i;
      }),
      (p.auth_req = function (e, t) {
        for (
          var r =
              p.APP_PROTO_PARAM_AUTH_NAME_STRLEN +
              p.APP_PROTO_PARAM_AUTH_PASSWD_STRLEN,
            n = new ArrayBuffer(r),
            i = new Uint8Array(n),
            a = 0;
          a < r;
          a++
        )
          i[a] = 0;
        for (a = 0; a < e.length; a += 2)
          i[a / 2] = parseInt(e.substr(a, 2), 16);
        for (a = 0; a < t.length; a += 2)
          i[p.APP_PROTO_PARAM_AUTH_NAME_STRLEN + a / 2] = parseInt(
            t.substr(a, 2),
            16
          );
        return i;
      }),
      (p.auth_req3 = function (e, t) {
        for (
          var r =
              p.APP_PROTO_PARAM_AUTH_NAME_STRLEN2 +
              p.APP_PROTO_PARAM_AUTH_PASSWD_STRLEN2,
            n = new ArrayBuffer(r),
            i = new Uint8Array(n),
            a = 0;
          a < r;
          a++
        )
          i[a] = 0;
        for (a = 0; a < e.length; a++) i[a] = e.charCodeAt(a);
        for (a = 0; a < t.length; a++)
          i[p.APP_PROTO_PARAM_AUTH_NAME_STRLEN2 + a] = t.charCodeAt(a);
        return i;
      }),
      (p.live_req = function (e, t, r) {
        for (
          var n = new ArrayBuffer(12), i = new Uint8Array(n), a = 0;
          a < 12;
          a++
        )
          i[a] = 0;
        return (
          (i[0] = e & v),
          (i[1] = (e >> 8) & v),
          (i[2] = (e >> 16) & v),
          (i[3] = (e >> 24) & v),
          (i[4] = t & v),
          (i[5] = (t >> 8) & v),
          (i[6] = (t >> 16) & v),
          (i[7] = (t >> 24) & v),
          (i[8] = r & v),
          (i[9] = (r >> 8) & v),
          (i[10] = (r >> 16) & v),
          (i[11] = (r >> 24) & v),
          i
        );
      }),
      (p.vop2p_call_req = function (e, t) {
        for (
          var r = new ArrayBuffer(8), n = new Uint8Array(r), i = 0;
          i < 8;
          i++
        )
          n[i] = 0;
        return (
          (n[0] = t & v),
          (n[1] = (t >> 8) & v),
          (n[2] = (t >> 16) & v),
          (n[3] = (t >> 24) & v),
          (n[4] = e & v),
          (n[5] = (e >> 8) & v),
          (n[6] = (e >> 16) & v),
          (n[7] = (e >> 24) & v),
          n
        );
      }),
      (p.vop2p_send_req = function (e, t, r, n, i, a, _, o, c) {
        for (
          var s = 64 + c, l = new ArrayBuffer(s), f = new Uint8Array(l), u = 0;
          u < s;
          u++
        )
          f[u] = 0;
        (f[0] = p.PROC_FRAME_MAGIC & v),
          (f[1] = (p.PROC_FRAME_MAGIC >> 8) & v),
          (f[2] = (p.PROC_FRAME_MAGIC >> 16) & v),
          (f[3] = (p.PROC_FRAME_MAGIC >> 24) & v),
          (f[4] = p.PROC_FRAME_VERSION & v),
          (f[5] = (p.PROC_FRAME_VERSION >> 8) & v),
          (f[6] = (p.PROC_FRAME_VERSION >> 16) & v),
          (f[7] = (p.PROC_FRAME_VERSION >> 24) & v),
          (f[8] = p.frame_head_type.PROC_FRAME_HEAD_TYPE_VOP2P & v),
          (f[9] = (p.frame_head_type.PROC_FRAME_HEAD_TYPE_VOP2P >> 8) & v),
          (f[10] = (p.frame_head_type.PROC_FRAME_HEAD_TYPE_VOP2P >> 16) & v),
          (f[11] = (p.frame_head_type.PROC_FRAME_HEAD_TYPE_VOP2P >> 24) & v),
          (f[12] = c & v),
          (f[13] = (c >> 8) & v),
          (f[14] = (c >> 16) & v),
          (f[15] = (c >> 24) & v),
          (f[16] = t & v),
          (f[17] = (t >> 8) & v),
          (f[18] = (t >> 16) & v),
          (f[19] = (t >> 24) & v),
          (f[20] = (t >> 32) & v),
          (f[21] = (t >> 40) & v),
          (f[22] = (t >> 48) & v),
          (f[23] = (t >> 56) & v),
          (f[24] = p.frame_type.PROC_FRAME_TYPE_AUDIO & v),
          (f[25] = (p.frame_type.PROC_FRAME_TYPE_AUDIO >> 8) & v),
          (f[26] = (p.frame_type.PROC_FRAME_TYPE_AUDIO >> 16) & v),
          (f[27] = (p.frame_type.PROC_FRAME_TYPE_AUDIO >> 24) & v),
          (f[28] = e & v),
          (f[29] = (e >> 8) & v),
          (f[30] = (e >> 16) & v),
          (f[31] = (e >> 24) & v);
        for (u = 0; u < r.length; u++) f[u + 32] = r.charCodeAt(u);
        (f[40] = n & v),
          (f[41] = (n >> 8) & v),
          (f[42] = (n >> 16) & v),
          (f[43] = (n >> 24) & v),
          (f[44] = i & v),
          (f[45] = (i >> 8) & v),
          (f[46] = (i >> 16) & v),
          (f[47] = (i >> 24) & v),
          (f[48] = a & v),
          (f[49] = (a >> 8) & v),
          (f[50] = (a >> 16) & v),
          (f[51] = (a >> 24) & v),
          (f[52] = _ & v),
          (f[53] = (_ >> 8) & v),
          (f[54] = (_ >> 16) & v),
          (f[55] = (_ >> 24) & v);
        for (u = 0; u < c; u++) f[u + 64] = o[u];
        return f;
      }),
      (p.time_struct = function (e) {
        var t = new ArrayBuffer(24),
          t = new Uint8Array(t),
          r = e.getFullYear(),
          n = e.getMonth() + 1,
          i = e.getDate(),
          a = e.getHours(),
          _ = e.getMinutes(),
          e = e.getSeconds();
        return (
          (t[0] = r & v),
          (t[1] = (r >> 8) & v),
          (t[2] = (r >> 16) & v),
          (t[3] = (r >> 24) & v),
          (t[4] = n & v),
          (t[5] = (n >> 8) & v),
          (t[6] = (n >> 16) & v),
          (t[7] = (n >> 24) & v),
          (t[8] = i & v),
          (t[9] = (i >> 8) & v),
          (t[10] = (i >> 16) & v),
          (t[11] = (i >> 24) & v),
          (t[12] = a & v),
          (t[13] = (a >> 8) & v),
          (t[14] = (a >> 16) & v),
          (t[15] = (a >> 24) & v),
          (t[16] = _ & v),
          (t[17] = (_ >> 8) & v),
          (t[18] = (_ >> 16) & v),
          (t[19] = (_ >> 24) & v),
          (t[20] = e & v),
          (t[21] = (e >> 8) & v),
          (t[22] = (e >> 16) & v),
          (t[23] = (e >> 24) & v),
          t
        );
      }),
      (p.find_file_cond = function (e, t, r, n) {
        var i = new ArrayBuffer(56),
          a = new Uint8Array(i),
          _ = p.time_struct(r),
          o = p.time_struct(n);
        (a[0] = e & v),
          (a[1] = (e >> 8) & v),
          (a[2] = (e >> 16) & v),
          (a[3] = (e >> 24) & v),
          (a[4] = t & v),
          (a[5] = (t >> 8) & v),
          (a[6] = (t >> 16) & v),
          (a[7] = (t >> 24) & v);
        for (var c = 0; c < _.length; c++) a[c + 8] = _[c];
        for (c = 0; c < o.length; c++) a[c + 32] = o[c];
        return a;
      }),
      (p.find_next_req = function (e) {
        var t = new ArrayBuffer(4),
          t = new Uint8Array(t);
        return (
          (t[0] = e & v),
          (t[1] = (e >> 8) & v),
          (t[2] = (e >> 16) & v),
          (t[3] = (e >> 24) & v),
          t
        );
      }),
      (p.find_stop_req = function (e) {
        var t = new ArrayBuffer(4),
          t = new Uint8Array(t);
        return (
          (t[0] = e & v),
          (t[1] = (e >> 8) & v),
          (t[2] = (e >> 16) & v),
          (t[3] = (e >> 24) & v),
          t
        );
      }),
      (p.find_file_req_2 = function (e, t, r, n, i, a, _, o) {
        for (
          var c = new ArrayBuffer(52), s = new Uint8Array(c), l = 0;
          l < s.length;
          l++
        )
          s[l] = 0;
        if (
          ((s[0] = e & v),
          (s[1] = (e >> 8) & v),
          (s[2] = (e >> 16) & v),
          (s[3] = (e >> 24) & v),
          (s[4] = r & v),
          (s[5] = (r >> 8) & v),
          (s[6] = (r >> 16) & v),
          (s[7] = (r >> 24) & v),
          null != t)
        )
          for (l = 0; l < t.length; l++)
            0 < t[l] &&
              (s[8 + parseInt(l / 8)] = s[8 + parseInt(l / 8)] | (1 << l % 8));
        return (
          (s[24] = n & v),
          (s[25] = (n >> 8) & v),
          (s[26] = (n >> 16) & v),
          (s[27] = (n >> 24) & v),
          (s[32] = i & v),
          (s[33] = (i >> 8) & v),
          (s[34] = (i >> 16) & v),
          (s[35] = (i >> 24) & v),
          (s[36] = a & v),
          (s[37] = (a >> 8) & v),
          (s[38] = (a >> 16) & v),
          (s[39] = (a >> 24) & v),
          (s[44] = _ & v),
          (s[45] = (_ >> 8) & v),
          (s[46] = (_ >> 16) & v),
          (s[47] = (_ >> 24) & v),
          (s[48] = o & v),
          (s[49] = (o >> 8) & v),
          (s[50] = (o >> 16) & v),
          (s[51] = (o >> 24) & v),
          s
        );
      }),
      (p.ptz_req = function (e, t, r, n) {
        var i = new ArrayBuffer(16),
          i = new Uint8Array(i);
        return (
          (i[0] = e & v),
          (i[1] = (e >> 8) & v),
          (i[2] = (e >> 16) & v),
          (i[3] = (e >> 24) & v),
          (i[4] = t & v),
          (i[5] = (t >> 8) & v),
          (i[6] = (t >> 16) & v),
          (i[7] = (t >> 24) & v),
          (i[8] = r & v),
          (i[9] = (r >> 8) & v),
          (i[10] = (r >> 16) & v),
          (i[11] = (r >> 24) & v),
          (i[12] = n & v),
          (i[13] = (n >> 8) & v),
          (i[14] = (n >> 16) & v),
          (i[15] = (n >> 24) & v),
          i
        );
      }),
      (p.parse_ptz_req = function (e) {
        var t = { len: 4 };
        return (
          (t.result =
            ((e[3] << 24) & c) |
            ((e[2] << 16) & d) |
            ((e[1] << 8) & P) |
            (e[0] & v)),
          t
        );
      }),
      (p.parse_search_res = function (e) {
        var t = { len: 52 };
        return (
          (t.replay_cmd =
            ((e[3] << 24) & c) |
            ((e[2] << 16) & d) |
            ((e[1] << 8) & P) |
            (e[0] & v)),
          (t.search_type =
            ((e[23] << 24) & c) |
            ((e[22] << 16) & d) |
            ((e[21] << 8) & P) |
            (e[20] & v)),
          (t.begin_time =
            ((e[31] << 24) & c) |
            ((e[30] << 16) & d) |
            ((e[29] << 8) & P) |
            (e[28] & v)),
          (t.end_time =
            ((e[35] << 24) & c) |
            ((e[34] << 16) & d) |
            ((e[33] << 8) & P) |
            (e[32] & v)),
          (t.file_index =
            ((e[43] << 24) & c) |
            ((e[42] << 16) & d) |
            ((e[41] << 8) & P) |
            (e[40] & v)),
          (t.file_count =
            ((e[47] << 24) & c) |
            ((e[46] << 16) & d) |
            ((e[45] << 8) & P) |
            (e[44] & v)),
          (t.file_total =
            ((e[51] << 24) & c) |
            ((e[50] << 16) & d) |
            ((e[49] << 8) & P) |
            (e[48] & v)),
          t
        );
      }),
      (p.parse_record_file = function (e) {
        var t = { len: 20 };
        return (
          (t.channel =
            ((e[3] << 24) & c) |
            ((e[2] << 16) & d) |
            ((e[1] << 8) & P) |
            (e[0] & v)),
          (t.file_type =
            ((e[7] << 24) & c) |
            ((e[6] << 16) & d) |
            ((e[5] << 8) & P) |
            (e[4] & v)),
          (t.file_begintime =
            ((e[11] << 24) & c) |
            ((e[10] << 16) & d) |
            ((e[9] << 8) & P) |
            (e[8] & v)),
          (t.file_endtime =
            ((e[15] << 24) & c) |
            ((e[14] << 16) & d) |
            ((e[13] << 8) & P) |
            (e[12] & v)),
          (t.file_quality =
            ((e[19] << 24) & c) |
            ((e[18] << 16) & d) |
            ((e[17] << 8) & P) |
            (e[16] & v)),
          t
        );
      }),
      (p.get_api_magic = function (e) {
        return (
          ((e[3] << 24) & c) |
          ((e[2] << 16) & d) |
          ((e[1] << 8) & P) |
          (e[0] & v)
        );
      }),
      (p.parse_api_hdr = function (e) {
        var t = {};
        return (
          (t.magic =
            ((e[3] << 24) & c) |
            ((e[2] << 16) & d) |
            ((e[1] << 8) & P) |
            (e[0] & v)),
          (t.version =
            ((e[7] << 24) & c) |
            ((e[6] << 16) & d) |
            ((e[5] << 8) & P) |
            (e[4] & v)),
          (t.ticket =
            ((e[11] << 24) & c) |
            ((e[10] << 16) & d) |
            ((e[9] << 8) & P) |
            (e[8] & v)),
          (t.cmd =
            ((e[15] << 24) & c) |
            ((e[14] << 16) & d) |
            ((e[13] << 8) & P) |
            (e[12] & v)),
          (t.result =
            ((e[19] << 24) & c) |
            ((e[18] << 16) & d) |
            ((e[17] << 8) & P) |
            (e[16] & v)),
          (t.size =
            ((e[23] << 24) & c) |
            ((e[22] << 16) & d) |
            ((e[21] << 8) & P) |
            (e[20] & v)),
          t
        );
      }),
      (p.parse_auth_res = function (e) {
        var t = {};
        return (
          (t.reserve =
            ((e[3] << 24) & c) |
            ((e[2] << 16) & d) |
            ((e[1] << 8) & P) |
            (e[0] & v)),
          t
        );
      }),
      (p.parse_auth3_res = function (e) {
        return e;
      }),
      (p.parse_live_res = function (e) {
        var t = { cam_desc: "" };
        (t.channel =
          ((e[3] << 24) & c) |
          ((e[2] << 16) & d) |
          ((e[1] << 8) & P) |
          (e[0] & v)),
          (t.streamid =
            ((e[7] << 24) & c) |
            ((e[6] << 16) & d) |
            ((e[5] << 8) & P) |
            (e[4] & v)),
          (t.live_cmd =
            ((e[11] << 24) & c) |
            ((e[10] << 16) & d) |
            ((e[9] << 8) & P) |
            (e[8] & v));
        for (
          var r = 12;
          r < p.APP_PROTO_PARAM_LIVE_CAM_DESC_STRLEN && 0 != e[r];
          r++
        )
          t.cam_desc = t.cam_desc + String.fromCharCode(e[r]);
        return t;
      }),
      (p.parse_p2p_frame_head = function (e) {
        var t = {};
        function r(e, t) {
          for (; t > e.length; ) e = "0" + e;
          return e;
        }
        (t.magic =
          ((e[3] << 24) & c) |
          ((e[2] << 16) & d) |
          ((e[1] << 8) & P) |
          (e[0] & v)),
          (t.version =
            ((e[7] << 24) & c) |
            ((e[6] << 16) & d) |
            ((e[5] << 8) & P) |
            (e[4] & v)),
          (t.headtype =
            ((e[11] << 24) & c) |
            ((e[10] << 16) & d) |
            ((e[9] << 8) & P) |
            (e[8] & v)),
          (t.framesize =
            ((e[15] << 24) & c) |
            ((e[14] << 16) & d) |
            ((e[13] << 8) & P) |
            (e[12] & v)),
          (t.len = 24);
        e =
          r(e[23].toString(2), 8) +
          r(e[22].toString(2), 8) +
          r(e[21].toString(2), 8) +
          r(e[20].toString(2), 8) +
          r(e[19].toString(2), 8) +
          r(e[18].toString(2), 8) +
          r(e[17].toString(2), 8) +
          r(e[16].toString(2), 8);
        return (t.ts_ms = parseInt(e, 2)), t;
      }),
      (p.parse_p2p_frame_head_2 = function (e) {
        var t = {};
        return (
          (t.margic =
            ((e[3] << 24) & c) |
            ((e[2] << 16) & d) |
            ((e[1] << 8) & P) |
            (e[0] & v)),
          (t.frame_seq =
            ((e[7] << 24) & c) |
            ((e[6] << 16) & d) |
            ((e[5] << 8) & P) |
            (e[4] & v)),
          (t.len = 40),
          t
        );
      }),
      (p.parse_live_head = function (e) {
        var t = {};
        return (
          (t.frametype =
            ((e[3] << 24) & c) |
            ((e[2] << 16) & d) |
            ((e[1] << 8) & P) |
            (e[0] & v)),
          (t.channel =
            ((e[7] << 24) & c) |
            ((e[6] << 16) & d) |
            ((e[5] << 8) & P) |
            (e[4] & v)),
          (t.len = 8),
          t
        );
      }),
      (p.parse_oob = function (e) {
        var t = {},
          e = e.subarray(40);
        return (
          (t.centerX =
            ((e[3] << 24) & c) |
            ((e[2] << 16) & d) |
            ((e[1] << 8) & P) |
            (e[0] & v)),
          (t.centerY =
            ((e[7] << 24) & c) |
            ((e[6] << 16) & d) |
            ((e[5] << 8) & P) |
            (e[4] & v)),
          (t.radius =
            ((e[11] << 24) & c) |
            ((e[10] << 16) & d) |
            ((e[9] << 8) & P) |
            (e[8] & v)),
          (t.angleX =
            ((e[15] << 24) & c) |
            ((e[14] << 16) & d) |
            ((e[13] << 8) & P) |
            (e[12] & v)),
          (t.angleY =
            ((e[19] << 24) & c) |
            ((e[18] << 16) & d) |
            ((e[17] << 8) & P) |
            (e[16] & v)),
          (t.angleZ =
            ((e[23] << 24) & c) |
            ((e[22] << 16) & d) |
            ((e[21] << 8) & P) |
            (e[20] & v)),
          t
        );
      }),
      (p.parse_video_param = function (e) {
        for (var t = { enc: "" }, r = 0; r < 8 && 0 != e[r]; r++)
          t.enc = t.enc + String.fromCharCode(e[r]);
        return (
          (t.fps =
            ((e[11] << 24) & c) |
            ((e[10] << 16) & d) |
            ((e[9] << 8) & P) |
            (e[8] & v)),
          (t.width =
            ((e[15] << 24) & c) |
            ((e[14] << 16) & d) |
            ((e[13] << 8) & P) |
            (e[12] & v)),
          (t.height =
            ((e[19] << 24) & c) |
            ((e[18] << 16) & d) |
            ((e[17] << 8) & P) |
            (e[16] & v)),
          (t.reserv =
            ((e[23] << 24) & c) |
            ((e[22] << 16) & d) |
            ((e[21] << 8) & P) |
            (e[20] & v)),
          ("H265" !== t.enc && "H264" !== t.enc) || (t.len = 24),
          t
        );
      }),
      (p.parse_audio_param = function (e) {
        for (var t = { enc: "" }, r = 0; r < 8 && 0 != e[r]; r++)
          t.enc = t.enc + String.fromCharCode(e[r]);
        return (
          (t.samplerate =
            ((e[11] << 24) & c) |
            ((e[10] << 16) & d) |
            ((e[9] << 8) & P) |
            (e[8] & v)),
          (t.samplewidth =
            ((e[15] << 24) & c) |
            ((e[14] << 16) & d) |
            ((e[13] << 8) & P) |
            (e[12] & v)),
          (t.channels =
            ((e[19] << 24) & c) |
            ((e[18] << 16) & d) |
            ((e[17] << 8) & P) |
            (e[16] & v)),
          (t.cpmpress =
            ((e[23] << 24) & c) |
            ((e[22] << 16) & d) |
            ((e[21] << 8) & P) |
            (e[20] & v)),
          (t.len = 32),
          t
        );
      }),
      (p.parse_replay_head = function (e) {
        var t = {};
        return (
          (t.frametype =
            ((e[3] << 24) & c) |
            ((e[2] << 16) & d) |
            ((e[1] << 8) & P) |
            (e[0] & v)),
          (t.channel =
            ((e[7] << 24) & c) |
            ((e[6] << 16) & d) |
            ((e[5] << 8) & P) |
            (e[4] & v)),
          (t.type =
            ((e[11] << 24) & c) |
            ((e[10] << 16) & d) |
            ((e[9] << 8) & P) |
            (e[8] & v)),
          (t.quality =
            ((e[15] << 24) & c) |
            ((e[14] << 16) & d) |
            ((e[13] << 8) & P) |
            (e[12] & v)),
          (t.len = 16),
          t
        );
      }),
      (p.setup_req = function (e) {
        var t = new ArrayBuffer(2052),
          r = new Uint8Array(t);
        if (
          ((r[0] = e.length & v),
          (r[1] = (e.length >> 8) & v),
          (r[2] = (e.length >> 16) & v),
          (r[3] = (e.length >> 24) & v),
          2048 <= e.length)
        )
          return r;
        for (var n = 0; n < e.length; n++) r[n + 4] = e.charCodeAt(n);
        return r;
      }),
      (p.setup_req2 = function (e) {
        var t = new ArrayBuffer(36),
          t = new Uint8Array(t);
        return (
          (t[32] = e.length & v),
          (t[33] = (e.length >> 8) & v),
          (t[34] = (e.length >> 16) & v),
          (t[35] = (e.length >> 24) & v),
          t
        );
      }),
      (p.parse_setup = function (e) {
        var t = {};
        return (
          (t.data_size =
            ((e[3] << 24) & c) |
            ((e[2] << 16) & d) |
            ((e[1] << 8) & P) |
            (e[0] & v)),
          (t.len = 4),
          t
        );
      }),
      (p.parse_setup2 = function (e) {
        var t = { len: 36 };
        return (
          (t.data_size =
            ((e[35] << 24) & c) |
            ((e[34] << 16) & d) |
            ((e[33] << 8) & P) |
            (e[32] & v)),
          t
        );
      }),
      (p.parse_p2p_head = function (e) {});
    const E = p,
      R = {};
    function T(e) {
      for (var t = 0; t < O.length; t++)
        if (O[t].p2p_key == e || O[t].turn_key == e || O[t].iptcp_key == e)
          return O[t];
    }
    function A(e, t) {
      var r = l.iot_open_req(e.sid, e.turntype),
        e = l.iot_hdr(l.iot_cmd.IOT_LINK_CMD_OPEN_REQ, 0, e.sid, r);
      h.send(t, e);
    }
    function m(e, t, r) {
      null != R.ondata && R.ondata(e, r, e.ctx);
    }
    var O = [];
    (R.onconnect = null),
      (R.onclose = null),
      (R.ondata = null),
      (R.onerror = null),
      (R.iot_linktype = { turntcp: 1, iptcp: 2, p2ptcp: 3 }),
      (R.setAddressUrl = function (e) {
        0;
      });
    (h.onopen = function (e, t, r) {
      var n,
        i,
        a,
        e = T(e);
      null != e &&
        (e.linktype == R.iot_linktype.iptcp
          ? A(e, e.iptcp_key)
          : e.linktype == R.iot_linktype.turntcp
          ? ((i = e),
            (a = l.iot_loginturn(i.sid)),
            (a = l.iot_hdr(
              l.iot_cmd.IOT_LINK_CMD_CLIENT_LOGINTURN_REQ,
              0,
              i.sid,
              a
            )),
            h.send(i.turn_key, a))
          : e.linktype == R.iot_linktype.p2ptcp &&
            ((n = e),
            (i = l.iot_turn_req(n.uid, n.turntype, n.chancount)),
            (i = l.iot_hdr(l.iot_cmd.IOT_LINK_CMD_TURN_REQ, 0, n.sid, i)),
            h.send(n.p2p_key, i),
            (n.turn_timestamp = Date.parse(new Date())),
            (n.turn_timer = setInterval(function () {
              var e = (Date.parse(new Date()) - n.turn_timestamp) / 1e3;
              20 <= e &&
                (clearInterval(n.turn_timer), R.onconnect(n, n.ctx, -15));
            }, 2e3)),
            (e.linktype = R.iot_linktype.turntcp)));
    }),
      (h.onerror = function (e, t, r) {
        e = T(e);
        null != e && null != R.onerror && R.onerror(e, e.ctx, r);
      }),
      (h.ondata = function (e, t, r) {
        var n,
          e = T(e);
        if (null != e) {
          var i = l.parse_iot_hdr(r);
          if (i.cmd == l.iot_cmd.IOT_LINK_CMD_TURN_S2A) {
            var a = r.slice(l.hdr_len),
              a = l.parse_iot_turn_s2a(a);
            (a = a),
              ((n = e).turn_ip = a.turnsvr_ip),
              (n.turn_port = a.turnsvr_port),
              (n.turn_timestamp = Date.parse(new Date())),
              n.usehttps &&
                ((n.turn_ip =
                  n.turn_ip.replace(/\./g, "-") + ".kp2p.dvr163.com"),
                (n.turn_port = 2e4)),
              h.connect(n.turn_key, n.turn_ip, n.turn_port, n.ctx, n.usehttps),
              h.disconnect(n.p2p_key),
              (n.p2p_key = 0);
          } else if (i.cmd != l.iot_cmd.IOT_LINK_CMD_PONG)
            if (i.cmd == l.iot_cmd.IOT_LINK_CMD_OPEN_RES) {
              0 < e.turn_timer && clearInterval(e.turn_timer);
              a = r.slice(l.hdr_len);
              l.parse_iot_open_res(a);
              (n = e),
                0 == (o = i.ecode) &&
                  (null != R.onconnect &&
                    ((n.link_isok = 1), R.onconnect(n, n.ctx, o)),
                  (n.live_timer = setInterval(function () {
                    for (var e = 0; e < O.length; e++) {
                      var t,
                        r,
                        n = O[e];
                      n.linktype == R.iot_linktype.iptcp &&
                        ((t = l.iot_ping(n.iptcp_key)),
                        (r = l.iot_hdr(
                          l.iot_cmd.IOT_LINK_CMD_PING,
                          0,
                          n.sid,
                          t
                        )),
                        h.send(n.iptcp_key, r)),
                        n.linktype == R.iot_linktype.turntcp &&
                          ((t = l.iot_ping(n.uid)),
                          (r = l.iot_hdr(
                            l.iot_cmd.IOT_LINK_CMD_PING,
                            0,
                            n.sid,
                            t
                          )),
                          h.send(n.turn_key, r));
                    }
                  }, 1e4)));
            } else if (i.cmd != l.iot_cmd.IOT_LINK_CMD_CLOSE_RES)
              if (i.cmd == l.iot_cmd.IOT_LINK_CMD_DATA) {
                var _ = r.slice(l.hdr_len),
                  o = E.get_api_magic(_);
                if (o == E.PROC_FRAME_MAGIC || o == E.PROC_FRAME_MAGIC2) {
                  var c = _.slice(0),
                    s =
                      (o == E.PROC_FRAME_MAGIC2 &&
                        ((s = E.parse_p2p_frame_head_2(c)),
                        (c = c.subarray(s.len))),
                      E.parse_p2p_frame_head(c));
                  if (s.framesize > c.length)
                    return (
                      (e.trunk_buf = c.slice(0)),
                      void (e.trunk_size = s.framesize)
                    );
                } else if (0 < e.trunk_size) {
                  var c = new Uint8Array(e.trunk_buf.length + _.length);
                  if (
                    (c.set(e.trunk_buf, 0),
                    c.set(_, e.trunk_buf.length),
                    !(e.trunk_size <= c.length))
                  )
                    return void (e.trunk_buf = c.slice(0));
                  (e.trunk_size = 0), m(e, 0, c), (e.trunk_buf = null);
                }
                m(e, 0, _);
              } else
                i.cmd == l.iot_cmd.IOT_LINK_CMD_DATA_PRIOR
                  ? ((_ = r.slice(l.hdr_len)), m(e, 0, _))
                  : i.cmd == l.iot_cmd.IOT_LINK_CMD_CLIENT_LOGINTURN_RES &&
                    ((s = r.slice(l.hdr_len)),
                    l.parse_iot_login_res(s),
                    A((c = e), c.turn_key));
        }
      }),
      (h.onclose = function (e, t, r) {
        var n = T(e);
        if (null != n) {
          if (
            (null != R.onclose &&
              e != n.p2p_key &&
              1 == n.link_isok &&
              R.onclose(n, n.ctx, r),
            null != R.onconnect &&
              e != n.p2p_key &&
              0 == n.link_isok &&
              R.onconnect(n, n.ctx, -13),
            e != n.p2p_key)
          ) {
            0 < n.turn_timer && clearInterval(n.turn_timer),
              0 < n.live_timer && clearInterval(n.live_timer);
            for (var i = e, a = 0; a < O.length; a++)
              if (
                O[a].p2p_key == i ||
                O[a].turn_key == i ||
                O[a].iptcp_key == i
              ) {
                O.splice(a, 1);
                break;
              }
          }
        } else null != R.onclose && R.onclose(0, 0, r);
      }),
      (R.init = function (e, t, r, n) {
        (R.onconnect = e), (R.onclose = t), (R.onerror = r), (R.ondata = n);
      }),
      (R.connect = function (e, t, r, n, i, a, _) {
        var o,
          c,
          s = {
            uid: e,
            iptcp_ip: r,
            iptcp_port: n,
            ctx: a,
            linktype: 0,
            chancount: t,
            turntype: i,
            iptcp_key: 0,
            turn_key: 0,
            p2p_key: 0,
            link_isok: 0,
            turn_timer: -1,
            turn_timestamp: 0,
            trunk_size: 0,
            trunk_buf: null,
            usehttps: _,
          };
        if ("" != r) {
          for (s.linktype = R.iot_linktype.iptcp; 0 == s.iptcp_key; )
            s.iptcp_key = Math.round(1e4 * Math.random());
          (s.sid = s.iptcp_key), h.connect(s.iptcp_key, r, n, a, "ws");
        } else {
          if ("" == e) return null;
          (s.linktype = R.iot_linktype.p2ptcp),
            (o = s),
            ((c = new XMLHttpRequest()).onreadystatechange = function () {
              var e;
              4 == c.readyState && 200 == c.status
                ? ((e = JSON.parse(c.responseText)),
                  (o.p2p_ip = e.ipv4),
                  (o.p2p_port = parseInt(e.tcpport)),
                  (o.p2p_key = parseInt(e.apconv)),
                  (o.turn_key = parseInt(e.amconv)),
                  (o.sid = parseInt(e.sid)),
                  o.usehttps &&
                    ((o.p2p_ip =
                      o.p2p_ip.replace(/\./g, "-") + ".kp2p.dvr163.com"),
                    (o.p2p_port = 19001)),
                  h.connect(o.p2p_key, o.p2p_ip, o.p2p_port, o.ctx, o.usehttps))
                : 4 == c.readyState &&
                  200 != c.status &&
                  R.onconnect(o, o.ctx, -12);
            }),
            (t = "http://"),
            o.usehttps && (t = "https://"),
            c.open(
              "GET",
              t +
                "ngw.dvr163.com/address/client?id=" +
                o.uid +
                "&ch_count=" +
                o.chancount +
                "&r=" +
                Math.round(1e7 * Math.random())
            ),
            c.send();
        }
        return O.push(s), s;
      }),
      (R.close = function (e) {
        clearInterval(e.live_timer),
          0 < e.p2p_key && h.disconnect(e.p2p_key),
          0 < e.turn_key && h.disconnect(e.turn_key),
          0 < e.iptcp_key && h.disconnect(e.iptcp_key);
        for (var t = 0; t < O.length; t++)
          if (O[t] == e) {
            O.slice(t, 1);
            break;
          }
      }),
      (R.send = function (e, t) {
        var r;
        return e.linktype == R.iot_linktype.iptcp
          ? ((r = l.iot_hdr(l.iot_cmd.IOT_LINK_CMD_DATA, 0, e.sid, t)),
            h.send(e.iptcp_key, r),
            0)
          : e.linktype == R.iot_linktype.turntcp
          ? ((r = l.iot_hdr(l.iot_cmd.IOT_LINK_CMD_DATA, 0, e.sid, t)),
            h.send(e.turn_key, r),
            0)
          : -1;
      });
    const g = R,
      y = {};
    E.connect_type.CONNECT_TYPE_NONE;
    function C(e, t, r, n, i) {
      (t = E.find_file_req_2(
        E.api_cmd.APP_PROTO_PARAM_REPLAY_CMD_SEARCH,
        t,
        0,
        i,
        r,
        n,
        e.find_file_index,
        e.find_file_count
      )),
        (i = E.api_hdr(E.api_cmd.APP_PROTO_CMD_REPLAY_REQ, e.tick, t)),
        g.send(e.iot, i);
    }
    var M = [],
      r =
        ((y.onconnect = null),
        (y.ondisconnect = null),
        (y.onloginresult = null),
        (y.onptzresult = null),
        (y.onopenstream = null),
        (y.onclosestream = null),
        (y.onrecvframe = null),
        (y.onrecvframeex = null),
        (y.onrecplaystart = null),
        (y.onrecplaycontrol = null),
        (y.onrecplaystop = null),
        (y.onrecvrecframe = null),
        (y.onremotesetup = null),
        (y.onp2perror = null),
        (y.onsearchrec = null),
        (y.onsearchrecend = null),
        (y.onoob = null),
        (y.onvop2pcallresult = null),
        g.init(
          function (e, t, r) {
            null != y.onconnect && y.onconnect(t, r);
          },
          function (e, t, r) {
            null != y.ondisconnect && y.ondisconnect(t, r);
          },
          function (e, t, r) {
            null != onp2perror && y.onp2perror(t, r);
          },
          function (e, t, r) {
            t.length;
            var n,
              i,
              a,
              _,
              o = E.get_api_magic(t);
            if (o == E.APP_PROTO_MAGIC) {
              var c = new Int8Array(t),
                c = (E.parse_api_hdr(c), E.parse_api_hdr(t));
              if (c.cmd == E.api_cmd.APP_PROTO_CMD_AUTH_RSP) {
                var s = t.subarray(E.hdr_len);
                E.parse_auth_res(s);
                null != y.onloginresult && y.onloginresult(r, c.result);
              } else if (c.cmd == E.api_cmd.APP_PROTO_CMD_LIVE_RSP) {
                var s = t.subarray(E.hdr_len),
                  s = E.parse_live_res(s);
                s.live_cmd == E.api_cmd.APP_PROTO_PARAM_LIVE_CMD_STOP
                  ? null != y.onclosestream &&
                    y.onclosestream(r, s.channel, s.streamid, c.result)
                  : s.live_cmd == E.api_cmd.APP_PROTO_PARAM_LIVE_CMD_START &&
                    null != y.onopenstream &&
                    y.onopenstream(
                      r,
                      s.channel,
                      s.streamid,
                      c.result,
                      s.cam_desc
                    );
              } else if (c.cmd == E.api_cmd.APP_PROTO_CMD_VOP2P_RSP)
                null != y.onvop2pcallresult && y.onvop2pcallresult(r, c.result);
              else if (c.cmd == E.api_cmd.APP_PROTO_CMD_FIND_START_RSP)
                y.find_next(r);
              else if (c.cmd != E.api_cmd.APP_PROTO_CMD_FIND_NEXT_RSP)
                if (c.cmd == E.api_cmd.APP_PROTO_CMD_REPLAY_RSP)
                  if (1 != r.file_find)
                    0 == r.file_find &&
                      (null != y.onsearchrecend && y.onsearchrecend(r),
                      (r.file_find = 2));
                  else {
                    var s = t.subarray(E.hdr_len),
                      l = E.parse_search_res(s);
                    if (
                      ((r.file_total += l.file_count),
                      (r.file_index += l.file_count),
                      null != y.onsearchrec)
                    )
                      for (
                        var f = s.subarray(l.len), u = 0;
                        u < l.file_count;
                        u++
                      ) {
                        var h = E.parse_record_file(f),
                          f = f.subarray(h.len);
                        y.onsearchrec(
                          r,
                          h.channel,
                          h.file_type,
                          h.file_begintime,
                          h.file_endtime,
                          l.file_total
                        );
                      }
                    r.file_total >= l.file_total
                      ? null != y.onsearchrecend &&
                        ((r.file_find = 2), y.onsearchrecend(r))
                      : ((r.find_file_index += r.find_file_count),
                        C(
                          r,
                          r.file_chnlist,
                          r.file_begintime,
                          r.file_endtime,
                          r.file_type
                        ));
                  }
                else if (c.cmd == E.api_cmd.APP_PROTO_CMD_SETUP_RSP) {
                  for (
                    var p = t.subarray(E.hdr_len),
                      d = E.parse_setup(p),
                      P = p.subarray(d.len),
                      v = "",
                      u = 0;
                    u < d.data_size;
                    u++
                  )
                    v += String.fromCharCode(P[u]);
                  null != y.onremotesetup &&
                    y.onremotesetup(r, v, d.data_size, c.result);
                } else if (c.cmd === E.api_cmd.APP_PROTO_CMD_SETUP2_RSP) {
                  for (
                    p = t.subarray(E.hdr_len),
                      d = E.parse_setup2(p),
                      P = p.subarray(d.len),
                      v = "",
                      u = 0;
                    u < d.data_size;
                    u++
                  )
                    v += String.fromCharCode(P[u]);
                  null != y.onremotesetup &&
                    y.onremotesetup(r, v, d.data_size, c.result);
                } else
                  c.cmd === E.api_cmd.APP_PROTO_CMD_PTZ_RSP &&
                    ((s = t.subarray(E.hdr_len)),
                    E.parse_ptz_req(s),
                    y.onptzresult(r, c.result));
            } else
              (o != E.PROC_FRAME_MAGIC && o != E.PROC_FRAME_MAGIC2) ||
                (o == E.PROC_FRAME_MAGIC2 &&
                  ((p = E.parse_p2p_frame_head_2(t)), (t = t.subarray(p.len))),
                (s = E.parse_p2p_frame_head(t)),
                (t = t.subarray(s.len)),
                s.headtype == E.p2p_frame_type.live
                  ? ((c = E.parse_live_head(t)),
                    (t = t.subarray(c.len)),
                    c.frametype == E.frame_type.PROC_FRAME_TYPE_AUDIO
                      ? ((n = E.parse_audio_param(t)),
                        (i = t.subarray(n.len)),
                        null != y.onrecvframeex &&
                          y.onrecvframeex(
                            r,
                            c.frametype,
                            i,
                            i.length,
                            c.channel,
                            n.samplerate,
                            n.samplewidth,
                            n.enc,
                            n.channels
                          ))
                      : c.frametype == E.frame_type.PROC_FRAME_TYPE_IFRAME ||
                        c.frametype == E.frame_type.PROC_FRAME_TYPE_PFRAME
                      ? ((a = E.parse_video_param(t)),
                        (_ = t.subarray(a.len)),
                        null != y.onrecvframeex &&
                          y.onrecvframeex(
                            r,
                            c.frametype,
                            _,
                            _.length,
                            c.channel,
                            a.width,
                            a.height,
                            a.enc,
                            a.fps,
                            s.ts_ms
                          ))
                      : c.frametype == E.frame_type.PROC_FRAME_TYPE_OOB &&
                        ((o = E.parse_oob(t)),
                        null != y.onoob && y.onoob(r, o)))
                  : s.headtype == E.p2p_frame_type.replay &&
                    ((p = E.parse_replay_head(t)),
                    (t = t.subarray(p.len)),
                    p.frametype == E.frame_type.PROC_FRAME_TYPE_AUDIO
                      ? ((n = E.parse_audio_param(t)),
                        (i = t.subarray(n.len)),
                        -1 < n.enc.indexOf("AAC") && (i = t.subarray(24)),
                        null != y.onrecvrecframe &&
                          y.onrecvrecframe(
                            r,
                            p.frametype,
                            i,
                            i.length,
                            p.channel,
                            n.samplerate,
                            n.samplewidth,
                            n.enc,
                            n.channels,
                            s.ts_ms
                          ))
                      : p.frametype == E.frame_type.PROC_FRAME_TYPE_IFRAME ||
                        p.frametype == E.frame_type.PROC_FRAME_TYPE_PFRAME
                      ? ((a = E.parse_video_param(t)),
                        (_ = t.subarray(a.len)),
                        null != y.onrecvrecframe &&
                          y.onrecvrecframe(
                            r,
                            p.frametype,
                            _,
                            _.length,
                            p.channel,
                            a.width,
                            a.height,
                            a.enc,
                            a.fps,
                            s.ts_ms
                          ))
                      : (p.frametype, E.frame_type.PROC_FRAME_TYPE_OOB)));
          }
        ),
        (y.getversion = function () {
          return "0.1.32";
        }),
        (y.set_conn_type = function (e) {
          0;
        }),
        (y.set_turn_server = function (e) {
          0;
        }),
        (y.create = function (e, t) {
          if (!t) return null;
          var r = {};
          return (
            (r.context = e),
            M.push(r),
            (r.tick = 0),
            (r.aes = t),
            (r.find_file_index = 0),
            (r.find_file_count = 100),
            (r.find_file_total = 0),
            r
          );
        }),
        (y.connectbyid = function (e, t, r) {
          (e.deviceid = t),
            (e.ip = ""),
            (e.port = 0),
            (e.iot = g.connect(t, 1, "", 0, 0, e, r));
        }),
        (y.connectbyip = function (e, t, r) {
          (e.deviceid = ""),
            (e.ip = t),
            (e.port = r),
            (e.iot = g.connect("", 1, t, r, 0, e));
        }),
        (y.login = function (e, t, r) {
          if (
            t.length < E.APP_PROTO_PARAM_AUTH_NAME_STRLEN &&
            r.length < E.APP_PROTO_PARAM_AUTH_PASSWD_STRLEN
          ) {
            for (
              var n = t.substr(0, 16),
                i = t.substr(16),
                a = r.substr(0, 16),
                _ = r.substr(16),
                o = n.length;
              o < 16;
              o++
            )
              n += String.fromCharCode(0);
            for (o = i.length; o < 16; o++) i += String.fromCharCode(0);
            for (o = a.length; o < 16; o++) a += String.fromCharCode(0);
            for (o = _.length; o < 16; o++) _ += String.fromCharCode(0);
            for (
              var n = e.aes.enc.Utf8.parse(n),
                i = e.aes.enc.Utf8.parse(i),
                a = e.aes.enc.Utf8.parse(a),
                _ = e.aes.enc.Utf8.parse(_),
                c = e.aes.enc.Utf8.parse(E.APP_PROTO_AES128_KEY),
                s = e.aes.AES.encrypt(n, c, {
                  mode: e.aes.mode.ECB,
                  padding: e.aes.pad.NoPadding,
                }),
                l = e.aes.AES.encrypt(i, c, {
                  mode: e.aes.mode.ECB,
                  padding: e.aes.pad.NoPadding,
                }),
                f = e.aes.AES.encrypt(a, c, {
                  mode: e.aes.mode.ECB,
                  padding: e.aes.pad.NoPadding,
                }),
                c = e.aes.AES.encrypt(_, c, {
                  mode: e.aes.mode.ECB,
                  padding: e.aes.pad.NoPadding,
                }),
                s =
                  e.aes.enc.Hex.stringify(s.ciphertext).toString() +
                  e.aes.enc.Hex.stringify(l.ciphertext).toString(),
                l =
                  e.aes.enc.Hex.stringify(f.ciphertext).toString() +
                  e.aes.enc.Hex.stringify(c.ciphertext).toString(),
                u = ((e.tick += 1), E.auth_req(s, l)),
                h = "",
                o = 0;
              o < u.length;
              o++
            )
              h += String.fromCharCode(u[o]);
            (t = h.slice(32)),
              (r = h),
              (f = E.api_hdr(E.api_cmd.APP_PROTO_CMD_AUTH_REQ, e.tick, u));
            g.send(e.iot, f);
          }
        }),
        (y.login2 = function (e, t, r) {
          e.tick += 1;
        }),
        (y.ptz_ctrl = function (e, t, r, n, i) {
          e.tick += 1;
          (t = E.ptz_req(t, r, n, i)),
            (r = E.api_hdr(E.api_cmd.APP_PROTO_CMD_PTZ_REQ, e.tick, t));
          g.send(e.iot, r);
        }),
        (y.open_stream = function (e, t, r) {
          (e.tick += 1), (e.channel = t), (e.streamid = r);
          (t = E.live_req(t, r, E.api_cmd.APP_PROTO_PARAM_LIVE_CMD_START)),
            (r = E.api_hdr(E.api_cmd.APP_PROTO_CMD_LIVE_REQ, e.tick, t));
          g.send(e.iot, r);
        }),
        (y.close_stream = function (e, t, r) {
          e.tick += 1;
          (t = E.live_req(t, r, E.api_cmd.APP_PROTO_PARAM_LIVE_CMD_STOP)),
            (r = E.api_hdr(E.api_cmd.APP_PROTO_CMD_LIVE_REQ, e.tick, t));
          g.send(e.iot, r);
        }),
        (y.close_socket = function (e) {
          g.close(e.iot);
        }),
        (y.change_stream = function (e, t, r) {
          (e.tick += 1), (e.channel = t), (e.streamid = r);
          (t = E.live_req(t, r, E.api_cmd.APP_PROTO_PARAM_LIVE_CMD_START)),
            (r = E.api_hdr(E.api_cmd.APP_PROTO_CMD_LIVE_REQ, e.tick, t));
          g.send(e.iot, r);
        }),
        (y.find_file_start = function (e, t, r, n, i) {
          e.tick += 1;
          (t = E.find_file_cond(t, r, n, i)),
            (r = E.api_hdr(E.api_cmd.APP_PROTO_CMD_FIND_START_REQ, e.tick, t));
          g.send(e.iot, r);
        }),
        (y.find_next = function (e) {
          e.tick += 1;
          var t = E.find_next_req(0),
            t = E.api_hdr(E.api_cmd.APP_PROTO_CMD_FIND_NEXT_REQ, e.tick, t);
          g.send(e.iot, t);
        }),
        (y.find_file_stop = function (e) {
          e.tick += 1;
          var t = E.find_next_req(0),
            t = E.api_hdr(E.api_cmd.APP_PROTO_CMD_FIND_STOP_REQ, e.tick, t);
          g.send(e.iot, t);
        }),
        (y.find_file_start_2 = function (e, t, r, n, i) {
          (e.tick += 1),
            (e.file_index = 0),
            (e.file_total = 0),
            (e.file_begintime = r),
            (e.file_endtime = n),
            (e.file_type = i),
            (e.file_chnlist = t),
            (e.file_find = 1),
            (e.find_file_index = 0),
            (e.find_file_count = 100),
            (e.find_file_total = 0),
            C(e, t, r, n, i);
        }),
        (y.find_file_stop_2 = function (e) {
          e.file_find = 0;
        }),
        (y.replay_start = function (e, t, r, n, i) {
          e.tick += 1;
          (t = E.find_file_req_2(
            E.api_cmd.APP_PROTO_PARAM_REPLAY_CMD_START,
            t,
            0,
            i,
            r,
            n,
            0,
            0
          )),
            (i = E.api_hdr(E.api_cmd.APP_PROTO_CMD_REPLAY_REQ, e.tick, t));
          g.send(e.iot, i);
        }),
        (y.replay_pause = function (e) {
          e.tick += 1;
          var t = E.find_file_req_2(
              E.api_cmd.APP_PROTO_PARAM_REPLAY_CMD_PAUSE,
              null,
              0,
              0,
              0,
              0,
              0,
              0
            ),
            t = E.api_hdr(E.api_cmd.APP_PROTO_CMD_REPLAY_REQ, e.tick, t);
          g.send(e.iot, t);
        }),
        (y.replay_continue = function (e) {
          e.tick += 1;
          var t = E.find_file_req_2(
              E.api_cmd.APP_PROTO_PARAM_REPLAY_CMD_CONTINUE,
              null,
              0,
              0,
              0,
              0,
              0,
              0
            ),
            t = E.api_hdr(E.api_cmd.APP_PROTO_CMD_REPLAY_REQ, e.tick, t);
          g.send(e.iot, t);
        }),
        (y.replay_stop = function (e) {
          e.tick += 1;
          var t = E.find_file_req_2(
              E.api_cmd.APP_PROTO_PARAM_REPLAY_CMD_STOP,
              null,
              0,
              0,
              0,
              0,
              0,
              0
            ),
            t = E.api_hdr(E.api_cmd.APP_PROTO_CMD_REPLAY_REQ, e.tick, t);
          g.send(e.iot, t);
        }),
        (y.remote_setup = function (e, t) {
          e.tick += 1;
          (t = E.setup_req(t)),
            (t = E.api_hdr(E.api_cmd.APP_PROTO_CMD_SETUP_REQ, e.tick, t));
          g.send(e.iot, t);
        }),
        (y.remote_setup2 = function (e, t) {
          e.tick += 1;
          for (
            var r = E.setup_req2(t),
              n = E.api_hdr(E.api_cmd.APP_PROTO_CMD_SETUP2_REQ, e.tick, r),
              r = n.length + t.length,
              r = new ArrayBuffer(r),
              i = new Uint8Array(r),
              a = 0;
            a < n.length;
            a++
          )
            i[a] = n[a];
          for (a = n.length; a < t.length + n.length; a++)
            i[a] = t.charCodeAt(a - n.length);
          g.send(e.iot, i);
        }),
        (y.vop2p_call = function (e, t) {
          e.tick += 1;
          (t = E.vop2p_call_req(t, E.api_cmd.APP_PROTO_PARAM_VOP2P_CMD_CALL)),
            (t = E.api_hdr(E.api_cmd.APP_PROTO_CMD_VOP2P_REQ, e.tick, t));
          g.send(e.iot, t);
        }),
        (y.vop2p_send = function (e, t, r, n, i, a, _, o, c, s) {
          t = E.vop2p_send_req(t, r, n, i, a, _, o, c, s);
          g.send(e.iot, t);
        }),
        (y.vop2p_hangup = function (e, t) {
          (t = E.vop2p_call_req(t, E.api_cmd.APP_PROTO_PARAM_VOP2P_CMD_HANGUP)),
            (t = E.api_hdr(E.api_cmd.APP_PROTO_CMD_VOP2P_REQ, e.tick, t));
          g.send(e.iot, t);
        }),
        (y.setAddressUrl = function (e) {}),
        y);
    const w = function (e, t, b, U) {
      var d,
        F =
          "#define PI 3.1415926535897932384626433832795\n#define VERTEX_TYPE_HEMISPHERE 0\n#define VERTEX_TYPE_PANORAMA 1\n#define VERTEX_TYPE_CYLINDER 2\n#define VERTEX_TYPE_EXPAND 3\n#define VERTEX_TYPE_NORMAL 4\n#define VERTEX_TYPE_SPHERE 5\n#define VERTEX_TYPE_CONE 6\nuniform mat4 projection;\nuniform mat4 modelView;\nuniform mat4 changeprojection;\nuniform mat4 changemodelView;\nattribute vec4 vPosition;\nattribute vec4 vChangePosition;\nattribute vec2 aTexCoor;\nuniform int aMode;\nuniform int aChangeMode;\nuniform float texwidth;\nuniform float texheight;\nuniform float aRotate;\nuniform float aDiameter;\nuniform float aAspect;\nuniform float aViewportAspect;\nuniform float aChangeDiameter;uniform float aChangeRotate;uniform int aChangeAnimation;\nuniform float aChangeStep;\nuniform float aChangeStepCount;\n\nvarying vec2 vTextureCoord;\nvarying float vtexwidth;\nvarying float vtexheight;\nvarying float fMode;\n\nvec4 GetPosition(mat4 proj,mat4 mv,vec4 pos,int mode,float diameter)\n{\n    vec4 aPos=pos;\n    if(mode==VERTEX_TYPE_CYLINDER||mode==VERTEX_TYPE_CONE)\n    {\n       float y;       float x=cos((aPos.x)/diameter-0.5*PI+(diameter-1.0)/diameter*PI)*0.8*diameter;\n       if(aPos.y>250.0)\n           y=-35.0/180.0*PI*1.1;\n       else\n           if(mode==VERTEX_TYPE_CONE)\n              y=(215.0-(180.0+(1.0-abs(cos(aPos.y/180.0*PI)))*90.0))/180.0*PI*1.1;\n           else\n              y=(215.0-aPos.y)/180.0*PI*1.1;\n       float z=sin((aPos.x)/diameter-0.5*PI+(diameter-1.0)/diameter*PI)*0.8*diameter-(sqrt(diameter)-1.0/diameter);\n       aPos = vec4(x,y,z,1.0);\n    }\n    else\n    if(mode!=VERTEX_TYPE_HEMISPHERE&&mode!=VERTEX_TYPE_SPHERE)\n    {\n       float vcut=texwidth/texheight;\n       if(mode==VERTEX_TYPE_EXPAND)\n           aPos=vec4(aPos.x*aAspect,aPos.y*vcut,aPos.z,1.0);\n       else\n           aPos=vec4(aPos.x*aAspect,aPos.y,aPos.z,1.0);\n    }\n    else\n           aPos=vec4(aPos.x,aPos.y,aPos.z,1.0);\n    return proj * mv * aPos;\n}\nvec2 GetCoord(float pRotate)\n{\n    float sin_factor = sin(-pRotate);\n    float cos_factor = cos(-pRotate);\n    vec2 tmpcoor = vec2(aTexCoor.x - 0.5, aTexCoor.y - 0.5) * mat2(cos_factor, sin_factor, -sin_factor, cos_factor);\n       return vec2(tmpcoor.x+0.5,tmpcoor.y+0.5);\n}\nvoid main(void)\n{\n    vec4 aPos = GetPosition(projection,modelView,vPosition,aMode,aDiameter);\n    if(aChangeAnimation==1)\n    {\n       vec4 bPos=GetPosition(changeprojection,changemodelView,vChangePosition,aChangeMode,aChangeDiameter)-aPos;\n       bPos=bPos/aChangeStepCount;\n       aPos=aPos+bPos*aChangeStep;\n       float tmp1 = aChangeRotate - aRotate;\n       tmp1=aRotate+tmp1/aChangeStepCount*aChangeStep;\n       vTextureCoord = GetCoord(tmp1);\n    }\n    else\n       vTextureCoord = GetCoord(aRotate);\n    gl_Position = aPos;\n    vtexwidth=texwidth;\n    vtexheight = texheight;\n    if(aMode==4)\n       fMode=1.0;\n    else\n       fMode=0.0;\n}\n",
        B =
          "precision mediump float;\n\nvarying vec2 vTextureCoord;\nvarying vec2 vTextCoord;\n uniform sampler2D s_texture_y;\n uniform sampler2D s_texture_u;\n uniform sampler2D s_texture_v;\nuniform float centerx;\nuniform float centery;\nuniform float radius;\nvarying float vtexwidth;\nvarying float vtexheight;\nvarying float fMode;\n\nvoid main()\n{\n    vec2 ltc;\n    if(fMode>0.0)\n        ltc = vTextureCoord;\n    else\n        ltc = vec2((vTextureCoord.x-0.5)*radius+centerx+0.5,(vTextureCoord.y-0.5)*radius*(vtexwidth/vtexheight)+0.5+centery);    if(ltc.y>1.0||ltc.y<0.0)\n       gl_FragColor=vec4(0.0,0.0,0.0,0.0);\n    else\n    {\n     highp float y = texture2D(s_texture_y, vTextureCoord).r;\n     highp float u = texture2D(s_texture_u, vTextureCoord).r - 0.5;\n     highp float v = texture2D(s_texture_v, vTextureCoord).r - 0.5;\n     \n     highp float r = y +             1.402 * v;\n     highp float g = y - 0.344 * u - 0.714 * v;\n     highp float b = y + 1.772 * u;\n     gl_FragColor=vec4(r,g,b,1.0);\n    }\n}",
        i = null,
        a = new Array(VERTEX_TYPE_COUNT),
        H = new Array(VERTEX_TYPE_COUNT),
        Y = new Array(VERTEX_TYPE_COUNT),
        V = new Array(VERTEX_TYPE_COUNT),
        _ = new Array(VERTEX_TYPE_COUNT),
        X = 0,
        K = 0,
        z = 0,
        G = 0,
        q = 0,
        Q = 0,
        W = 0,
        j = 0,
        o = 0,
        Z = 0,
        J = 0,
        $ = 0,
        ee = 0,
        te = 0,
        re = 0,
        ne = 0,
        ie = 0,
        ae = 0,
        _e = 0,
        c = new Array(3),
        i = 0,
        s = 0,
        l = 0,
        f = 0,
        u = 0,
        oe = (newMat4_identity(), newMat4_identity()),
        ce = (newMat4_identity(), 256),
        se = 256,
        P = 256,
        h = 0,
        p = vec3(0, 0, 0),
        le = vec3(1, 1, 1),
        fe = vec3(0, 0, 0),
        ue = vec3(0, 0, 0),
        he = vec3(1, 1, 1),
        pe = vec3(0, 0, 0),
        de = vec3(0, 0, 0),
        Pe = vec3(1, 1, 1),
        ve = vec3(0, 0, 0),
        Ee = vec3(0, 0, 0),
        Re = vec3(1, 1, 1),
        Te = vec3(0, 0, 0),
        Ae = !1,
        v = 0,
        me = 0,
        Oe = 0,
        ge = new Array(3),
        E = new Array(3),
        R = 512,
        T = 512,
        r = 3,
        n = vec2(0 + r, 180 + r),
        A = vec2(360 + r, 270 + r),
        m = t,
        O = e,
        g = b;
      function ye(e, t, r, n, i, a, _, o, c, s) {
        (t = newMat4_identity()),
          ksTranslate(t, vec3(0, 0, n)),
          (r = newMat4_identity());
        n = newMat4_identity();
        newMat4_identity();
        _[0] && ksRotate(n, _[0], 1, 0, 0),
          _[1] && ksRotate(n, _[1], 0, 1, 0),
          _[2] && ksRotate(n, _[2], 0, 0, 1),
          ksMatrixMultiply(r, r, n),
          ksTranslate(t, vec3(i[0], i[1], i[2])),
          s != VERTEX_TYPE_CYLINDER && s != VERTEX_TYPE_CONE
            ? ((e = newMat4_identity()),
              ksPerspective(e, 60 / a[0], g, 1e-4, 1200),
              O.uniformMatrix4fv(o, !1, e))
            : ((e = newMat4_identity()),
              ksOrtho(e, -g, g, -1, 1, 1e-4, 1200),
              O.uniformMatrix4fv(o, !1, e),
              ksScale(r, vec3(a[0], a[1], 1))),
          ksMatrixMultiply(t, r, t),
          O.uniformMatrix4fv(c, !1, t);
      }
      function Ce() {
        return ((A[0] - n[0]) / r) * ((A[1] - n[1]) / r) * 6;
      }
      function y(e) {
        var t = e[0],
          r = e[1],
          n = 0,
          i = 0,
          a = 0;
        switch (h) {
          case VERTEX_TYPE_HEMISPHERE:
            (n =
              m *
              Math.cos((t / 180) * Math.PI) *
              Math.cos((r / 180) * Math.PI)),
              (i =
                m *
                Math.sin((t / 180) * Math.PI) *
                Math.cos((r / 180) * Math.PI)),
              (a = m * Math.sin((r / 180) * Math.PI));
            break;
          case VERTEX_TYPE_PANORAMA:
            (n = ((180 - t) / 180) * 1.2),
              (i = 250 < r ? (-35 / 180) * 6 : ((215 - r) / 180) * 6),
              (a = 1);
            break;
          case VERTEX_TYPE_CYLINDER:
          case VERTEX_TYPE_CONE:
            (n = (t / 180) * Math.PI), (i = r), (a = 1);
            break;
          case VERTEX_TYPE_EXPAND:
            (n =
              2 *
              Math.cos((t / 180) * Math.PI) *
              Math.cos((r / 180) * Math.PI)),
              (i =
                2 *
                Math.sin((t / 180) * Math.PI) *
                Math.cos((r / 180) * Math.PI)),
              0 == (a = 2 * Math.sin(((r - 180) / 180) * Math.PI)) &&
                (a = 1e-7),
              (n = (2 * Math.atan(n / a)) / Math.PI),
              (i =
                -Math.sin((t / 180) * Math.PI) *
                Math.sin(((270 - r) / 180) * Math.PI)),
              (a = 1.265);
            break;
          case VERTEX_TYPE_NORMAL:
            (n = ((t - 180) / 360) * 2),
              (i = ((r - 225) / 90) * 2),
              (a = 1.265);
            break;
          case VERTEX_TYPE_SPHERE:
            (n = Math.cos((t / 180) * Math.PI) * Math.cos((r / 180) * Math.PI)),
              (i =
                Math.sin((t / 180) * Math.PI) * Math.cos((r / 180) * Math.PI)),
              0 == (a = Math.sin(((r - 180) / 180) * Math.PI)) && (a = 1e-7),
              (n = (2 * Math.atan(n / a)) / Math.PI),
              (i =
                -Math.sin((t / 180) * Math.PI) *
                Math.sin(((270 - r) / 180) * Math.PI)),
              (a = 1.265);
        }
        return vec3(n, i, a);
      }
      function C(e) {
        var t, r, n, i;
        return h == VERTEX_TYPE_NORMAL
          ? vec2(e[0] / 360, (270 - e[1]) / 90)
          : ((i = e[0]),
            (e = e[1]),
            (n = r = t = 0),
            (t =
              m *
              Math.cos((i / 180) * Math.PI) *
              Math.cos((e / 180) * Math.PI)),
            (r =
              m *
              Math.sin((i / 180) * Math.PI) *
              Math.cos((e / 180) * Math.PI)),
            (n = m * Math.sin((e / 180) * Math.PI)),
            (i = vec3(t, r, n)),
            vec3normalize(i, i),
            (e = vec2(i[0], i[1])),
            (t = vec2length(e)),
            vec2normalize(e, e),
            1 < t && (t = 1),
            (r = Math.asin(t)),
            (n = 2 * Math.sin(0.5 * r)),
            ((i = vec2(
              e[0] * n * ((1 / Math.pow(2, 0.5)) * 0.5),
              e[1] * n * ((1 / Math.pow(2, 0.5)) * 0.5)
            ))[0] = i[0] + 0.5),
            (i[1] = i[1] + 0.5),
            (i[1] = 1 - i[1]),
            i);
      }
      (this.DrawSelf = function () {
        if (!(P <= 0 && h != VERTEX_TYPE_NORMAL)) {
          O.useProgram(i);
          for (
            var e = R,
              t = T,
              r =
                (O.uniform1f(G, e),
                O.uniform1f(q, t),
                h == VERTEX_TYPE_HEMISPHERE || h == VERTEX_TYPE_SPHERE
                  ? ye(
                      oe,
                      0,
                      0,
                      (-3 * Math.tan((30 / 180) * Math.PI)) /
                        Math.tan((30 / 180) * Math.PI),
                      vec3(
                        p[0],
                        p[1],
                        (p[2] * Math.tan((30 / 180) * Math.PI)) /
                          Math.tan((30 / 180) * Math.PI)
                      ),
                      le,
                      fe,
                      u,
                      f,
                      h
                    )
                  : ye(oe, 0, 0, -3, p, le, fe, u, f, h),
                O.uniform1i(X, h),
                O.uniform1f(K, ue[0]),
                O.uniform1f(z, he[0]),
                O.uniform1f(Q, g),
                O.uniform1f(ne, 1),
                O.uniform1f(ie, ce / e - 0.5),
                O.uniform1f(ae, se / t - 0.5),
                O.uniform1f(_e, P / (e / 2)),
                O.uniform1i(W, Ae ? 1 : 0),
                Ae &&
                  (O.uniform1f(re, Ee[0]),
                  O.uniform1f(te, Re[0]),
                  O.uniform1f(Z, Oe),
                  O.uniform1f(j, me),
                  O.uniform1i(J, v),
                  (t =
                    v != VERTEX_TYPE_CYLINDER && v != VERTEX_TYPE_CONE
                      ? -3
                      : 1),
                  ye(
                    mChangeprojectionMatrix,
                    mChangemodelViewMatrix,
                    mChangeRoateMatrix,
                    t,
                    de,
                    Pe,
                    ve,
                    $,
                    ee,
                    v
                  )),
                O.bindBuffer(O.ARRAY_BUFFER, a[v]),
                O.vertexAttribPointer(o, 3, O.FLOAT, !1, 0, 0),
                O.enableVertexAttribArray(o),
                O.bindBuffer(O.ARRAY_BUFFER, a[h]),
                O.vertexAttribPointer(s, 3, O.FLOAT, !1, 0, 0),
                O.enableVertexAttribArray(s),
                O.bindBuffer(O.ARRAY_BUFFER, _[h]),
                O.vertexAttribPointer(l, 2, O.FLOAT, !1, 0, 0),
                O.enableVertexAttribArray(l),
                [O.TEXTURE0, O.TEXTURE1, O.TEXTURE2]),
              n = 0;
            n < 3;
            n++
          )
            O.activeTexture(r[n]),
              null != E[0]
                ? O.bindTexture(O.TEXTURE_2D, E[n])
                : O.bindTexture(O.TEXTURE_2D, ge[n]),
              O.uniform1i(c[n], n);
          O.drawArrays(O.TRIANGLES, 0, Y[h]),
            O.disableVertexAttribArray(s),
            O.disableVertexAttribArray(l);
        }
      }),
        (this.SwitchMode = function (e) {
          e < 0 || 6 < e || (h = e);
        }),
        (this.Transform = function (e, t, r) {
          if (r)
            switch (e) {
              case TRANSFORM_TYPE_POSITION:
                cpvec3(t, ue);
                break;
              case TRANSFORM_TYPE_SCALE:
                cpvec3(t, he);
                break;
              case TRANSFORM_TYPE_ROTATE:
                cpvec3(t, pe);
            }
          else
            switch (e) {
              case TRANSFORM_TYPE_POSITION:
                cpvec3(t, p);
                break;
              case TRANSFORM_TYPE_SCALE:
                cpvec3(t, le);
                break;
              case TRANSFORM_TYPE_ROTATE:
                cpvec3(t, fe);
            }
        }),
        (this.SetTexture = function (e) {
          (E[0] = e.texture[0]),
            (E[1] = e.texture[1]),
            (E[2] = e.texture[2]),
            (R = e.texwidth),
            (T = e.texheight);
        }),
        (this.ClearTexture = function () {
          (E[0] = null), (E[1] = null), (E[2] = null), (T = R = 0);
        }),
        (this.SetFishEyeParameter = function (e, t, r) {
          (P = e), (ce = t), (se = r);
        }),
        (this.SetChangeAnimation = function (e, t, r, n) {
          (Ae = e), (me = t), (v = n), (Oe = r);
        }),
        (this.SetChangePSR = function (e, t, r, n, i, a) {
          cpvec3(e, de),
            cpvec3(t, Pe),
            cpvec3(r, ve),
            cpvec3(n, Ee),
            cpvec3(i, Re),
            cpvec3(a, Te);
        }),
        (t = O.createShader(O.VERTEX_SHADER)),
        O.shaderSource(t, F),
        O.compileShader(t),
        (e = O.createShader(O.FRAGMENT_SHADER)),
        O.shaderSource(e, B),
        O.compileShader(e),
        (i = O.createProgram()),
        O.attachShader(i, t),
        O.attachShader(i, e),
        O.linkProgram(i),
        O.useProgram(i),
        O.getUniformLocation(i, "modelView"),
        (X = O.getUniformLocation(i, "aMode")),
        (K = O.getUniformLocation(i, "aRotate")),
        (z = O.getUniformLocation(i, "aDiameter")),
        (G = O.getUniformLocation(i, "texwidth")),
        (q = O.getUniformLocation(i, "texheight")),
        (Q = O.getUniformLocation(i, "aAspect")),
        (W = O.getUniformLocation(i, "aChangeAnimation")),
        (j = O.getUniformLocation(i, "aChangeStep")),
        (o = O.getAttribLocation(i, "vChangePosition")),
        (Z = O.getUniformLocation(i, "aChangeStepCount")),
        ($ = O.getUniformLocation(i, "changeprojection")),
        (ee = O.getUniformLocation(i, "changemodelView")),
        (J = O.getUniformLocation(i, "aChangeMode")),
        (c[0] = O.getUniformLocation(i, "s_texture_y")),
        (c[1] = O.getUniformLocation(i, "s_texture_u")),
        (c[2] = O.getUniformLocation(i, "s_texture_v")),
        O.getUniformLocation(i, "sTexText"),
        (te = O.getUniformLocation(i, "aChangeDiameter")),
        (re = O.getUniformLocation(i, "aChangeRotate")),
        (ne = O.getUniformLocation(i, "aViewportAspect")),
        (ie = O.getUniformLocation(i, "centerx")),
        (ae = O.getUniformLocation(i, "centery")),
        (_e = O.getUniformLocation(i, "radius")),
        (s = O.getAttribLocation(i, "vPosition")),
        (l = O.getAttribLocation(i, "aTexCoor")),
        (f = O.getUniformLocation(i, "modelView")),
        (u = O.getUniformLocation(i, "projection")),
        (t = newMat4_identity()),
        (e = O.canvas.clientWidth / O.canvas.clientHeight),
        h != VERTEX_TYPE_CYLINDER && h != VERTEX_TYPE_CONE
          ? ksPerspective(t, 60, e, 1e-4, 1200)
          : ksOrtho(t, -e, e, -1, 1, 1e-4, 1200),
        O.uniformMatrix4fv(u, !1, t);
      for (var M = 0; M < VERTEX_TYPE_COUNT; M++) {
        h = M;
        for (
          var I = 3 * Ce(),
            S = Ce(),
            S = ((Y[M] = S), new Float32Array(I)),
            I = ((A[0] - n[0]) / r) * ((A[1] - n[1]) / r) * 6 * 2,
            I = new Float32Array(I),
            Me = ((L = L = k = D = N = x = w = Ie = Me = void 0), S),
            Ie = I,
            w = [],
            x = [],
            N = n[1];
          N < A[1];
          N += r
        )
          for (var D = n[0]; D < A[0]; D += r) {
            var k,
              L = y((k = vec2(D, N))),
              L =
                (w.push(L[0]),
                w.push(L[1]),
                w.push(L[2]),
                (k = vec2(D - r, N)),
                (L = y(k)),
                w.push(L[0]),
                w.push(L[1]),
                w.push(L[2]),
                (k = vec2(D, N - r)),
                (L = y(k)),
                w.push(L[0]),
                w.push(L[1]),
                w.push(L[2]),
                (k = vec2(D, N - r)),
                (L = y(k)),
                w.push(L[0]),
                w.push(L[1]),
                w.push(L[2]),
                (k = vec2(D - r, N)),
                (L = y(k)),
                w.push(L[0]),
                w.push(L[1]),
                w.push(L[2]),
                (k = vec2(D - r, N - r)),
                (L = y(k)),
                w.push(L[0]),
                w.push(L[1]),
                w.push(L[2]),
                C((k = vec2(D, N)))),
              L = (x.push(L[0]), x.push(L[1]), C((k = vec2(D - r, N)))),
              L = (x.push(L[0]), x.push(L[1]), C((k = vec2(D, N - r)))),
              L = (x.push(L[0]), x.push(L[1]), C((k = vec2(D, N - r)))),
              L = (x.push(L[0]), x.push(L[1]), C((k = vec2(D - r, N)))),
              L = (x.push(L[0]), x.push(L[1]), C((k = vec2(D - r, N - r))));
            x.push(L[0]), x.push(L[1]);
          }
        Me.set(w),
          Ie.set(x),
          (H[M] = S.BYTES_PER_ELEMENT),
          (V[M] = I.BYTES_PER_ELEMENT),
          (a[M] = O.createBuffer()),
          O.bindBuffer(O.ARRAY_BUFFER, a[M]),
          O.bufferData(O.ARRAY_BUFFER, S, O.STATIC_DRAW),
          (_[M] = O.createBuffer()),
          O.bindBuffer(O.ARRAY_BUFFER, _[M]),
          O.bufferData(O.ARRAY_BUFFER, I, O.STATIC_DRAW);
      }
      (h = 4),
        ((d = new Image()).src = "./logo_bg.png"),
        d.addEventListener("load", function () {
          var e = document.createElement("canvas"),
            t =
              ((e.width = d.height), (e.height = d.height), e.getContext("2d")),
            r =
              (t.drawImage(d, 0, 0, d.height, d.height),
              t.getImageData(0, 0, d.height, d.height).data),
            n = r.length / 4;
          let i = new Uint8Array(n),
            a = new Uint8Array(n),
            _ = new Uint8Array(n);
          for (let e = 0; e < n; e++) {
            var o = r[4 * e],
              c = r[4 * e + 1],
              s = r[4 * e + 2];
            (i[e] = 0.299 * o + 0.587 * c + 0.114 * s),
              (a[e] = -0.147108 * o - 0.288804 * c + 0.435912 * s + 128),
              (_[e] = 0.614777 * o - 0.514799 * c - 0.099978 * s + 128);
          }
          for (
            var t = e.width,
              e = e.height,
              l = [O.TEXTURE0, O.TEXTURE1, O.TEXTURE2],
              f = [i, a, _],
              u = [t, t / 2, t / 2],
              h = [e, e / 2, e / 2],
              p = 0;
            p < 3;
            p++
          )
            (ge[p] = O.createTexture()),
              O.activeTexture(l[p]),
              O.bindTexture(O.TEXTURE_2D, ge[p]),
              O.texParameteri(O.TEXTURE_2D, O.TEXTURE_MIN_FILTER, O.LINEAR),
              O.texParameteri(O.TEXTURE_2D, O.TEXTURE_WRAP_S, O.CLAMP_TO_EDGE),
              O.texParameteri(O.TEXTURE_2D, O.TEXTURE_WRAP_T, O.CLAMP_TO_EDGE),
              O.texImage2D(
                O.TEXTURE_2D,
                0,
                O.LUMINANCE,
                u[p],
                h[p],
                0,
                O.LUMINANCE,
                O.UNSIGNED_BYTE,
                f[p]
              );
          (P = d.height / 2),
            (T = d.height),
            (R = d.width),
            (ce = d.width / 2),
            (se = d.height / 2);
        });
    };
    const j = function (e) {
      function t() {
        return vec3(0, 0, 0);
      }
      function r() {
        return vec3(1, 1, 1);
      }
      function n() {
        return vec3(0, 0, 0);
      }
      function i() {
        return vec3(60, 0, 0);
      }
      function a() {
        return vec3(0, 0, 3);
      }
      function _() {
        var e = {};
        return (
          (e._pos = t()),
          (e._scale = r()),
          (e._rotate = n()),
          (e._texpos = t()),
          (e._texscale = r()),
          (e._texrotate = n()),
          e
        );
      }
      var l,
        u,
        f,
        h,
        p,
        d,
        P,
        v = [
          {
            _item: [
              {
                _winpos: [0, 0, 12, 12],
                _default: _(),
                _matrix: _(),
                _vertype: VERTEX_TYPE_NORMAL,
                _ismain: !0,
                _showframe: !1,
              },
            ],
            _mode: SCRN_NORMAL,
            _count: 1,
            _showselected: !1,
          },
          {
            _item: [
              {
                _winpos: [0, 0, 12, 12],
                _default: _(),
                _matrix: _(),
                _vertype: VERTEX_TYPE_HEMISPHERE,
                _ismain: !0,
                _showframe: !1,
              },
            ],
            _mode: SCRN_HEMISPHERE,
            _count: 1,
            _showselected: !1,
          },
          {
            _item: [
              {
                _winpos: [0, 0, 12, 12],
                _default: {
                  _pos: vec3(0, 0, 0),
                  _scale: r(),
                  _rotate: vec3(-30, 0, 0),
                  _texpos: t(),
                  _texscale: r(),
                  _texrotate: n(),
                },
                _matrix: {
                  _pos: vec3(0, 0, 0),
                  _scale: r(),
                  _rotate: vec3(-30, 0, 0),
                  _texpos: t(),
                  _texscale: r(),
                  _texrotate: n(),
                },
                _vertype: VERTEX_TYPE_CYLINDER,
                _ismain: !0,
                _showframe: !1,
              },
            ],
            _mode: SCRN_CYLINDER,
            _count: 1,
            _showselected: !1,
          },
          {
            _item: [
              {
                _winpos: [0, 0, 12, 12],
                _default: _(),
                _matrix: _(),
                _vertype: VERTEX_TYPE_EXPAND,
                _ismain: !0,
                _showframe: !1,
              },
            ],
            _mode: SCRN_EXPAND,
            _count: 1,
            _showselected: !1,
          },
          {
            _item: [
              {
                _winpos: [-12, 6, 24, 6],
                _default: _(),
                _matrix: _(),
                _vertype: VERTEX_TYPE_PANORAMA,
                _ismain: !0,
                _showframe: !1,
              },
              {
                _winpos: [0, 0, 24, 6],
                _default: _(),
                _matrix: _(),
                _vertype: VERTEX_TYPE_PANORAMA,
                _ismain: !1,
                _showframe: !1,
              },
            ],
            _mode: SCRN_UPDOWN,
            _count: 2,
            _showselected: !1,
          },
          {
            _item: [
              {
                _winpos: [0, 0, 6, 6],
                _default: {
                  _pos: a(),
                  _scale: r(),
                  _rotate: i(),
                  _texpos: t(),
                  _texscale: r(),
                  _texrotate: n(),
                },
                _matrix: {
                  _pos: a(),
                  _scale: r(),
                  _rotate: i(),
                  _texpos: t(),
                  _texscale: r(),
                  _texrotate: n(),
                },
                _vertype: VERTEX_TYPE_HEMISPHERE,
                _ismain: !1,
                _showframe: !1,
              },
              {
                _winpos: [6, 0, 6, 6],
                _default: {
                  _pos: a(),
                  _scale: r(),
                  _rotate: vec3(60, 0, -90),
                  _texpos: t(),
                  _texscale: r(),
                  _texrotate: n(),
                },
                _matrix: {
                  _pos: a(),
                  _scale: r(),
                  _rotate: vec3(60, 0, -90),
                  _texpos: t(),
                  _texscale: r(),
                  _texrotate: n(),
                },
                _vertype: VERTEX_TYPE_HEMISPHERE,
                _ismain: !1,
                _showframe: !1,
              },
              {
                _winpos: [0, 6, 6, 6],
                _default: {
                  _pos: a(),
                  _scale: r(),
                  _rotate: vec3(60, 0, -180),
                  _texpos: t(),
                  _texscale: r(),
                  _texrotate: n(),
                },
                _matrix: {
                  _pos: a(),
                  _scale: r(),
                  _rotate: vec3(60, 0, -180),
                  _texpos: t(),
                  _texscale: r(),
                  _texrotate: n(),
                },
                _vertype: VERTEX_TYPE_HEMISPHERE,
                _ismain: !1,
                _showframe: !1,
              },
              {
                _winpos: [6, 6, 6, 6],
                _default: {
                  _pos: a(),
                  _scale: r(),
                  _rotate: vec3(60, 0, -270),
                  _texpos: t(),
                  _texscale: r(),
                  _texrotate: n(),
                },
                _matrix: {
                  _pos: a(),
                  _scale: r(),
                  _rotate: vec3(60, 0, -270),
                  _texpos: t(),
                  _texscale: r(),
                  _texrotate: n(),
                },
                _vertype: VERTEX_TYPE_HEMISPHERE,
                _ismain: !1,
                _showframe: !1,
              },
            ],
            _mode: SCRN_FOUR,
            _count: 4,
            _showselected: !1,
          },
        ],
        E = 0,
        R = 0,
        T = [],
        A = -1,
        m = -1,
        O = -1,
        g = this,
        y = e,
        C = new w(y, 1.7, y.canvas.width / y.canvas.height, 1),
        M = y.canvas.width,
        I = y.canvas.height;
      function S() {
        return new Date().valueOf();
      }
      (this.DrawSelf = function () {
        y.viewport(0, 0, y.canvas.width, y.canvas.height),
          y.enable(y.DEPTH_TEST),
          y.clearColor(0, 0, 0, 1),
          y.clear(y.COLOR_BUFFER_BIT | y.DEPTH_BUFFER_BIT);
        for (
          var e = y.canvas.width / 12,
            t = y.canvas.height / 12,
            r = v[E],
            n = 0;
          n < r._count;
          n++
        )
          y.viewport(
            r._item[n]._winpos[0] * e,
            r._item[n]._winpos[1] * t,
            r._item[n]._winpos[2] * e,
            r._item[n]._winpos[3] * t
          ),
            C.Transform(TRANSFORM_TYPE_POSITION, r._item[n]._matrix._pos, !1),
            C.Transform(TRANSFORM_TYPE_SCALE, r._item[n]._matrix._scale, !1),
            C.Transform(TRANSFORM_TYPE_ROTATE, r._item[n]._matrix._rotate, !1),
            C.Transform(
              TRANSFORM_TYPE_POSITION,
              r._item[n]._matrix._texpos,
              !0
            ),
            C.Transform(TRANSFORM_TYPE_SCALE, r._item[n]._matrix._texscale, !0),
            C.Transform(
              TRANSFORM_TYPE_ROTATE,
              r._item[n]._matrix._texrotate,
              !0
            ),
            C.SwitchMode(r._item[n]._vertype),
            C.DrawSelf();
        y.viewport(0, 0, y.canvas.width, y.canvas.height);
      }),
        (this.ClearTexture = function () {
          C.ClearTexture();
        }),
        (this.LoadTexture = function (e, t, r) {
          for (
            var n = {},
              i = [y.TEXTURE0, y.TEXTURE1, y.TEXTURE2],
              a = t * r,
              _ = a >> 2,
              o = [
                e.subarray(0, a),
                e.subarray(a, a + _),
                e.subarray(a + _, a + 2 * _),
              ],
              c = ((n.texture = new Array(3)), [t, t / 2, t / 2]),
              s = [r, r / 2, r / 2],
              l = 0;
            l < 3;
            l++
          )
            (n.texture[l] = y.createTexture()),
              y.activeTexture(i[l]),
              y.bindTexture(y.TEXTURE_2D, n.texture[l]),
              y.texParameteri(y.TEXTURE_2D, y.TEXTURE_MIN_FILTER, y.LINEAR),
              y.texParameteri(y.TEXTURE_2D, y.TEXTURE_WRAP_S, y.CLAMP_TO_EDGE),
              y.texParameteri(y.TEXTURE_2D, y.TEXTURE_WRAP_T, y.CLAMP_TO_EDGE),
              y.texImage2D(
                y.TEXTURE_2D,
                0,
                y.LUMINANCE,
                c[l],
                s[l],
                0,
                y.LUMINANCE,
                y.UNSIGNED_BYTE,
                o[l]
              );
          return (n.texwidth = t), (n.texheight = r), C.SetTexture(n), n;
        }),
        (this.LoadTextureFormFile = function (e, t) {
          var r = new Image(),
            n = ((r.src = e), {});
          return (
            r.addEventListener("load", function () {
              (n.texture = y.createTexture()),
                y.activeTexture(y.TEXTURE0),
                y.bindTexture(y.TEXTURE_2D, n.texture),
                y.texImage2D(
                  y.TEXTURE_2D,
                  0,
                  y.RGBA,
                  y.RGBA,
                  y.UNSIGNED_BYTE,
                  r
                ),
                y.texParameteri(y.TEXTURE_2D, y.TEXTURE_MAG_FILTER, y.NEAREST),
                y.texParameteri(y.TEXTURE_2D, y.TEXTURE_MIN_FILTER, y.NEAREST),
                y.texParameteri(
                  y.TEXTURE_2D,
                  y.TEXTURE_WRAP_S,
                  y.CLAMP_TO_EDGE
                ),
                y.texParameteri(
                  y.TEXTURE_2D,
                  y.TEXTURE_WRAP_T,
                  y.CLAMP_TO_EDGE
                ),
                y.generateMipmap(y.TEXTURE_2D),
                (n.texwidth = r.width),
                (n.texheight = r.height),
                C.SetTexture(n),
                null != t && t(n);
            }),
            n
          );
        }),
        (this.Transform = function (e, t, r, n) {
          if (!(n >= v[E]._count))
            if (r)
              switch (e) {
                case TRANSFORM_TYPE_POSITION:
                  cpvec3(t, v[E]._item[n]._matrix._texpos);
                  break;
                case TRANSFORM_TYPE_SCALE:
                  cpvec3(t, v[E]._item[n]._matrix._texscale);
                  break;
                case TRANSFORM_TYPE_ROTATE:
                  cpvec3(t, v[E]._item[n]._matrix._texrotate);
              }
            else
              switch (e) {
                case TRANSFORM_TYPE_POSITION:
                  cpvec3(t, v[E]._item[n]._matrix._pos);
                  break;
                case TRANSFORM_TYPE_SCALE:
                  cpvec3(t, v[E]._item[n]._matrix._scale);
                  break;
                case TRANSFORM_TYPE_ROTATE:
                  cpvec3(t, v[E]._item[n]._matrix._rotate);
              }
        }),
        (this.SetFishEyeParameter = function (e, t, r) {
          C.SetFishEyeParameter(e, t, r);
        }),
        (this.SwitchMode = function (e) {
          e < 0 || 5 < e || (E = e);
        }),
        (this.StartAnimation = function (e, t, r, n, i, a, _, o) {
          var c = v[E];
          if (!(a < 0 || a >= c._count)) {
            var s = {};
            switch (
              ((s._onEnd = o),
              (s._end = new Float32Array(3)),
              cpvec3(e, s._end),
              (s._start = new Float32Array(3)),
              (s._value = new Float32Array(3)),
              (s._Inertia = _),
              n)
            ) {
              case TRANSFORM_TYPE_POSITION:
                i
                  ? (cpvec3(c._item[a]._matrix._texpos, s._start),
                    cpvec3(c._item[a]._matrix._texpos, s._value))
                  : (cpvec3(c._item[a]._matrix._pos, s._start),
                    cpvec3(c._item[a]._matrix._pos, s._value));
                break;
              case TRANSFORM_TYPE_SCALE:
                i
                  ? (cpvec3(c._item[a]._matrix._texscale, s._start),
                    cpvec3(c._item[a]._matrix._texscale, s._value))
                  : (cpvec3(c._item[a]._matrix._scale, s._start),
                    cpvec3(c._item[a]._matrix._scale, s._value));
                break;
              case TRANSFORM_TYPE_ROTATE:
                i
                  ? (cpvec3(c._item[a]._matrix._texrotate, s._start),
                    cpvec3(c._item[a]._matrix._texrotate, s._value))
                  : (cpvec3(c._item[a]._matrix._rotate, s._start),
                    cpvec3(c._item[a]._matrix._rotate, s._value));
            }
            return (
              (s._isloop = r),
              (s._istexture = i),
              (s._type = n),
              (s._step = t),
              (s._stepcount = 0),
              (s._index = a),
              s._isloop
                ? (s._unit = s._end)
                : (s._unit = vec3(
                    (e[0] - s._start[0]) / t,
                    (e[1] - s._start[1]) / t,
                    (e[2] - s._start[2]) / t
                  )),
              T.push(s),
              s
            );
          }
        }),
        (this.TapOrMouseDown = function (e, t) {
          (O = (function (e, t, r) {
            var n, i, a;
            switch (r) {
              case SCRN_UPDOWN:
                a = I / 2 < t ? 1 : 0;
                break;
              case SCRN_FOUR:
                (n = parseInt(e / (M / 2))),
                  (i = parseInt(t / (I / 2))),
                  (a = parseInt(n + 2 * (1 - i)));
                break;
              default:
                a = 0;
            }
            return a;
          })(e, t, E)),
            (T = []),
            (l = A = e),
            (u = m = t),
            (f = S());
        }),
        (this.TapOrMouseMove = function (e, t) {
          var r, n;
          if (!(A < 0 && m < 0)) {
            var i = new Float32Array(3),
              a = new Float32Array(3),
              _ = new Float32Array(3),
              o = new Float32Array(3),
              c = new Float32Array(3),
              s = new Float32Array(3),
              l = v[E],
              f = R;
            switch (E) {
              case SCRN_NORMAL:
                (r = e - A),
                  (n = t - m),
                  cpvec3(l._item[0]._matrix._scale, _),
                  1.00001 < _[0] &&
                    ((h = ((_[0] - 1) * M) / I),
                    (d = -h),
                    (p = _[1] - 1),
                    (P = -p),
                    cpvec3(l._item[0]._matrix._pos, i),
                    (i[0] += (r / M) * 2),
                    (i[1] -= (n / I) * 2),
                    i[0] > h && (i[0] = h),
                    i[0] < d && (i[0] = d),
                    i[1] > p && (i[1] = p),
                    i[1] < P && (i[1] = P),
                    cpvec3(i, l._item[0]._matrix._pos));
                break;
              case SCRN_HEMISPHERE:
                cpvec3(l._item[0]._matrix._scale, i),
                  cpvec3(l._item[0]._matrix._rotate, a),
                  f
                    ? ((h = 60 - 60 / i[1] / 2),
                      (d = -h),
                      (p = 30 - 60 / i[0] / 2),
                      (P = -p),
                      (a[0] = a[0] + ((t - m) / I) * 90),
                      (a[1] = a[1] + ((e - A) / M) * 90),
                      a[1] > h + 20 && (a[1] = h + 20),
                      a[1] < d - 20 && (a[1] = d - 20))
                    : ((p = 90 - 60 / i[1] / 2),
                      (a[(P = 0)] = a[0] + ((t - m) / I) * 90),
                      (a[2] = a[2] + ((e - A) / M) * 90)),
                  a[0] > p + 10 && (a[0] = p + 10),
                  a[0] < P - 10 && (a[0] = P - 10),
                  cpvec3(a, l._item[0]._matrix._rotate);
                break;
              case SCRN_CYLINDER:
                cpvec3(l._item[0]._matrix._scale, _),
                  cpvec3(l._item[0]._matrix._rotate, o),
                  cpvec3(l._item[0]._matrix._texscale, c),
                  cpvec3(l._item[0]._matrix._texpos, s),
                  Math.abs(e - A) < 20 &&
                    20 < Math.abs(t - u) &&
                    ((c[0] += (10 * (m - t)) / I),
                    c[0] < 1 && (c[0] = 1),
                    6 < c[0] && (c[0] = 6),
                    (o[0] = 6 * (c[0] - 1) - 30),
                    (_ = vec3(
                      1 + 0.1 * (c[0] - 1),
                      1 + 0.1 * (c[0] - 1),
                      1 + 0.1 * (c[0] - 1)
                    )),
                    cpvec3(c, l._item[0]._matrix._texscale),
                    cpvec3(o, l._item[0]._matrix._rotate),
                    cpvec3(_, l._item[0]._matrix._scale)),
                  (s[0] -= (e - A) / M),
                  cpvec3(s, l._item[0]._matrix._texpos);
                break;
              case SCRN_UPDOWN:
                cpvec3(l._item[O]._matrix._texpos, s),
                  (s[0] -= (2 * (e - A)) / M),
                  cpvec3(s, l._item[O]._matrix._texpos);
                break;
              case SCRN_FOUR:
                0 <= O &&
                  (cpvec3(l._item[O]._matrix._rotate, a),
                  cpvec3(l._item[O]._matrix._scale, i),
                  (p = 90 - (60 - 100 * (i[1] - 1) * 8) / 2),
                  (a[(P = 0)] = a[0] + ((t - m) / I) * 90),
                  (a[2] = a[2] + ((e - A) / M) * 90),
                  a[0] > p + 10 && (a[0] = p + 10),
                  a[0] < P - 10 && (a[0] = P - 10),
                  cpvec3(a, l._item[O]._matrix._rotate));
            }
            (A = e), (m = t);
          }
        }),
        (this.TapOrMouseUp = function (e, t) {
          new Float32Array(3);
          var r,
            n = new Float32Array(3),
            i = new Float32Array(3),
            a = new Float32Array(3),
            _ = new Float32Array(3),
            o = new Float32Array(3),
            c = v[E],
            s = R;
          switch (E) {
            case SCRN_NORMAL:
              cpvec3(c._item[0]._matrix._scale, i),
                1.00001 < i[0] &&
                  (cpvec3(c._item[0]._matrix._pos, n),
                  (r = S() - f) < 1500 &&
                    100 < r &&
                    30 < Math.abs(e - l) &&
                    ((n[0] += (e - l) / M / (r / 1e3)),
                    (n[1] -= (t - u) / I / (r / 1e3)),
                    n[0] > h && (n[0] = h),
                    n[0] < d && (n[0] = d),
                    n[1] > p && (n[1] = p),
                    n[1] < P && (n[1] = P),
                    g.StartAnimation(
                      n,
                      100,
                      !1,
                      TRANSFORM_TYPE_POSITION,
                      !1,
                      0,
                      !0,
                      null
                    )));
              break;
            case SCRN_HEMISPHERE:
              cpvec3(c._item[0]._matrix._rotate, n),
                s
                  ? (n[1] > h && (n[1] = h),
                    n[1] < d && (n[1] = d),
                    n[0] > p && (n[0] = p),
                    n[0] < P && (n[0] = P),
                    g.StartAnimation(
                      n,
                      100,
                      !1,
                      TRANSFORM_TYPE_ROTATE,
                      !1,
                      0,
                      !0,
                      null
                    ))
                  : (n[0] > p && (n[0] = p),
                    n[0] < P && (n[0] = P),
                    (r = S() - f),
                    30 < Math.abs(e - l) &&
                      ((n[2] += ((e - l) / M / (r / 1e3)) * 180),
                      g.StartAnimation(
                        n,
                        100,
                        !1,
                        TRANSFORM_TYPE_ROTATE,
                        !1,
                        0,
                        !0,
                        null
                      )));
              break;
            case SCRN_CYLINDER:
              cpvec3(c._item[0]._matrix._texpos, n),
                cpvec3(c._item[0]._matrix._scale, i),
                cpvec3(c._item[0]._matrix._rotate, a),
                cpvec3(c._item[0]._matrix._texscale, _),
                cpvec3(c._item[0]._matrix._texpos, o),
                (r = S() - f) < 1500 &&
                  0 < r &&
                  (n[0] -= ((e - l) / M / (r / 1e3)) * 2),
                g.StartAnimation(
                  n,
                  100,
                  !1,
                  TRANSFORM_TYPE_POSITION,
                  !0,
                  0,
                  !0,
                  null
                ),
                1 != _[0] &&
                  6 != _[0] &&
                  ((i =
                    _[0] < 1.3
                      ? ((_[0] = 1), (a[0] = -30), vec3(1, 1, 1))
                      : ((_[0] = 6), (a[0] = 0), vec3(1.5, 1.5, 1.5))),
                  g.StartAnimation(
                    _,
                    100,
                    !1,
                    TRANSFORM_TYPE_SCALE,
                    !0,
                    0,
                    !0,
                    null
                  ),
                  g.StartAnimation(
                    a,
                    100,
                    !1,
                    TRANSFORM_TYPE_ROTATE,
                    !1,
                    0,
                    !0,
                    null
                  ),
                  g.StartAnimation(
                    i,
                    100,
                    !1,
                    TRANSFORM_TYPE_SCALE,
                    !1,
                    0,
                    !0,
                    null
                  ));
              break;
            case SCRN_UPDOWN:
              cpvec3(c._item[O]._matrix._texpos, n),
                (r = S() - f) < 1500 &&
                  0 < r &&
                  (n[0] -= ((e - l) / M / (r / 1e3)) * 2),
                g.StartAnimation(
                  n,
                  100,
                  !1,
                  TRANSFORM_TYPE_POSITION,
                  !0,
                  O,
                  !0,
                  null
                );
              break;
            case SCRN_FOUR:
              0 <= O &&
                (cpvec3(c._item[O]._matrix._rotate, n),
                n[0] > p && (n[0] = p),
                n[0] < P && (n[0] = P),
                (r = S() - f) < 1500 &&
                  0 < r &&
                  30 < Math.abs(e - l) &&
                  ((n[2] += ((e - l) / M / (r / 1e3)) * 180),
                  g.StartAnimation(
                    n,
                    100,
                    !1,
                    TRANSFORM_TYPE_ROTATE,
                    !1,
                    O,
                    !0,
                    null
                  )));
          }
          (f = 0), (O = u = l = m = A = -1);
        }),
        (this.SetWallmode = function (e) {
          R = e;
        }),
        (this.tick = function () {
          for (var e, t, r, n = v[E], i = T.length - 1; 0 <= i; i--) {
            switch (
              ((ani = T[i])._Inertia
                ? ((t = Math.PI / 180),
                  (r =
                    Math.sin(t * ani._stepcount * (90 / ani._step)) *
                    (ani._end[0] - ani._start[0])),
                  (e =
                    Math.sin(t * ani._stepcount * (90 / ani._step)) *
                    (ani._end[1] - ani._start[1])),
                  (t =
                    Math.sin(t * ani._stepcount * (90 / ani._step)) *
                    (ani._end[2] - ani._start[2])),
                  (ani._value = addvec3(ani._start, vec3(r, e, t))))
                : (ani._value = addvec3(ani._value, ani._unit)),
              ani._type)
            ) {
              case TRANSFORM_TYPE_POSITION:
                ani._istexture
                  ? cpvec3(ani._value, n._item[ani._index]._matrix._texpos)
                  : cpvec3(ani._value, n._item[ani._index]._matrix._pos);
                break;
              case TRANSFORM_TYPE_SCALE:
                ani._istexture
                  ? cpvec3(ani._value, n._item[ani._index]._matrix._texscale)
                  : cpvec3(ani._value, n._item[ani._index]._matrix._scale);
                break;
              case TRANSFORM_TYPE_ROTATE:
                ani._istexture
                  ? cpvec3(ani._value, n._item[ani._index]._matrix._texrotate)
                  : cpvec3(ani._value, n._item[ani._index]._matrix._rotate);
            }
            ani._stepcount++,
              ani._stepcount >= ani._step &&
                !ani._isloop &&
                (null != ani._onEnd && ani._onEnd(ani),
                -1 < (r = T.indexOf(ani)) && T.splice(r, 1));
          }
          g.DrawSelf(), window.setTimeout(g.tick, 40);
        }),
        (this.ClearAnimation = function () {
          T = [];
        }),
        window.setTimeout(this.tick, 40);
    };
    (window.CryptoJS = e()),
      (window.p2papi = r),
      (window.ConnectApi = r),
      (window.kp2pPlayer = function (e, b, t, r) {
        var U,
          d,
          P,
          n,
          h = e,
          F = this,
          v = null,
          i = null,
          B = b,
          a = null,
          E = null,
          p = null,
          R = 0,
          H = 0,
          Y = 0,
          V = 0,
          X = 0,
          _ = 0,
          K = 0,
          z = 0,
          o = !1,
          T = document.createElement("canvas"),
          c =
            ((T.visible = !1),
            (this.OnTooManyFrames = null),
            (this.OnNeedFrames = null)),
          s = !1,
          l = !1,
          G = t,
          f = [],
          q = 40,
          u = 1,
          A = !0,
          Q = 0,
          m = 0,
          W = -1,
          O = null,
          g = !1,
          y = "snapshot.png",
          C = 0,
          M = 0,
          I = null,
          S = ((this.winIndex = t), 0),
          w = 0,
          x = { callback: null, index: 0 },
          N = null;
        function D() {
          O
            ? p.drawImage(O, 0, 0, O.width, O.height, 0, 0, h.width, h.height)
            : (((O = new Image()).src = "logo_bg.png"),
              O.addEventListener("load", function () {
                p.drawImage(
                  O,
                  0,
                  0,
                  O.width,
                  O.height,
                  0,
                  0,
                  h.width,
                  h.height
                );
              }));
        }
        function k() {
          return new Date().valueOf();
        }
        function L() {
          if (A) {
            f.length < 100 && null != c && !s && l && (c(G), (l = !(s = !0)));
            var e = q,
              t = 40;
            if (!o) {
              if (0 < f.length) {
                var r = new Date().getTime(),
                  n = f.shift();
                if (
                  ((m = n.timestamp),
                  (U = k()),
                  (F.codec = n.encode),
                  "H264" == n.encode)
                ) {
                  S &&
                    n.frame_width &&
                    (n.frame_width != S || n.frame_height != w) &&
                    ((a = null),
                    ((a = new Decoder({ rgb: null == v })).onPictureDecoded =
                      P)),
                    (S = n.frame_width),
                    (w = n.frame_height);
                  try {
                    a.decode(n.frame);
                  } catch (e) {}
                } else
                  "H265" == n.encode &&
                    (S &&
                      n.frame_width &&
                      (n.frame_width != S || n.frame_height != w) &&
                      E &&
                      E.reset(),
                    (S = n.frame_width),
                    (w = n.frame_height),
                    (n = E.push_data(n.frame)),
                    libde265.de265_isOK(n) && E.decode(function (e) {}));
                n = new Date().getTime();
                K < (t = n - r) ? (K = t) : (t < _ || _ <= 0) && (_ = t),
                  W < 0 && (W = k()),
                  0;
              }
              (100 < (e = 0 < f.length ? f[0].timestamp - m - t : e) ||
                e < 0) &&
                (e = 0);
            }
            A
              ? 0 == Q
                ? window.setTimeout(L, 10)
                : window.setTimeout(L, e * u)
              : ((f = []), null != v && v.ClearTexture());
          } else D();
        }
        r &&
        null !=
          (r =
            e.getContext("webgl", { preserveDrawingBuffer: !0 }) ||
            e.getContext("experimental-webgl", { preserveDrawingBuffer: !0 }))
          ? (v = new j(r))
          : (p = e.getContext("2d")),
          b
            ? ((i = new Worker("Decoder.js")).addEventListener(
                "message",
                function (e) {
                  e = e.data;
                  e.consoleLog ||
                    v.LoadTexture(new Uint8Array(e.buf), e.width, e.height);
                }
              ),
              i.postMessage({
                type: "Broadway.js - Worker init",
                options: { rgb: !1 },
              }))
            : ((d = this),
              (P = function (e, t, r, n, i) {
                0;
                var a,
                  _,
                  o,
                  c,
                  s,
                  l,
                  f = new Date().getTime(),
                  u = f - V;
                H <= u ? (H = u) : (0 == R || u <= R) && (R = u),
                  Y++,
                  (0 == t && 0 == r) ||
                    (null != v
                      ? v.LoadTexture(new Uint8Array(e), t, r)
                      : ((u = T.getContext("2d")),
                        "H264" == d.codec
                          ? ((f = u.createImageData(t, r)).data.set(e),
                            u.putImageData(f, 0, 0),
                            T.width != t && ((T.width = t), (T.height = r)))
                          : u.putImageData(e, 0, 0),
                        p.drawImage(
                          T,
                          0,
                          0,
                          T.width,
                          T.height,
                          0,
                          0,
                          h.width,
                          h.height
                        )),
                    g &&
                      ((f = d.codec),
                      (u = e),
                      (e = t),
                      (t = r),
                      (g = !1),
                      (r = document.createElement("a")),
                      (a = "image/png"),
                      (a =
                        -1 < y.indexOf("jpg") || -1 < y.indexOf("jpeg")
                          ? "image/jpeg"
                          : "image/png"),
                      (c = ""),
                      (s = document.createElement("canvas")),
                      C && M
                        ? ((s.width = e),
                          (s.height = t),
                          (_ = s.getContext("2d")),
                          "H264" == f
                            ? ((o = _.createImageData(e, t)).data.set(u),
                              _.putImageData(o, 0, 0))
                            : _.putImageData(u, 0, 0),
                          ((l = document.createElement("canvas")).width = C),
                          (l.height = M),
                          l
                            .getContext("2d")
                            .drawImage(s, 0, 0, s.width, s.height, 0, 0, C, M),
                          (c = l.toDataURL(a)),
                          (M = C = 0))
                        : ((s.width = e),
                          (s.height = t),
                          (_ = s.getContext("2d")),
                          "H264" == f
                            ? ((o = _.createImageData(e, t)).data.set(u),
                              _.putImageData(o, 0, 0))
                            : _.putImageData(u, 0, 0),
                          (c = s.toDataURL(a))),
                      I
                        ? (I(c), (I = null))
                        : ((r.href = c),
                          (r.download = y),
                          document.body.appendChild(r),
                          r.click(),
                          document.body.removeChild(r),
                          (y = "snapshot.png"))),
                    d.setDecodeTime(k() - U),
                    d.setPlaybackTime(m));
              }),
              ((a = new Decoder({ rgb: null == v })).onPictureDecoded = P),
              window.H265decoder || (window.H265decoder = []),
              window.H265decoder[t] && window.H265decoder[t].free(),
              (window.H265decoder[t] = new libde265.Decoder()),
              (E = window.H265decoder[t]).set_image_callback(function (e) {
                var t = e.get_width(),
                  r = e.get_height();
                if (null != v) {
                  var n = new Uint8Array(t * r * 1.5);
                  E.merge_yuv(e, n), P(n, t, r);
                } else {
                  if (T.width != t) {
                    (T.width = t),
                      (T.height = r),
                      (d.imagedata = T.getContext("2d").createImageData(t, r));
                    for (var i = d.imagedata.data, a = 0; a < t * r; a++)
                      i[4 * a + 3] = 255;
                  }
                  var n = libde265.de265_get_chroma_format(e.img),
                    _ = libde265.malloc(4),
                    o = libde265.de265_get_image_plane(e.img, 0, _),
                    c = libde265.getValue(_, "i32"),
                    s = libde265.de265_get_bits_per_pixel(e.img, 0),
                    l = libde265.de265_get_image_plane(e.img, 1, _),
                    f = libde265.getValue(_, "i32"),
                    u = libde265.de265_get_bits_per_pixel(e.img, 1),
                    h = libde265.de265_get_image_plane(e.img, 2, _),
                    p = libde265.getValue(_, "i32"),
                    e = libde265.de265_get_bits_per_pixel(e.img, 2);
                  libde265.free(_),
                    E.convert_yuv2rgb(
                      n,
                      o,
                      l,
                      h,
                      t,
                      r,
                      c,
                      f,
                      p,
                      s,
                      u,
                      e,
                      d.imagedata,
                      function (e) {
                        P(e, t, r, 0, 0);
                      }
                    );
                }
              })),
          null != v &&
            (h.addEventListener(
              "mousedown",
              function (e) {
                v.TapOrMouseDown(e.offsetX, e.offsetY);
              },
              !1
            ),
            h.addEventListener(
              "mouseup",
              function (e) {
                v.TapOrMouseUp(e.offsetX, e.offsetY);
              },
              !1
            ),
            h.addEventListener(
              "mousemove",
              function (e) {
                v.TapOrMouseMove(e.offsetX, e.offsetY);
              },
              !1
            ),
            (n = {}),
            h.addEventListener(
              "touchstart",
              function (e) {
                (e = e.touches[0]),
                  (e = new MouseEvent("mousedown", {
                    clientX: e.clientX,
                    clientY: e.clientY,
                  }));
                h.dispatchEvent(e);
              },
              !1
            ),
            h.addEventListener(
              "touchend",
              function (e) {
                var t = new MouseEvent("mouseup", n);
                h.dispatchEvent(t);
              },
              !1
            ),
            h.addEventListener(
              "touchmove",
              function (e) {
                (e = e.touches[0]),
                  (n.clientX = e.clientX),
                  (n.clientY = e.clientY),
                  (e = new MouseEvent("mousemove", {
                    clientX: e.clientX,
                    clientY: e.clientY,
                  }));
                h.dispatchEvent(e);
              },
              !1
            )),
          D(),
          (this.fillframe = function (e, t, r) {
            var n;
            0 == X && (X = new Date().getTime()),
              B
                ? "H264" == r &&
                  ((n = new Uint8Array(e.length)).set(e, 0, e.length),
                  i.postMessage({ buf: n.buffer, time: new Date().getTime() }, [
                    n.buffer,
                  ]))
                : "H264" == r
                ? a.decode(e)
                : "H265" == r &&
                  ((n = E.push_data(e)),
                  libde265.de265_isOK(n) && E.decode(function (e) {}));
          }),
          (this.fillframe_v2 = function (e, t, r, n, i, a) {
            A &&
              (z++,
              f.push({
                frame: e,
                frame_len: t,
                encode: r,
                timestamp: n,
                index: z,
                frame_width: i,
                frame_height: a,
              }),
              200 < f.length &&
                (null == this.OnTooManyFrames ||
                  l ||
                  (this.OnTooManyFrames(G), (s = !(l = !0)))));
          }),
          (this.LogPlayInfo = function () {
            0 < Y && 0;
          }),
          (this.pauseDecode = function () {
            o = !0;
          }),
          (this.continueDecode = function () {
            o = !1;
          }),
          (this.fast = function () {
            u <= 0 || (u <= 0.125 ? (u = 0) : (u /= 2));
          }),
          (this.slow = function () {
            4 <= u || (u <= 0 ? (u = 0.25) : (u *= 2));
          }),
          (this.reset = function () {
            u = 1;
          }),
          (this.close = function () {
            (A = !1),
              (g = !(f = [])),
              (y = "snapshot.png"),
              (M = C = 0),
              E && E.reset(),
              (a = null),
              ((a = new Decoder({ rgb: null == v })).onPictureDecoded = P),
              window.H265decoder[t] && window.H265decoder[t].free(),
              (window.H265decoder[t] = new libde265.Decoder()),
              (E = window.H265decoder[t]).set_image_callback(function (e) {
                var t = e.get_width(),
                  r = e.get_height();
                if (null != v) {
                  var n = new Uint8Array(t * r * 1.5);
                  E.merge_yuv(e, n), P(n, t, r);
                } else {
                  if (T.width != t) {
                    (T.width = t),
                      (T.height = r),
                      (d.imagedata = T.getContext("2d").createImageData(t, r));
                    for (var i = d.imagedata.data, a = 0; a < t * r; a++)
                      i[4 * a + 3] = 255;
                  }
                  var n = libde265.de265_get_chroma_format(e.img),
                    _ = libde265.malloc(4),
                    o = libde265.de265_get_image_plane(e.img, 0, _),
                    c = libde265.getValue(_, "i32"),
                    s = libde265.de265_get_bits_per_pixel(e.img, 0),
                    l = libde265.de265_get_image_plane(e.img, 1, _),
                    f = libde265.getValue(_, "i32"),
                    u = libde265.de265_get_bits_per_pixel(e.img, 1),
                    h = libde265.de265_get_image_plane(e.img, 2, _),
                    p = libde265.getValue(_, "i32"),
                    e = libde265.de265_get_bits_per_pixel(e.img, 2);
                  libde265.free(_),
                    E.convert_yuv2rgb(
                      n,
                      o,
                      l,
                      h,
                      t,
                      r,
                      c,
                      f,
                      p,
                      s,
                      u,
                      e,
                      d.imagedata,
                      function (e) {
                        P(e, t, r, 0, 0);
                      }
                    );
                }
              });
          }),
          (this.cleanFrame = function () {
            (f = []), E && E.reset();
          }),
          (this.open = function () {
            (A = !0), (f = []), (c = this.OnNeedFrames), L(this.OnNeedFrames);
          }),
          (this.SetStreamMode = function (e) {
            Q = e;
          }),
          (this.GetVersion = function () {
            return "1.0.0.0";
          }),
          (this.LogPlayInfo_v2 = function () {}),
          (this.Snapshot = function (e, t, r, n, i) {
            var a, _, o;
            t && (y = t),
              1 === e
                ? (r && ((C = r), (M = n)), i && (I = i), (g = !0))
                : ((t = r),
                  (e = n),
                  (r = i),
                  (n = document.createElement("a")),
                  (i = "image/png"),
                  (o = ""),
                  (i =
                    -1 < y.indexOf("jpg") || -1 < y.indexOf("jpeg")
                      ? "image/jpeg"
                      : "image/png"),
                  (o =
                    t && e
                      ? ((_ = (a = document.createElement("canvas")).getContext(
                          "2d"
                        )),
                        (a.width = t),
                        (a.height = e),
                        _.drawImage(h, 0, 0, h.width, h.height, 0, 0, t, e),
                        a.toDataURL(i))
                      : h.toDataURL(i)),
                  r
                    ? r(o)
                    : ((n.href = o),
                      (n.download = y),
                      document.body.appendChild(n),
                      n.click(),
                      document.body.removeChild(n),
                      (y = "snapshot.png")));
          }),
          (this.renderBackground = function () {
            D();
          }),
          (this.setDecodeTimeCallback = function (e, t) {
            (x.callback = t), (x.index = e);
          }),
          (this.setDecodeTime = function (e) {
            x.callback && x.callback(x.index, e);
          }),
          (this.setPlaybackTimeCallback = function (e) {
            N = e;
          }),
          (this.setPlaybackTime = function (e) {
            N && N(e);
          });
      });
  })();
})();
