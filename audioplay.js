(() => {
  "use strict";
  const i = [
      -5504, -5248, -6016, -5760, -4480, -4224, -4992, -4736, -7552, -7296,
      -8064, -7808, -6528, -6272, -7040, -6784, -2752, -2624, -3008, -2880,
      -2240, -2112, -2496, -2368, -3776, -3648, -4032, -3904, -3264, -3136,
      -3520, -3392, -22016, -20992, -24064, -23040, -17920, -16896, -19968,
      -18944, -30208, -29184, -32256, -31232, -26112, -25088, -28160, -27136,
      -11008, -10496, -12032, -11520, -8960, -8448, -9984, -9472, -15104,
      -14592, -16128, -15616, -13056, -12544, -14080, -13568, -344, -328, -376,
      -360, -280, -264, -312, -296, -472, -456, -504, -488, -408, -392, -440,
      -424, -88, -72, -120, -104, -24, -8, -56, -40, -216, -200, -248, -232,
      -152, -136, -184, -168, -1376, -1312, -1504, -1440, -1120, -1056, -1248,
      -1184, -1888, -1824, -2016, -1952, -1632, -1568, -1760, -1696, -688, -656,
      -752, -720, -560, -528, -624, -592, -944, -912, -1008, -976, -816, -784,
      -880, -848, 5504, 5248, 6016, 5760, 4480, 4224, 4992, 4736, 7552, 7296,
      8064, 7808, 6528, 6272, 7040, 6784, 2752, 2624, 3008, 2880, 2240, 2112,
      2496, 2368, 3776, 3648, 4032, 3904, 3264, 3136, 3520, 3392, 22016, 20992,
      24064, 23040, 17920, 16896, 19968, 18944, 30208, 29184, 32256, 31232,
      26112, 25088, 28160, 27136, 11008, 10496, 12032, 11520, 8960, 8448, 9984,
      9472, 15104, 14592, 16128, 15616, 13056, 12544, 14080, 13568, 344, 328,
      376, 360, 280, 264, 312, 296, 472, 456, 504, 488, 408, 392, 440, 424, 88,
      72, 120, 104, 24, 8, 56, 40, 216, 200, 248, 232, 152, 136, 184, 168, 1376,
      1312, 1504, 1440, 1120, 1056, 1248, 1184, 1888, 1824, 2016, 1952, 1632,
      1568, 1760, 1696, 688, 656, 752, 720, 560, 528, 624, 592, 944, 912, 1008,
      976, 816, 784, 880, 848,
    ],
    s = [
      -32124, -31100, -30076, -29052, -28028, -27004, -25980, -24956, -23932,
      -22908, -21884, -20860, -19836, -18812, -17788, -16764, -15996, -15484,
      -14972, -14460, -13948, -13436, -12924, -12412, -11900, -11388, -10876,
      -10364, -9852, -9340, -8828, -8316, -7932, -7676, -7420, -7164, -6908,
      -6652, -6396, -6140, -5884, -5628, -5372, -5116, -4860, -4604, -4348,
      -4092, -3900, -3772, -3644, -3516, -3388, -3260, -3132, -3004, -2876,
      -2748, -2620, -2492, -2364, -2236, -2108, -1980, -1884, -1820, -1756,
      -1692, -1628, -1564, -1500, -1436, -1372, -1308, -1244, -1180, -1116,
      -1052, -988, -924, -876, -844, -812, -780, -748, -716, -684, -652, -620,
      -588, -556, -524, -492, -460, -428, -396, -372, -356, -340, -324, -308,
      -292, -276, -260, -244, -228, -212, -196, -180, -164, -148, -132, -120,
      -112, -104, -96, -88, -80, -72, -64, -56, -48, -40, -32, -24, -16, -8, 0,
      32124, 31100, 30076, 29052, 28028, 27004, 25980, 24956, 23932, 22908,
      21884, 20860, 19836, 18812, 17788, 16764, 15996, 15484, 14972, 14460,
      13948, 13436, 12924, 12412, 11900, 11388, 10876, 10364, 9852, 9340, 8828,
      8316, 7932, 7676, 7420, 7164, 6908, 6652, 6396, 6140, 5884, 5628, 5372,
      5116, 4860, 4604, 4348, 4092, 3900, 3772, 3644, 3516, 3388, 3260, 3132,
      3004, 2876, 2748, 2620, 2492, 2364, 2236, 2108, 1980, 1884, 1820, 1756,
      1692, 1628, 1564, 1500, 1436, 1372, 1308, 1244, 1180, 1116, 1052, 988,
      924, 876, 844, 812, 780, 748, 716, 684, 652, 620, 588, 556, 524, 492, 460,
      428, 396, 372, 356, 340, 324, 308, 292, 276, 260, 244, 228, 212, 196, 180,
      164, 148, 132, 120, 112, 104, 96, 88, 80, 72, 64, 56, 48, 40, 32, 24, 16,
      8, 0,
    ];
  const o = {
    decodeAlaw: function (t) {
      const e = new Uint8Array(2 * t.length);
      let a = 0,
        n = 0;
      for (; a < t.length; ) {
        var r = i[t[a]];
        if (void 0 === r) throw new Error("can not decode g711 alaw data!");
        (e[n] = 255 & r), (e[n + 1] = r >> 8), (a += 1), (n += 2);
      }
      return e;
    },
    decodeUlaw: function (t) {
      const e = new Uint8Array(2 * t.length);
      let a = 0,
        n = 0;
      for (; a < t.length; ) {
        var r = s[t[a]];
        if (void 0 === r) throw new Error("can not decode g711 ulaw data!");
        (e[n] = 255 & r), (e[n + 1] = r >> 8), (a += 1), (n += 2);
      }
      return e;
    },
  };
  class e {
    constructor(t, e) {
      (this._samples = new Float32Array()),
        (this._flushingTime = 200),
        (this._channels = t),
        (this._sampleRate = e),
        (this._flush = this._flush.bind(this)),
        (this._audioCtx = new (window.AudioContext ||
          window.webkitAudioContext)()),
        (this._gainNode = this._audioCtx.createGain()),
        (this._gainNode.gain.value = 1),
        this._gainNode.connect(this._audioCtx.destination),
        (this._startTime = this._audioCtx.currentTime),
        (this._interval = setInterval(this._flush, this._flushingTime)),
        (this.pause = !1);
    }
    setVolume(t) {
      this._gainNode.gain.value = t;
    }
    close() {
      this._samples = new Float32Array();
    }
    pauseAudio() {
      this.pause = !0;
    }
    continueAudio() {
      this.pause = !1;
    }
    feed(t) {
      let e = new Float32Array(this._samples.length + t.length);
      e.set(this._samples, 0),
        e.set(t, this._samples.length),
        (this._samples = e);
    }
    _flush() {
      if (
        this._channels &&
        this._sampleRate &&
        this._samples.length &&
        !this.pause
      ) {
        let t = this._audioCtx.createBufferSource();
        var i = this._samples.length / this._channels;
        let r = this._audioCtx.createBuffer(
          this._channels,
          i,
          this._sampleRate
        );
        for (let t = 0; t != this._channels; ++t) {
          let e = r.getChannelData(t),
            a = t,
            n = 50;
          for (let t = 0; t != i; ++t)
            (e[t] = this._samples[a]),
              t < 50 && (e[t] = (e[t] * t) / 50),
              t >= i - 51 && (e[t] = (e[t] * n--) / 50),
              (a += this._channels);
        }
        this._startTime < this._audioCtx.currentTime &&
          (this._startTime = this._audioCtx.currentTime),
          (t.buffer = r),
          t.connect(this._gainNode),
          t.start(this._startTime),
          (this._startTime += r.duration),
          (this._samples = new Float32Array());
      }
    }
  }
  class u {
    constructor() {}
    static memmem(a, n, r) {
      for (let e = 0; e <= a.byteLength - r.byteLength - n; ++e) {
        let t = 0;
        for (; t != r.byteLength && a[e + t + n] == r[t]; ++t);
        if (t >= r.byteLength) return e + n;
      }
      return -1;
    }
    static memcmp(e, a, n) {
      for (let t = 0; t != n.byteLength; ++t) if (e[t + a] != n[t]) return -1;
      return 0;
    }
    static memcpy(t, e, a, n, r) {
      t.set(a.subarray(n, r), e);
    }
    static milliSecondTime() {
      return new Date().getTime();
    }
    static shortToFloatData(e) {
      var a = e.length;
      let n = new Float32Array(a);
      for (let t = 0; t != a; ++t) n[t] = e[t] / 32768;
      return n;
    }
    static floatToShortData(e) {
      var a = e.length;
      let n = new Int16Array(a);
      for (let t = 0; t != a; ++t) n[t] = 32768 * e[t];
      return n;
    }
    static downsampleBuffer(n, t, e) {
      if (t == e) return n;
      if (e < t) throw "rate > sampleRate error !!";
      var r = e / t,
        e = 65532 & Math.ceil(n.length / r);
      let i = new Float32Array(e),
        s = 0,
        o = 0;
      for (; s != i.length; ) {
        var l = o + r;
        let e = 0,
          a = 0;
        var u = Math.ceil(o),
          h = Math.ceil(l);
        for (let t = u; t != h && t != n.length; ++t) (e += n[t]), ++a;
        (i[s] = e / a), ++s, (o = l);
      }
      return i;
    }
  }
  class a {
    constructor(t, e, a, n, r = 20) {
      (this.data = t),
        (this.type = e),
        (this.time = a),
        (this.duration = r),
        (this.errorCode = n);
    }
    static makeErrorResult(t) {
      return new a(null, -1, -1, t);
    }
  }
  (a.ErrorCode = class {
    constructor() {}
  }),
    (a.ErrorCode.SUCCESS = 0),
    (a.ErrorCode.PARAM_ERROR = 1e3),
    (a.ErrorCode.PARAM_CHANGE = 2e3),
    (a.ErrorCode.FAIL = 3e3),
    (a.ErrorCode.NO_INIT_ERROR = a.ErrorCode.FAIL + 1),
    (a.ErrorCode.CACHE_MAX_ERROR = a.ErrorCode.FAIL + 2),
    (a.Type = class {
      constructor() {}
    }),
    (a.Type.H264_I_FRAME = 0),
    (a.Type.H264_P_FRAME = 1),
    (a.Type.H264_B_FRAME = 2),
    (a.Type.AUDIO = 3),
    (a.Type.TRANS_DATA = 4),
    (a.Type.FMP4_HEAD = 5),
    (a.Type.FMP4_BODY = 6);
  (class p {}), a, u;
  var l = {
    BIAS: 132,
    CLIP: 32635,
    tables: {
      ulaw: {
        compress: [
          0, 0, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4,
          4, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
          5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6,
          6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
          6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
          6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
          7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
          7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
          7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
          7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
          7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
          7, 7, 7,
        ],
        decompress: [
          -32124, -31100, -30076, -29052, -28028, -27004, -25980, -24956,
          -23932, -22908, -21884, -20860, -19836, -18812, -17788, -16764,
          -15996, -15484, -14972, -14460, -13948, -13436, -12924, -12412,
          -11900, -11388, -10876, -10364, -9852, -9340, -8828, -8316, -7932,
          -7676, -7420, -7164, -6908, -6652, -6396, -6140, -5884, -5628, -5372,
          -5116, -4860, -4604, -4348, -4092, -3900, -3772, -3644, -3516, -3388,
          -3260, -3132, -3004, -2876, -2748, -2620, -2492, -2364, -2236, -2108,
          -1980, -1884, -1820, -1756, -1692, -1628, -1564, -1500, -1436, -1372,
          -1308, -1244, -1180, -1116, -1052, -988, -924, -876, -844, -812, -780,
          -748, -716, -684, -652, -620, -588, -556, -524, -492, -460, -428,
          -396, -372, -356, -340, -324, -308, -292, -276, -260, -244, -228,
          -212, -196, -180, -164, -148, -132, -120, -112, -104, -96, -88, -80,
          -72, -64, -56, -48, -40, -32, -24, -16, -8, 0, 32124, 31100, 30076,
          29052, 28028, 27004, 25980, 24956, 23932, 22908, 21884, 20860, 19836,
          18812, 17788, 16764, 15996, 15484, 14972, 14460, 13948, 13436, 12924,
          12412, 11900, 11388, 10876, 10364, 9852, 9340, 8828, 8316, 7932, 7676,
          7420, 7164, 6908, 6652, 6396, 6140, 5884, 5628, 5372, 5116, 4860,
          4604, 4348, 4092, 3900, 3772, 3644, 3516, 3388, 3260, 3132, 3004,
          2876, 2748, 2620, 2492, 2364, 2236, 2108, 1980, 1884, 1820, 1756,
          1692, 1628, 1564, 1500, 1436, 1372, 1308, 1244, 1180, 1116, 1052, 988,
          924, 876, 844, 812, 780, 748, 716, 684, 652, 620, 588, 556, 524, 492,
          460, 428, 396, 372, 356, 340, 324, 308, 292, 276, 260, 244, 228, 212,
          196, 180, 164, 148, 132, 120, 112, 104, 96, 88, 80, 72, 64, 56, 48,
          40, 32, 24, 16, 8, 0,
        ],
      },
      alaw: {
        compress: [
          1, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5,
          5, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
          6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7,
          7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
          7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
          7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        ],
        decompress: [
          -5504, -5248, -6016, -5760, -4480, -4224, -4992, -4736, -7552, -7296,
          -8064, -7808, -6528, -6272, -7040, -6784, -2752, -2624, -3008, -2880,
          -2240, -2112, -2496, -2368, -3776, -3648, -4032, -3904, -3264, -3136,
          -3520, -3392, -22016, -20992, -24064, -23040, -17920, -16896, -19968,
          -18944, -30208, -29184, -32256, -31232, -26112, -25088, -28160,
          -27136, -11008, -10496, -12032, -11520, -8960, -8448, -9984, -9472,
          -15104, -14592, -16128, -15616, -13056, -12544, -14080, -13568, -344,
          -328, -376, -360, -280, -264, -312, -296, -472, -456, -504, -488,
          -408, -392, -440, -424, -88, -72, -120, -104, -24, -8, -56, -40, -216,
          -200, -248, -232, -152, -136, -184, -168, -1376, -1312, -1504, -1440,
          -1120, -1056, -1248, -1184, -1888, -1824, -2016, -1952, -1632, -1568,
          -1760, -1696, -688, -656, -752, -720, -560, -528, -624, -592, -944,
          -912, -1008, -976, -816, -784, -880, -848, 5504, 5248, 6016, 5760,
          4480, 4224, 4992, 4736, 7552, 7296, 8064, 7808, 6528, 6272, 7040,
          6784, 2752, 2624, 3008, 2880, 2240, 2112, 2496, 2368, 3776, 3648,
          4032, 3904, 3264, 3136, 3520, 3392, 22016, 20992, 24064, 23040, 17920,
          16896, 19968, 18944, 30208, 29184, 32256, 31232, 26112, 25088, 28160,
          27136, 11008, 10496, 12032, 11520, 8960, 8448, 9984, 9472, 15104,
          14592, 16128, 15616, 13056, 12544, 14080, 13568, 344, 328, 376, 360,
          280, 264, 312, 296, 472, 456, 504, 488, 408, 392, 440, 424, 88, 72,
          120, 104, 24, 8, 56, 40, 216, 200, 248, 232, 152, 136, 184, 168, 1376,
          1312, 1504, 1440, 1120, 1056, 1248, 1184, 1888, 1824, 2016, 1952,
          1632, 1568, 1760, 1696, 688, 656, 752, 720, 560, 528, 624, 592, 944,
          912, 1008, 976, 816, 784, 880, 848,
        ],
      },
    },
    encode: function (t, e) {
      e = e || {};
      for (
        var a = new ArrayBuffer(t.byteLength / 2),
          n = new Int8Array(a),
          a = e.alaw ? "alaw" : "ulaw",
          r = l[a],
          i = 0;
        i < t.byteLength / 2;
        i++
      )
        n[i] = r(t[i]);
      return n;
    },
    decode: function (t, e) {
      for (
        var a,
          n = !!(e = e || {}).floating_point,
          r = new ArrayBuffer(t.byteLength * (n ? 4 : 2)),
          i = new (n ? Float32Array : Int16Array)(r),
          s = l[(e.alaw ? "alaw" : "ulaw") + "_dec"],
          o = 0;
        o < t.byteLength;
        o++
      )
        (a = s(t[o])), (i[o] = n ? a / 32768 : a);
      return i;
    },
    alaw: function (t) {
      var e = new ArrayBuffer(2),
        a = new ArrayBuffer(1),
        e = new Int16Array(e),
        a = new Int8Array(a),
        n = (~t >> 8) & 128;
      return (
        128 != n && ((e[0] = -t), (t = e[0])),
        256 <= (t = t > l.CLIP ? l.CLIP : t)
          ? ((e = l.tables.alaw.compress[(t >> 8) & 127]),
            (a[0] = (e << 4) | ((t >> (e + 3)) & 15)))
          : (a[0] = t >> 4),
        (a[0] ^= 85 ^ n),
        a[0]
      );
    },
    alaw_dec: function (t) {
      var e = new ArrayBuffer(2),
        e = new Int8Array(e),
        t = l.tables.alaw.decompress[255 & t];
      return (e[0] = t), (e[1] = t >> 8), new Int16Array(e.buffer)[0];
    },
    alawdecode: function (t) {
      for (var e = new Int16Array(t.length), a = 0; a < t.length; a++)
        e[a] = l.alaw_dec(t[a]);
      return e;
    },
    alawencode: function (t) {
      for (var e = new Int8Array(t.length), a = 0; a < t.length; a++)
        e[a] = l.alaw(t[a]);
      return e;
    },
    ulaw: function (t) {
      var e = new ArrayBuffer(2),
        a = new ArrayBuffer(1),
        e = new Int16Array(e),
        a = new Int8Array(a),
        e =
          t < 0 ? ((e[0] = l.BIAS - t), (t = e[0]), 127) : ((t += l.BIAS), 255),
        n = l.tables.ulaw.compress[(t >> 8) & 127];
      return 8 <= n
        ? 127 ^ e
        : ((a[0] = (n << 4) | ((t >> (n + 3)) & 15)), a[0] ^ e);
    },
    ulaw_dec: function (t) {
      var e = new ArrayBuffer(2),
        e = new Int8Array(e),
        t = l.tables.ulaw.decompress[255 & t];
      return (e[0] = t), (e[1] = t >> 8), new Int16Array(e.buffer)[0];
    },
    ulaw_dec_slow: function (e) {
      var a = new ArrayBuffer(2),
        a = new Int16Array(a),
        a =
          ((a[0] = ~e),
          (e = a[0]),
          (t = ((15 & e) << 3) + l.BIAS),
          (t <<= (112 & e) >> 4),
          128 == (128 & e)),
        e = new ArrayBuffer(2),
        e = new Int16Array(e);
      return (e[0] = a ? l.BIAS - t : t - l.BIAS), e[0];
    },
  };
  const h = l;
  (window.URL = window.URL || window.webkitURL),
    void 0 === navigator.mediaDevices && (navigator.mediaDevices = {}),
    (window.G711 = h),
    (window.audioBufferSouceNode = null);
  new e(1, 8e3);
  function n(e, l) {
    let t = window.AudioContext || window.webkitAudioContext;
    const a = new t({ sampleRate: 8e3 });
    ((l = l || {}).channelCount = 1),
      (l.numberOfInputChannels = l.channelCount),
      (l.numberOfOutputChannels = l.channelCount),
      (l.sampleBits = l.sampleBits || 16),
      (l.sampleRate = l.sampleRate || 8e3),
      (l.bufferSize = 4096);
    let n = a.createMediaStreamSource(e);
    var r = a.createGain();
    n.connect(r);
    let i = a.createScriptProcessor(
        l.bufferSize,
        l.channelCount,
        l.channelCount
      ),
      s = {
        size: 0,
        buffer: [],
        buffer2: [],
        inputSampleRate: a.sampleRate,
        inputSampleBits: 16,
        outputSampleRate: l.sampleRate,
        oututSampleBits: l.sampleBits,
        input: function (t) {
          var t = u.floatToShortData(new Float32Array(t)),
            t = h.encode(t, { alaw: !0 }),
            e = h.decode(t, { alaw: !0 });
          u.shortToFloatData(e);
          l.inputCallback && l.inputCallback(t);
        },
        getRawData: function () {
          let e = new Float32Array(this.size),
            a = 0;
          for (let t = 0; t < this.buffer.length; t++)
            e.set(this.buffer[t], a), (a += this.buffer[t].length);
          var t = parseInt(this.inputSampleRate / this.outputSampleRate),
            n = e.length / t;
          let r = new Float32Array(n),
            i = 0,
            s = 0;
          for (; i < n; ) (r[i] = e[s]), (s += t), i++;
          return r;
        },
        covertWav: function () {
          var t = Math.min(this.inputSampleRate, this.outputSampleRate),
            e = Math.min(this.inputSampleBits, this.oututSampleBits),
            a = this.getRawData(),
            n = a.length * (e / 8),
            r = new ArrayBuffer(44 + n);
          let i = new DataView(r),
            s = 0;
          function o(t) {
            for (var e = 0; e < t.length; e++)
              i.setUint8(s + e, t.charCodeAt(e));
          }
          return (
            o("RIFF"),
            (s += 4),
            i.setUint32(s, 36 + n, !0),
            (s += 4),
            o("WAVE"),
            (s += 4),
            o("fmt "),
            (s += 4),
            i.setUint32(s, 16, !0),
            (s += 4),
            i.setUint16(s, 1, !0),
            (s += 2),
            i.setUint16(s, l.channelCount, !0),
            (s += 2),
            i.setUint32(s, t, !0),
            (s += 4),
            i.setUint32(s, l.channelCount * t * (e / 8), !0),
            (s += 4),
            i.setUint16(s, l.channelCount * (e / 8), !0),
            (s += 2),
            i.setUint16(s, e, !0),
            (s += 2),
            o("data"),
            (s += 4),
            i.setUint32(s, n, !0),
            (s += 4),
            (i = this.reshapeWavData(e, s, a, i))
          );
        },
        getFullWavData: function () {
          var t = this.covertWav();
          return new Blob([t], { type: "audio/wav" });
        },
        closeContext: function () {
          a.close();
        },
        reshapeWavData: function (t, e, a, n) {
          if (8 === t)
            for (let t = 0; t < a.length; t++, e++) {
              var r = Math.max(-1, Math.min(1, a[t])),
                r = r < 0 ? 32768 * r : 32767 * r,
                r = parseInt(255 / (65535 / (32768 + r)));
              n.setInt8(e, r, !0);
            }
          else
            for (let t = 0; t < a.length; t++, e += 2) {
              var i = Math.max(-1, Math.min(1, a[t]));
              n.setInt16(e, i < 0 ? 32768 * i : 32767 * i, !0);
            }
          return n;
        },
        getWavBuffer: function () {
          return this.covertWav().buffer;
        },
        getPcmBuffer: function () {
          let t = this.getRawData(),
            e = 0,
            a = this.oututSampleBits,
            n = t.length * (a / 8),
            r = new ArrayBuffer(n),
            i = new DataView(r);
          for (var s = 0; s < t.length; s++, e += 2) {
            var o = Math.max(-1, Math.min(1, t[s]));
            i.setInt16(e, o < 0 ? 32768 * o : 32767 * o, !0);
          }
          return new Blob([i]);
        },
        getPcmData: function () {
          let t = this.getRawData(),
            e = 0,
            a = this.oututSampleBits,
            n = t.length * (a / 8),
            r = new ArrayBuffer(n),
            i = new DataView(r);
          for (var s = 0; s < t.length; s++, e += 2) {
            var o = Math.max(-1, Math.min(1, t[s]));
            i.setInt16(e, o < 0 ? 32768 * o : 32767 * o, !0);
          }
          return i;
        },
        getframeData: function (t) {
          let e = new Float32Array(t.length);
          e.set(t, 0), t.length;
          var a = parseInt(this.inputSampleRate / this.outputSampleRate),
            n = e.length / a;
          let r = new Float32Array(n),
            i = 0,
            s = 0;
          for (; i < n; ) (r[i] = e[s]), (s += a), i++;
          let o = 0,
            l = this.oututSampleBits,
            u = r.length * (l / 8),
            h = new ArrayBuffer(u),
            f = new DataView(h);
          for (var c = 0; c < r.length; c++, o += 2) {
            var w = Math.max(-1, Math.min(1, r[c]));
            f.setInt16(o, w < 0 ? 32768 * w : 32767 * w, !0);
          }
          return f;
        },
        concatenate(t) {
          let e = 0;
          for (var a of t) e += a.byteLength;
          let n = new Uint8Array(e),
            r = 0;
          for (var i of t) {
            var s = new Uint8Array(i);
            n.set(s, r), (r += i.byteLength);
          }
          return n.buffer;
        },
      };
    (this.start = () => {
      n.connect(i), i.connect(a.destination);
    }),
      (this.getBlob = () => (this.stop(), s.getFullWavData())),
      (this.getBuffer = () => (this.stop(), s.getPcmBuffer())),
      (this.play = (t, e) => {
        (t.src = window.URL.createObjectURL(this.getBlob())),
          t.addEventListener("play", () => {
            this.draw(e);
          });
      }),
      (this.wavSrc = () => window.URL.createObjectURL(this.getBlob())),
      (this.aacSrc = () => s.getPcmData()),
      (this.getWavBuffer = () => s.getWavBuffer()),
      (this.pcmSrc = () => (
        this.stop(), window.URL.createObjectURL(this.getBuffer())
      )),
      (this.stop = () => {
        i.disconnect();
      }),
      (this.close = function () {
        s.closeContext();
        const t = e.getTracks();
        t[0].stop();
      }),
      (this.draw = function (o) {
        var t = s.getWavBuffer();
        a.decodeAudioData(t, (t) => {
          null != window.audioBufferSouceNode &&
            window.audioBufferSouceNode.stop(),
            (window.audioBufferSouceNode = a.createBufferSource()),
            (audioBufferSouceNode.buffer = t),
            ((gainNode = a.createGain()).gain.value = 2),
            audioBufferSouceNode.connect(gainNode);
          let n = a.createAnalyser(),
            r =
              ((n.fftSize = 256),
              gainNode.connect(n),
              n.connect(a.destination),
              audioBufferSouceNode.start(0),
              new Uint8Array(n.frequencyBinCount)),
            i = o.createLinearGradient(0, 0, 4, 200),
            s =
              (i.addColorStop(1, "pink"),
              i.addColorStop(0.5, "blue"),
              i.addColorStop(0, "red"),
              function () {
                var e = new Uint8Array(n.frequencyBinCount);
                n.getByteFrequencyData(e), o.clearRect(0, 0, 600, 200);
                for (let t = 0; t < e.length; t++) {
                  var a = e[t];
                  !r[t] || a > r[t] ? (r[t] = a) : --r[t],
                    o.fillRect(20 * t, 200 - a, 4, a),
                    o.fillRect(20 * t, 200 - r[t] - 6.6, 4, 3.3),
                    (o.fillStyle = i);
                }
                requestAnimationFrame(s);
              });
          s();
        });
      }),
      (i.onaudioprocess = (t) => {
        s.input(t.inputBuffer.getChannelData(0));
      });
  }
  n.get = (e, a) => {
    e &&
      (navigator.mediaDevices && navigator.mediaDevices.getUserMedia
        ? navigator.mediaDevices
            .getUserMedia({ audio: !0 })
            .then((t) => {
              t = new n(t, a);
              e(t);
            })
            .catch((t) => {})
        : alert("麦克风获取失败"));
  };
  var r = n;
  (window.JARecorder = r),
    (window.JASplitData = class {
      constructor() {
        (this._samples = new Uint8Array()),
          (this._flushingTime = 20),
          (this.getDataCallback = null),
          (this.outputData = null),
          (this._flush = this._flush.bind(this)),
          (this._interval = setInterval(this._flush, this._flushingTime)),
          (this.pause = !1);
      }
      close() {
        this._samples = new Uint8Array();
      }
      pauseAudio() {
        this.pause = !0;
      }
      continueAudio() {
        this.pause = !1;
      }
      feed(t) {
        let e = new Uint8Array(this._samples.length + t.length);
        e.set(this._samples, 0),
          e.set(t, this._samples.length),
          (this._samples = e);
      }
      _flush() {
        if (!(this._samples && this._samples.length < 160)) {
          let t = new Uint8Array(this._samples.length - 160);
          var e = new Uint8Array(this._samples.subarray(0, 160));
          t.set(this._samples.subarray(160), 0),
            (this._samples = t),
            this.outputData && this.outputData(e);
        }
      }
      setDataCallback(t) {
        this.outputData = t;
      }
    });
  let f = window.AudioContext || window.webkitAudioContext,
    c = f ? new f({ sampleRate: 8e3, latencyHint: "interactive" }) : "";
  let w = null,
    d = [];
  (w = new e(1, 8e3)),
    (window.audioPlay = function (e, a, t, n) {
      if (-1 < a.indexOf("G711")) {
        let t = new Uint8Array(e);
        320 != t.length && 160 != t.length && (t = t.subarray(36));
        (a = o.decodeAlaw(t)), (a = u.shortToFloatData(a));
        w.feed(a);
      } else if ((249 == e[1] && (e[1] = 241), d.length))
        if (d[0].length < 8) {
          var r = new Uint8Array(d[0].buffer),
            a = new ArrayBuffer(e.length + r.length);
          let t = new Uint8Array(a);
          for (i = 0; i < r.length; i++) t[i] = r[i];
          for (i = r.length; i < t.length; i++) t[i] = e[i - r.length];
          (d[0].buffer = a), (d[0].length = d[0].length + 1);
        } else {
          a = d[0].buffer;
          c.decodeAudioData(a).then(function (t) {
            t = t.getChannelData(0);
            w.feed(t);
          }),
            (d = []);
        }
      else {
        a = new ArrayBuffer(e.length);
        let t = new Uint8Array(a);
        for (var i = 0; i < t.length; i++) t[i] = e[i];
        d.push({ buffer: a, length: 1 });
      }
    }),
    (window.audioStop = function () {
      w && w.close();
    });
})();
