// Checks examples/tcpfp.js with typical SYNs.
// Usage:  njs -p examples t/examples.js

import fp from "tcpfp.js";

let fail = 0;

function eq(name, got, want) {
	got = JSON.stringify(got);
	want = JSON.stringify(want);
	if (got === want) {
		console.log("ok    " + name);
	} else {
		console.log("FAIL  " + name + ": got " + got + ", expected " + want);
		fail = 1;
	}
}

const windows = fp.parse("4:116+12:0:1460:mss*44,8:mss,nop,ws,nop,nop,sok:df:0");
const linux = fp.parse("4:52+12:0:1460:mss*44,7:mss,sok,ts,nop,ws:df:0");
const apple = fp.parse("4:56+8:0:1460:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0");
const scanner = fp.parse("4:241+14:0:1460:1024,0:mss::0");
const wg = fp.parse("4:55+9:0:1380:mss*46,7:mss,sok,ts,nop,ws:df:0");
const sixrd = fp.parse("6:58+6:0:1420:mss*45,7:mss,sok,ts,nop,ws:flow:0");

eq("parse", windows, {
	ver: 4, ttl: 116, hops: 12, ittl: 128, olen: 0, mss: 1460, win: 64240,
	wscale: 8, options: "mss,nop,ws,nop,nop,sok", quirks: ["df"], data: false,
});
eq("parse: mtu multiple", fp.parse("6:64+0:0:1440:mtu*2,0:mss::0").win, 3000);
eq("parse: garbage", fp.parse("nope"), null);
eq("parse: empty", fp.parse(""), null);

eq("stack: windows", fp.stackOs(windows), "windows");
eq("stack: linux", fp.stackOs(linux), "linux");
eq("stack: apple", fp.stackOs(apple), "apple");
eq("stack: unknown", fp.stackOs(scanner), "unknown");

const chromeWin = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36";
const safariMac = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Safari/605.1.15";
const chromeAndroid = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Mobile Safari/537.36";

eq("mismatch: Windows UA on Linux stack", fp.osMismatch(linux, chromeWin), true);
eq("mismatch: Windows UA on Windows stack", fp.osMismatch(windows, chromeWin), false);
eq("mismatch: Mac UA on Linux stack", fp.osMismatch(linux, safariMac), true);
eq("mismatch: Android UA on Linux stack", fp.osMismatch(linux, chromeAndroid), false);
eq("mismatch: unknown stack", fp.osMismatch(scanner, chromeWin), false);
eq("mismatch: no fingerprint", fp.osMismatch(null, chromeWin), false);

eq("link: ethernet", fp.link(windows), "ethernet");
eq("link: wireguard", fp.link(wg), "wireguard");
eq("link: IPv6 over 6rd", fp.link(sixrd), "ip-tunnel");
eq("link: pppoe", fp.link(fp.parse("4:64+0:0:1452:mss*44,7:mss,sok,ts,nop,ws:df:0")), "pppoe");
eq("link: jumbo", fp.link(fp.parse("4:64+0:0:8961:62727,7:mss,sok,ts,nop,ws:df:0")), "jumbo");
eq("link: reduced", fp.link(fp.parse("4:64+0:0:1360:mss*44,7:mss,sok,ts,nop,ws:df:0")), "reduced");

eq("crafted: browsers", [windows, linux, apple].map(fp.crafted), [[], [], []]);
eq("crafted: scanner", fp.crafted(scanner), ["tiny-window", "ttl-255"]);
eq("crafted: quirks", fp.crafted(fp.parse("4:64+0:0:1460:1024,0::seq-,ts1-:0")), ["seq-", "ts1-", "no-options"]);

eq("rtt: direct", fp.tunnelled("21000", "20000"), false);
eq("rtt: tunnel", fp.tunnelled("180000", "9000"), true);
eq("rtt: small gap", fp.tunnelled("12000", "2000"), false);
eq("rtt: missing", fp.tunnelled("", "9000"), false);

if (fail) throw new Error("examples: failures");
