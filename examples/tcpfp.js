/*
 * Examples: reading $tcpfp_signature in njs.
 *
 * Every helper here gives a hint, never a verdict. A real visitor can show
 * any of them: corporate gateways (Zscaler, Netskope, Forcepoint) and
 * university networks rewrite TCP on Linux boxes, mobile carriers clamp the
 * MSS, iCloud Private Relay and VPNs change everything. Add them to a score
 * with other signals, measure them on your own traffic first, and treat a
 * missing signature (HTTP/3, no SYN saved) as "unknown", never as "clean".
 *
 *   js_import tcpfp from examples/tcpfp.js;
 *   js_set $tcpfp_hints tcpfp.hints;
 */

/*
 * "4:57+7:0:1460:mss*44,7:mss,sok,ts,nop,ws:df:0" -> object, or null.
 * Fields: ver:ttl+hops:olen:mss:wsize,scale:options:quirks:pclass
 */
function parse(sig) {
	if (!sig) return null;
	const f = String(sig).split(":");
	if (f.length !== 8) return null;
	const ttl = f[1].split("+");
	const w = f[4].split(",");
	const mss = parseInt(f[3], 10);
	const m = /^(mss|mtu)\*(\d+)$/.exec(w[0]);
	const hdr = f[0] === "6" ? 60 : 40;
	return {
		ver: parseInt(f[0], 10),
		ttl: parseInt(ttl[0], 10),
		hops: parseInt(ttl[1], 10),
		ittl: parseInt(ttl[0], 10) + parseInt(ttl[1], 10),
		olen: parseInt(f[2], 10),
		mss: mss,
		// back to the raw window
		win: m ? parseInt(m[2], 10) * (m[1] === "mss" ? mss : mss + hdr)
			: parseInt(w[0], 10),
		wscale: parseInt(w[1], 10),
		options: f[5],
		quirks: f[6] ? f[6].split(",") : [],
		data: f[7] === "+",
	};
}

/*
 * Operating system family of the stack that sent the SYN, from its initial
 * TTL and option layout. Rough on purpose: versions blur, and tuning (or a
 * NAT box) changes the details.
 */
function stackOs(fp) {
	if (!fp) return "unknown";
	if (fp.ittl === 128 && /^mss,nop,ws,nop,nop,sok$/.test(fp.options)) return "windows";
	if (fp.ittl === 64 && /^mss,nop,ws,nop,nop,ts,sok,eol\+\d+$/.test(fp.options)) return "apple";
	if (fp.ittl === 64 && /^mss,sok,ts,nop,ws$|^mss,nop,nop,sok,nop,ws$/.test(fp.options)) return "linux";
	return "unknown";
}

/* What the User-Agent claims, in the same families. */
function uaOs(ua) {
	ua = ua || "";
	if (/Windows NT/.test(ua)) return "windows";
	if (/iPhone|iPad|Macintosh|Mac OS X/.test(ua)) return "apple";
	if (/Android|Linux|CrOS/.test(ua)) return "linux";
	return "unknown";
}

/*
 * The User-Agent says one system, the SYN another: typically a residential
 * proxy or a scraping farm (Linux boxes announcing Windows). Also corporate
 * gateways and relays, see above.
 */
function osMismatch(fp, ua) {
	const s = stackOs(fp), u = uaOs(ua);
	return s !== "unknown" && u !== "unknown" && s !== u;
}

/*
 * Link the client's MSS points to. The MSS is the interface MTU minus the
 * IP and TCP headers (40 bytes in IPv4, 60 in IPv6), unless a box on the way
 * clamps it.
 *   ethernet  1500, the usual case
 *   pppoe     1492 (DSL, some fibre)
 *   ip-tunnel 1480 (6rd, 6in4: an IPv6 user of a 6rd ISP lands here)
 *   gre       1476
 *   wireguard 1420 (its default MTU)
 *   jumbo     above 1500: datacenter hosts (cloud instances run 9001)
 *   reduced   anything else below 1500: OpenVPN, IPsec, corporate links,
 *             and mobile carriers, which clamp the MSS
 */
function link(fp) {
	if (!fp || !fp.mss) return "unknown";
	const mtu = fp.mss + (fp.ver === 6 ? 60 : 40);
	switch (mtu) {
	case 1500: return "ethernet";
	case 1492: return "pppoe";
	case 1480: return "ip-tunnel";
	case 1476: return "gre";
	case 1420: return "wireguard";
	}
	return mtu > 1500 ? "jumbo" : "reduced";
}

/*
 * A SYN no ordinary stack sends: built by hand with a raw socket (scanners,
 * some bots). Returns the reasons, empty when none.
 */
function crafted(fp) {
	if (!fp) return [];
	const odd = ["0+", "seq-", "ack+", "uptr+", "urgf+", "ts1-", "opt+", "exws", "bad"];
	const why = fp.quirks.filter(q => odd.indexOf(q) !== -1);
	if (fp.options === "") why.push("no-options");
	else if (fp.options === "mss" && fp.win <= 4096) why.push("tiny-window");
	if (fp.ittl === 32 || fp.ittl === 255) why.push("ttl-" + fp.ittl);
	return why;
}

/*
 * TLS 1.3 round trip well above the TCP one: TCP ends at a relay close to
 * the server, TLS goes on to the real client farther away (CONNECT or SOCKS
 * proxy, residential proxy networks). Microseconds in, both from the module.
 * Mobile networks' transparent TCP proxies and slow devices (the client
 * checks the certificate inside that round trip) widen the gap too: keep the
 * margins wide.
 */
function tunnelled(tlsRtt, tcpRtt, ratio, gap) {
	const tls = parseInt(tlsRtt, 10), tcp = parseInt(tcpRtt, 10);
	if (!(tls > 0) || !(tcp > 0)) return false;
	return tls > tcp * (ratio || 3) && tls - tcp > (gap || 80000);
}

/*
 * Several stacks behind one address within a while: a NAT, a proxy pool or
 * a farm. Needs "js_shared_dict_zone zone=tcpfp:1m timeout=10m;" in http.
 * Returns how many operating system families the address showed.
 */
function stacksBehind(r, fp) {
	const dict = ngx.shared.tcpfp;
	const os = stackOs(fp);
	if (!dict || os === "unknown") return 0;
	const key = r.remoteAddress;
	const seen = (dict.get(key) || "").split(",").filter(Boolean);
	if (seen.indexOf(os) === -1) {
		seen.push(os);
		dict.set(key, seen.join(","));
	}
	return seen.length;
}

/* js_set handler: every hint of the connection, comma separated. */
function hints(r) {
	const v = r.variables;
	const fp = parse(v.tcpfp_signature);
	if (!fp) return "";
	const out = [];
	if (osMismatch(fp, r.headersIn["User-Agent"])) out.push("os-mismatch");
	const l = link(fp);
	if (l !== "ethernet" && l !== "pppoe") out.push("link-" + l);
	crafted(fp).forEach(w => out.push("crafted-" + w));
	if (tunnelled(v.tcpfp_tls_rtt, v.tcpfp_tcp_rtt)) out.push("rtt-gap");
	if (stacksBehind(r, fp) > 1) out.push("shared-address");
	return out.join(",");
}

export default { parse, stackOs, uaOs, osMismatch, link, crafted, tunnelled, stacksBehind, hints };
