function FindProxyForURL(url, host) {
    host = host.toLowerCase();
    if (host === "granbluefantasy.jp" || dnsDomainIs(host, ".granbluefantasy.jp") ||
        host === "granbluefantasy.com" || dnsDomainIs(host, ".granbluefantasy.com") ||
        host === "mbga.jp" || dnsDomainIs(host, ".mbga.jp") ||
        host === "gbf.akamaized.net" ||
        host === "granbluefantasy.akamaized.net" ||
        host === "prd-game-a-granbluefantasy.akamaized.net" ||
        host === "prd-game-a1-granbluefantasy.akamaized.net" ||
        host === "prd-game-a2-granbluefantasy.akamaized.net" ||
        host === "prd-game-a3-granbluefantasy.akamaized.net" ||
        host === "prd-game-a4-granbluefantasy.akamaized.net" ||
        host === "prd-game-a5-granbluefantasy.akamaized.net") {
        return "PROXY 127.0.0.1:8124; DIRECT";
    }
    return "DIRECT";
}
