@load base/protocols/dns
@load base/frameworks/notice

module EvDNSTunnel;

export {
    redef enum Notice::Type += { Tunnel_Detected };
    const min_queries:  count  = 50    &redef;
    const ur_threshold: double = 0.847 &redef;
    const beacon_t1:    double = 0.80  &redef;
}

global dns_labels:  table[addr] of table[string] of count &create_expire=5min;
global dns_total:   table[addr] of count &create_expire=5min;
global dns_alerted: set[addr] &create_expire=10min;

function process_query(c: connection, query: string)
    {
    if ( query == "" ) return;
    local src = c$id$orig_h;
    if ( src in dns_alerted ) return;

    local parts = split_string(query, /\./);
    if ( |parts| == 0 ) return;
    local label = parts[0];

    if ( src !in dns_total ) { dns_total[src]=0; dns_labels[src]=table(); }
    dns_total[src] += 1;
    if ( label !in dns_labels[src] ) dns_labels[src][label] = 0;
    dns_labels[src][label] += 1;

    local n = dns_total[src];
    if ( n < min_queries || n % min_queries != 0 ) return;

    local ur   = |dns_labels[src]| * 1.0 / n;
    local top1 = 0.0;
    for ( lbl in dns_labels[src] )
        {
        local freq = dns_labels[src][lbl] * 1.0 / n;
        if ( freq > top1 ) top1 = freq;
        }

    local rule = "";
    if ( top1 > beacon_t1 )
        rule = fmt("beacon(top1=%.3f)", top1);
    else if ( ur > ur_threshold )
        rule = fmt("high_ur(ur=%.3f>%.3f)", ur, ur_threshold);

    if ( rule != "" )
        {
        add dns_alerted[src];
        NOTICE([$note=Tunnel_Detected,
                $msg=fmt("DNS tunnel: src=%s %s n=%d", src, rule, n),
                $conn=c,
                $identifier=cat(src),
                $suppress_for=10min]);
        }
    }

# Standard queries (A, AAAA, CNAME, MX, TXT, SRV)
# Use dns_query_reply as PRIMARY — fires for ALL record types
# dns_request fires only for some types and may double-count
# Deduplication via transaction ID prevents double-counting
global seen_txids: table[addr] of set[count] &create_expire=30sec;

event dns_query_reply(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    local src = c$id$orig_h;
    local txid = msg$id;
    if ( src !in seen_txids ) seen_txids[src] = set();
    if ( txid in seen_txids[src] ) return;  # deduplicate
    add seen_txids[src][txid];
    process_query(c, query);
    }
