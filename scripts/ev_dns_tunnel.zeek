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
global dns_len_sum:   table[addr] of double &create_expire=5min;
global dns_len_sumsq: table[addr] of double &create_expire=5min;
global seen_txids:  table[addr] of set[count] &create_expire=30sec;

function process_query(c: connection, query: string)
    {
    if ( query == "" ) return;
    local src = c$id$orig_h;
    if ( src in dns_alerted ) return;

    local parts = split_string(query, /\./);
    if ( |parts| == 0 ) return;
    local label = parts[0];

    if ( src !in dns_total )
        {
        dns_total[src]    = 0;
        dns_labels[src]   = table();
        dns_len_sum[src]  = 0.0;
        dns_len_sumsq[src]= 0.0;
        }

    dns_total[src] += 1;
    if ( label !in dns_labels[src] ) dns_labels[src][label] = 0;
    dns_labels[src][label] += 1;
    dns_len_sum[src]   += |label|;
    dns_len_sumsq[src] += |label| * |label|;

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

    # Rule 1: Beacon
    if ( top1 > beacon_t1 )
        rule = fmt("beacon(top1=%.3f)", top1);

    # Rule 2: High unique ratio
    else if ( ur > ur_threshold )
        rule = fmt("high_ur(ur=%.3f>%.3f)", ur, ur_threshold);

    # Rule 3: DNS-shell — uniform label length, mid ur
    else if ( ur > 0.3 && ur < 0.7 )
        {
        local mean_len = dns_len_sum[src] / n;
        local variance = dns_len_sumsq[src] / n - mean_len * mean_len;
        local std_len  = sqrt(variance);
        if ( std_len < 1.5 && mean_len > 7.0 )
            rule = fmt("uniform_labels(len=%.1f,std=%.2f)", mean_len, std_len);
        }

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

event dns_query_reply(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    local src  = c$id$orig_h;
    local txid = msg$id;
    if ( src !in seen_txids ) seen_txids[src] = set();
    if ( txid in seen_txids[src] ) return;
    add seen_txids[src][txid];
    process_query(c, query);
    }
