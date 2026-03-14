@load base/protocols/dns
@load base/frameworks/notice

module EvDNSTunnel;

export {
    redef enum Notice::Type += { Tunnel_Detected };
    const min_queries:  count  = 50    &redef;
    const ur_threshold: double = 0.847 &redef;
    const beacon_t1:    double = 0.80  &redef;
    const check_every:  count  = 50    &redef;
}

global dns_labels: table[addr] of table[string] of count &create_expire=5min;
global dns_total:  table[addr] of count &create_expire=5min;

function check_and_alert(src: addr, c: connection)
    {
    local n   = dns_total[src];
    if ( n < min_queries ) return;

    local ur  = |dns_labels[src]| * 1.0 / n;
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
        NOTICE([$note=Tunnel_Detected,
                $msg=fmt("DNS tunnel: src=%s rule=%s n=%d ur=%.3f",
                         src, rule, n, ur),
                $conn=c,
                $identifier=cat(src),
                $suppress_for=10min]);
        delete dns_labels[src];
        delete dns_total[src];
        }
    }

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if ( query == "" ) return;
    local src = c$id$orig_h;
    local parts = split_string(query, /\./);
    if ( |parts| == 0 ) return;
    local label = parts[0];

    if ( src !in dns_total ) { dns_total[src]=0; dns_labels[src]=table(); }
    dns_total[src] += 1;
    if ( label !in dns_labels[src] ) dns_labels[src][label] = 0;
    dns_labels[src][label] += 1;

    # Check every N queries
    if ( dns_total[src] % check_every == 0 )
        check_and_alert(src, c);
    }
