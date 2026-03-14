##! Ev DNS Tunnel Detector — Zero-training DNS tunnel detection
##! Rule: ur > Beta_ppf(1-alpha, floor(ur_max*n)+1, n-floor(ur_max*n))
##! Beacon: t1*sqrt(n) > k*sigma (Chebyshev)

@load base/protocols/dns
@load base/frameworks/notice

module EvDNSTunnel;

export {
    redef enum Notice::Type += { Tunnel_Detected };
    const min_queries:  count  = 50    &redef;
    const ur_threshold: double = 0.847 &redef;  # Beta_ppf(0.99, ur_max*n+1, n-ur_max*n) at n=15000
    const beacon_t1:    double = 0.80  &redef;  # t1 threshold for beacon
}

global dns_labels:  table[addr] of table[string] of count &create_expire=5min;
global dns_total:   table[addr] of count &create_expire=5min;

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if ( query == "" ) return;
    local src = c$id$orig_h;
    local label = split_string(query, /\./)[0];

    if ( src !in dns_total )
        {
        dns_total[src] = 0;
        dns_labels[src] = table();
        }

    dns_total[src] += 1;
    if ( label !in dns_labels[src] )
        dns_labels[src][label] = 0;
    dns_labels[src][label] += 1;

    local n = dns_total[src];
    if ( n < min_queries ) return;

    local unique = |dns_labels[src]|;
    local ur     = unique * 1.0 / n;
    local top1   = 0.0;
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
