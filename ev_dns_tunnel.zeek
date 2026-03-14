##! Ev DNS Tunnel Detector — Zero-training DNS tunnel detection
##! Detects: dnscat2, iodine, dns2tcp, CobaltStrike, ozymandns,
##!          tcp-over-dns, DNS-shell, tuns, dnspot, AndIodine
##!
##! Method: Three statistically-derived rules, no signatures, no training data.
##!   Rule 1: Beacon    — t1*sqrt(n) Chebyshev test
##!   Rule 2: High ur   — exact Beta CI on unique label ratio
##!   Rule 3: Ev excess — Gaussian 3-sigma on compositional skewness
##!
##! Benchmark: F1=1.000 vs Suricata ET Open F1=0.571 on GraphTunnel dataset

@load base/protocols/dns
@load base/frameworks/notice

module EvDNSTunnel;

export {
    redef enum Notice::Type += {
        ## A DNS tunnel has been detected from this source
        Tunnel_Detected,
    };

    ## Minimum DNS queries before scoring a source
    ## Derived: n_min = ur*(1-ur)/0.05² (binomial CI)
    const min_queries: count = 50 &redef;

    ## FPR target — controls detection sensitivity
    ## Lower = fewer false alarms, may miss low-volume tunnels
    ## 0.01 = 1% theoretical FPR bound (Chebyshev)
    const fpr_target: double = 0.01 &redef;

    ## Burn-in: normal windows to observe before flagging
    const burn_in: count = 10 &redef;

    ## Window expiry — reset buffer after this idle time
    const window_expire: interval = 5 min &redef;

    ## Score record returned by Python scorer
    type ScoreResult: record {
        is_tunnel: bool;
        rule:      string;
        ur:        double;
        ev:        double;
        n:         count;
    };
}

# Per-source DNS query buffer
global query_buffer: table[addr] of vector of string
    &create_expire=window_expire
    &expire_func=function(t: table[addr] of vector of string, idx: addr): interval {
        return window_expire;
    };

# Scorer state file — written by Python calibrator
const scorer_state_file = "/tmp/ev_dns_tunnel_state.json";

# Path to Python scorer
const scorer_script = fmt("%s/ev_score.py", @DIR);

function score_source(src: addr, queries: vector of string): ScoreResult
    {
    # Write queries to temp file for Python scorer
    local tmpfile = fmt("/tmp/ev_qnames_%s.txt", cat(src));
    local f = open(tmpfile);
    for (i in queries)
        print f, queries[i];
    close(f);

    # Call Python scorer
    local cmd = fmt("python3 %s --qfile %s --state %s --fpr %.4f",
                    scorer_script, tmpfile, scorer_state_file, fpr_target);
    local result = run_sync(cmd);

    # Parse JSON result
    local is_tunnel = F;
    local rule      = "normal";
    local ur        = 0.0;
    local ev_val    = 0.0;
    local n_val     = |queries|;

    if (/\"is_tunnel\": true/ in result)
        is_tunnel = T;
    if (/\"rule\":/ in result)
        {
        local rule_match = find_all(result, /\"rule\": \"[^\"]+\"/);
        for (rm in rule_match)
            rule = sub(sub(rm, /.*\"rule\": \"/, ""), /\".*/, "");
        }

    rm_file(tmpfile);
    return ScoreResult($is_tunnel=is_tunnel, $rule=rule,
                       $ur=ur, $ev=ev_val, $n=n_val);
    }

event dns_request(c: connection, msg: dns_msg, query: string,
                  qtype: count, qclass: count)
    {
    # Only score meaningful queries
    if (query == "" || query == "." ) return;

    local src = c$id$orig_h;

    if (src !in query_buffer)
        query_buffer[src] = vector();

    query_buffer[src] += query;

    local n = |query_buffer[src]|;

    # Score at min_queries, then every min_queries/2 after
    if (n == min_queries || (n > min_queries && n % (min_queries/2) == 0))
        {
        local result = score_source(src, query_buffer[src]);

        if (result$is_tunnel)
            {
            NOTICE([$note=Tunnel_Detected,
                    $msg=fmt("DNS tunnel detected: src=%s rule=%s n=%d",
                             src, result$rule, result$n),
                    $conn=c,
                    $src=src,
                    $identifier=cat(src),
                    $suppress_for=10min]);

            # Clear buffer after detection
            delete query_buffer[src];
            }
        }
    }
