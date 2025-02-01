;
; BIND data file for google.com
;
;
$TTL   604800
@      IN       SOA     ns.google.com. root.google.com. (
                             31          ; Serial
                             1h         ; Refresh
                             1d         ; Retry
                             1d         ; Expire
                             1w )       ; Negative Cache TTL
;
@      IN       NS      ns.google.com.
ns     10s      IN      A       10.1.2.3
www    10s      IN      A       10.1.2.155
