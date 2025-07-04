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
ns     IN       A       10.1.2.3
www    IN       A       10.1.2.155
www    IN       TXT     "ThisisaverylongTXTrecordmeanttosimulatealargeTXTrecordusedinDNSamplificationattacksThisisaverylongTXTrecordmeanttosimulatealargeTXTrecordusedinDNSamplificationattacksThisisaverylongTXTrecordmeanttosimulatealargeTXTrecordusedinDNSamplificationattacksThisis"
www    IN       TXT     "ThisisanotherverylongTXTrecordmeanttofurtheramplifythesizeoftheDNSAmplificationattackThisisanotherverylongTXTrecordmeanttofurtheramplifythesizeoftheDNSAmplificationattackThisisanotherverylongTXTrecordmeanttofurtheramplifythesizeoftheDNSAmplificationattack"
www    IN 	TXT 	"ThisisathirdveryverylongTXTrecordmeanttofurtheramplifytheattackflowinDNSAmplificationThisisathirdveryverylongTXTrecordmeanttofurtheramplifytheattackflowinDNSAmplificationThisisathirdveryverylongTXTrecordmeanttofurtheramplifytheattackflowinDNSAmplification"
www    IN	TXT	"ThisisafourthveryverylongTXTrecordmeanttofurtheramplifytheattackflowinDNSAmplificationThisisafourthveryverylongTXTrecordmeanttofurtheramplifytheattackflowinDNSAmplificationThisisafourthveryverylongTXTrecordmeanttofurtheramplifytheattackflowinDNSAmplificat"
www    IN	TXT	"ThisisafifthlargeTXTrecordtofullyamplifythesizeoftheDNSAmplificationattackThisisafifthlargeTXTrecordtofullyamplifythesizeoftheDNSAmplificationattackThisisafifthlargeTXTrecordtofullyamplifythesizeoftheDNSAmplificationattackThisisafifthlargeTXTrecordtofully"
www    IN       TXT     "ThisisasixthlargeTXTrecordtofullyamplifythesizeoftheDNSAmplificationattackThisisafifthlargeTXTrecordtofullyamplifythesizeoftheDNSAmplificationattackThisisafifthlargeTXTrecordtofullyamplifythesizeoftheDNSAmplificationattackThisisafifthlargeTXTrecordtofully"
www    IN       TXT     "ThisisasevenlargeTXTrecordtofullyamplifythesizeoftheDNSAmplificationattackThisisafifthlargeTXTrecordtofullyamplifythesizeoftheDNSAmplificationattackThisisafifthlargeTXTrecordtofullyamplifythesizeoftheDNSAmplificationattackThisisafifthlargeTXTrecordtofully"
www    IN       TXT     "ThisisaeightlargeTXTrecordtofullyamplifythesizeoftheDNSAmplificationattackThisisafifthlargeTXTrecordtofullyamplifythesizeoftheDNSAmplificationattackThisisafifthlargeTXTrecordtofullyamplifythesizeoftheDNSAmplificationattackThisisafifthlargeTXTrecordtofully"
