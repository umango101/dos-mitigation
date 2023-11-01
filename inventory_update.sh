#!/bin/bash

if [ ! -f .settings ]; then
    cp settings .settings
fi
source .settings

cp mrg_hosts hosts
cp mrg_etchosts etchosts
echo "[active_clients]" >> hosts
for (( i=0; i<n_clients; i++ )); do
    echo "c$i" >> hosts
done

echo "[active_attackers]" >> hosts
for (( i=0; i<n_attackers; i++ )); do
    echo "a$i" >> hosts
done

echo "[syn_pow_verifier]" >> hosts
if [[ "$syn_pow_verifier" == "firewall" ]]; then
    echo "r0" >> hosts
elif [[ "$syn_pow_verifier" == "edge_router" ]]; then
    echo "r1" >> hosts
    echo "r2" >> hosts
    echo "r3" >> hosts
else
    echo $syn_pow_verifier >> hosts
fi

echo "[all:vars]" >> hosts
cat .settings >> hosts
