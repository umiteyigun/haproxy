#!/bin/bash
if [ -z "$1" ]; then
    echo "Kullanım: ./add-whitelist.sh <IP_ADRESI>"
    exit 1
fi

IP=$1
GUARD_LIST="/root/haproxy/guard/whitelist.txt"
HAPROXY_LIST="/root/haproxy/haproxy/config.d/whitelist.lst"

# 1. Guard Whitelist Ekle
if grep -q "$IP" "$GUARD_LIST"; then
    echo "ℹ️  $IP zaten Guard Whitelist'te var."
else
    echo "$IP" >> "$GUARD_LIST"
    echo "✅ Guard Whitelist'e eklendi."
fi

# 2. HAProxy Whitelist Ekle
if grep -q "$IP" "$HAPROXY_LIST"; then
    echo "ℹ️  $IP zaten HAProxy Whitelist'te var."
else
    echo "$IP" >> "$HAPROXY_LIST"
    echo "✅ HAProxy Whitelist'e eklendi."
    
    # ACL update için HAProxy Reload (HUP signal)
    # Not: Dosyadan okunan ACL'ler için reload şart olmayabilir (http-request sc-inc yapıyorsak update olur) 
    # Ama ACL file update'leri reload gerektirir.
    docker kill -s HUP haproxy > /dev/null 2>&1
    echo "🔄 HAProxy Reload edildi."
fi
