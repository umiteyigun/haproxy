#!/bin/bash
if [ -z "$1" ]; then
    echo "Kullanım: ./manual-ban.sh <IP_ADRESI>"
    exit 1
fi
IP=$1
sudo iptables -I INPUT -s $IP -j DROP
if [ $? -eq 0 ]; then
    echo "⛔ Başarılı: $IP manuel olarak banlandı."
else
    echo "❌ Hata oluştu."
fi
