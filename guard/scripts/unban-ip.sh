#!/bin/bash
if [ -z "$1" ]; then
    echo "Kullanım: ./unban-ip.sh <IP_ADRESI>"
    exit 1
fi

IP=$1
sudo iptables -D INPUT -s $IP -j DROP

if [ $? -eq 0 ]; then
    echo "✅ Başarılı: $IP banı kaldırıldı."
else
    echo "❌ Hata: $IP kurallarda bulunamadı."
fi
