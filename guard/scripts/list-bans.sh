#!/bin/bash
echo "=== Banlı IP Listesi (INPUT Chain) ==="
# Header'ı göster
sudo iptables -L INPUT -n -v | head -2
# Sadece DROP olanları göster
sudo iptables -L INPUT -n -v --line-numbers | grep DROP
echo "======================================"
