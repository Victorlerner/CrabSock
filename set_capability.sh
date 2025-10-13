#!/bin/bash

# Скрипт для установки capability на release версию
echo "Устанавливаем capability cap_net_admin=ep для release версии..."

sudo setcap cap_net_admin=ep /home/victor/PhpstormProjects/have-fun/CrabSock/src-tauri/target/release/crab-sock

if [ $? -eq 0 ]; then
    echo "Capability установлена успешно!"
    echo "Проверяем capability:"
    getcap /home/victor/PhpstormProjects/have-fun/CrabSock/ui/src-tauri/target/release/crab-sock
else
    echo "Ошибка при установке capability"
    exit 1
fi
