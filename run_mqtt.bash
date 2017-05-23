#!/usr/bin/env bash
# export SENDER_MANAGER_PATH=${SENDER_MANAGER_PATH:-"$SRC_DIR/messagesender"}
export SENDER_MANAGER_HOST="192.168.22.114"
export SENDER_MANAGER_PORT="1884"
export SENDER_MANAGER_DATABASE_SCHEMA="microfinance"
export SENDER_MANAGER_DATABASE_HOST="127.0.0.1"
export SENDER_MANAGER_DATABASE_PORT="5432"
export SENDER_MANAGER_DATABASE_USER="microfinanceuser"
export SENDER_MANAGER_DATABASE_PWD="123456"
kobo_workon kc

cd ./messagesender
mosquitto -p $SENDER_MANAGER_PORT  &
python -c "import senderManager;print senderManager.startApp('$SENDER_MANAGER_HOST','$SENDER_MANAGER_PORT','$SENDER_MANAGER_DATABASE_SCHEMA','$SENDER_MANAGER_DATABASE_HOST','$SENDER_MANAGER_DATABASE_PORT','$SENDER_MANAGER_DATABASE_USER','$SENDER_MANAGER_DATABASE_PWD')"
