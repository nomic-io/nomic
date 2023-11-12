#!/bin/bash

# this script shall be used when we run hermes

NOMIC_CHAIN_ID=${NOMIC_CHAIN_ID:-nomic-local-1}
ORAI_CHAIN_ID=${ORAI_CHAIN_ID:-testing}
KEY_NAME=${KEY_NAME:-nomic}

# install jq so we can parse the json string when checking ibc connection
apt install jq

hermes keys add --chain $NOMIC_CHAIN_ID --key-name $KEY_NAME --mnemonic-file .env.nomic
hermes keys add --chain $ORAI_CHAIN_ID --key-name $KEY_NAME --mnemonic-file .env.orai


# try to get latest ibc client
latest_ibc_client=$(hermes --json query clients --host-chain $NOMIC_CHAIN_ID --reference-chain $ORAI_CHAIN_ID | grep result | jq .result[-1])

if [ "$latest_ibc_client" == "null" ]; then
    hermes create channel --a-chain $NOMIC_CHAIN_ID --new-client-connection --b-chain $ORAI_CHAIN_ID --a-port transfer --b-port transfer --yes
else
    latest_connection=$(hermes --json query connections --chain $NOMIC_CHAIN_ID --counterparty-chain $ORAI_CHAIN_ID | grep result | jq .result[-1])
    # if empty connection then we create new connection and channel
    if [ "$latest_connection" == "null" ]; then
        # get the last client id of the host chain & attempt to create a connection
        host_client=$(hermes --json query clients --host-chain $NOMIC_CHAIN_ID --reference-chain $ORAI_CHAIN_ID | grep result | jq .result[-1])
        reference_client=$(hermes --json query clients --host-chain $ORAI_CHAIN_ID --reference-chain $NOMIC_CHAIN_ID | grep result | jq .result[-1])
        hermes create connection --a-chain $NOMIC_CHAIN_ID --b-chain $ORAI_CHAIN_ID --a-client $host_client --b-client $reference_client
        # create new channels based on the connections
        echo "preparing to create new channels"
        # after creating a new connection, we should have at least one by now
        latest_connection=$(hermes --json query connections --chain $NOMIC_CHAIN_ID --counterparty-chain $ORAI_CHAIN_ID | grep result | jq .result[-1])
        # need to trim double quotes before calling the above command
        echo "Creating new channels ..."
        trimmed_latest_connection="${latest_connection//\"}"
        hermes create channel --a-chain $NOMIC_CHAIN_ID --a-connection $trimmed_latest_connection --a-port transfer --b-port transfer --yes
    else
        echo "already having a connection, verifying if there are channels..."
        has_channel=$(hermes --json query connections --chain $NOMIC_CHAIN_ID --counterparty-chain $ORAI_CHAIN_ID | grep result | jq .result[-1])
        # if we find no channel => create new
        if [ "$has_channel" == "null" ]; then
            # need to trim double quotes before calling the above command
            echo "Creating new channels ..."
            trimmed_latest_connection="${latest_connection//\"}"
            hermes create channel --a-chain $NOMIC_CHAIN_ID --a-connection $trimmed_latest_connection --a-port transfer --b-port transfer --yes
        else
            echo "Already have at least a channel. Ready to start hermes..."
        fi
    fi
fi


hermes start