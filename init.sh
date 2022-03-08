#!/bin/bash

../fabric-samples/test-network/network.sh up -ca
../fabric-samples/test-network/network.sh createChannel -c data-chain
../fabric-samples/test-network/network.sh createChannel -c key-chain
../fabric-samples/test-network/network.sh deployCC -c data-chain -ccn abe-data -ccp ../../fabric-ABECHain/abe-basic/chaincode-data -ccl go
../fabric-samples/test-network/network.sh deployCC -c key-chain -ccn abe-key -ccp ../../fabric-ABECHain/abe-basic/chaincode-key -ccl go
