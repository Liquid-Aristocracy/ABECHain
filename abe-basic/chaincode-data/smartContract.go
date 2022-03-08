package main

import (
	"log"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	abeData "github.com/Liquid-Aristocracy/fabric-ABECHain/abe-basic/chaincode-data/smart-contract"
)

func main() {
	abeDataSmartContract, err := contractapi.NewChaincode(&abeData.SmartContract{})
	if err != nil {
		log.Panicf("Error creating abe-basic chaincode: %v", err)
	}

	if err := abeDataSmartContract.Start(); err != nil {
		log.Panicf("Error starting abe-basic chaincode: %v", err)
	}
}
