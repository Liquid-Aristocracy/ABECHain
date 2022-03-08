package main

import (
	"log"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	abeKey "github.com/Liquid-Aristocracy/fabric-ABECHain/abe-basic/chaincode-key/smart-contract"
)

func main() {
	abeKEySmartContract, err := contractapi.NewChaincode(&abeKey.SmartContract{})
	if err != nil {
		log.Panicf("Error creating abe-basic chaincode: %v", err)
	}

	if err := abeKeySmartContract.Start(); err != nil {
		log.Panicf("Error starting abe-basic chaincode: %v", err)
	}
}
