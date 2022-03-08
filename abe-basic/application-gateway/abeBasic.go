package main

import (
    "bytes"
    //"context"
    "crypto/x509"
    "encoding/json"
    //"errors"
    "fmt"
    "github.com/hyperledger/fabric-gateway/pkg/client"
    "github.com/hyperledger/fabric-gateway/pkg/identity"
    //gwproto "github.com/hyperledger/fabric-protos-go/gateway"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
    //"google.golang.org/grpc/status"
    "io/ioutil"
    "log"
    "path"
    "time"
    
    "github.com/marcellop71/mosaic/abe"
    "github.com/mervick/aes-everywhere/go/aes256"
    "github.com/brianvoe/gofakeit/v6"
    "crypto"
    "crypto/rsa"
    "math/rand"
    crand "crypto/rand"
    "encoding/pem"
    "encoding/base64"
    "math/big"
)

const (
    mspID           = "Org1MSP"
    cryptoPath      = "../../../fabric-samples/test-network/organizations/peerOrganizations/org1.example.com"
    certPath        = cryptoPath + "/users/User1@org1.example.com/msp/signcerts/cert.pem"
    keyPath         = cryptoPath + "/users/User1@org1.example.com/msp/keystore/"
    tlsCertPath     = cryptoPath + "/peers/peer0.org1.example.com/tls/ca.crt"
    peerEndpoint    = "localhost:7051"
    gatewayPeer     = "peer0.org1.example.com"
    dataChannelName = "data-chain"
    keyChannelName  = "key-chain"
    dataCCName      = "abe-data"
    keyCCName       = "abe-key"
)

var assetIdList = []string{}
var policies = []string{
    "A@auth0",
    "B@auth0",
    "A@auth0 \\/ B@auth0",
    "A@auth0 /\\ B@auth0",
    "B@auth0 \\/ (A@auth0 /\\ C@auth0)",
    "(B@auth0 /\\ C@auth0) \\/ A@auth0",
    "C@auth0",
}
var abeKeyList = [](*abe.Ciphertext){}
var abeKeyHashList = []string{}

type PlainData struct {
    Sentence string `json:"sentence"`
    Count    int    `json:"size"`
}

type dataAsset struct {
	ID      string `json:"ID"`
	Content string `json:"content"`
}

type keyAsset struct {
	ID     string `json:"ID"`
	Key    string `json:"key"`
	Policy int    `json:"policy"`
}

func main() {
    log.Println("============ application-golang starts ============")

    // The gRPC client connection should be shared by all Gateway connections to this endpoint
    clientConnection := newGrpcConnection()
    defer clientConnection.Close()

    id := newIdentity()
    sign := newSign()

    // Create a Gateway connection for a specific client identity
    gateway, err := client.Connect(
        id,
        client.WithSign(sign),
        client.WithClientConnection(clientConnection),
        // Default timeouts for different gRPC calls
        client.WithEvaluateTimeout(5*time.Second),
        client.WithEndorseTimeout(15*time.Second),
        client.WithSubmitTimeout(5*time.Second),
        client.WithCommitStatusTimeout(1*time.Minute),
    )
    if err != nil {
        panic(err)
    }
    defer gateway.Close()

    dataNetwork := gateway.GetNetwork(dataChannelName)
    keyNetwork := gateway.GetNetwork(keyChannelName)
    dataContract := dataNetwork.GetContract(dataCCName)
    keyContract := keyNetwork.GetContract(keyCCName)
    
    // Init ABE org
    abeSeed := "this-is-some-random-thing-for-org1-idk"
    abeCurve := abe.NewCurve()
    abeCurve.SetSeed(abeSeed).InitRng()
    abeOrg := abe.NewRandomOrg(abeCurve)
    abeAuthKeys := abe.NewRandomAuth(abeOrg)
    
    // Init gofakeit
    gofakeit.Seed(0)

    fmt.Println("initLedger:")
    initLedger(dataContract, keyContract, abeOrg, abeAuthKeys)
    
    // Init ABE user
    userAttrs := abe.NewRandomUserkey(gatewayPeer, "A@auth0", abeAuthKeys.AuthPrv)
    userAttrs.SelectUserAttrs(gatewayPeer, "A@auth0")
    secret := abe.Decrypt(abeKeyList[0], userAttrs)
    if abeKeyHashList[0] != abe.SecretHash(secret) {
        panic(fmt.Errorf("failed to get secret key of user policy"))
    }

    fmt.Println("getAllAssets:")
    getAllAssets(dataContract, keyContract)

    fmt.Println("createAsset:")
    createAsset(dataContract, keyContract, 0, secret)
    userAttrs.Coeff["A@auth0"] = make([]int, 0)
    
    fmt.Println("getAllAssets:")
    getAllAssets(dataContract, keyContract)
    
    for i, _ := range policies {
        fmt.Printf("readAssetByID: %s\n", assetIdList[i])
        readAssetByID(dataContract, keyContract, assetIdList[i], abeAuthKeys, "A@auth0", gatewayPeer)
    }

    log.Println("============ application-golang ends ============")
}

// newGrpcConnection creates a gRPC connection to the Gateway server.
func newGrpcConnection() *grpc.ClientConn {
    certificate, err := loadCertificate(tlsCertPath)
    if err != nil {
        panic(err)
    }

    certPool := x509.NewCertPool()
    certPool.AddCert(certificate)
    transportCredentials := credentials.NewClientTLSFromCert(certPool, gatewayPeer)

    connection, err := grpc.Dial(peerEndpoint, grpc.WithTransportCredentials(transportCredentials))
    if err != nil {
        panic(fmt.Errorf("failed to create gRPC connection: %w", err))
    }

    return connection
}

// newIdentity creates a client identity for this Gateway connection using an X.509 certificate.
func newIdentity() *identity.X509Identity {
    certificate, err := loadCertificate(certPath)
    if err != nil {
        panic(err)
    }

    id, err := identity.NewX509Identity(mspID, certificate)
    if err != nil {
        panic(err)
    }

    return id
}

func loadCertificate(filename string) (*x509.Certificate, error) {
    certificatePEM, err := ioutil.ReadFile(filename)
    if err != nil {
        return nil, fmt.Errorf("failed to read certificate file: %w", err)
    }
    return identity.CertificateFromPEM(certificatePEM)
}

// newSign creates a function that generates a digital signature from a message digest using a private key.
func newSign() identity.Sign {
    files, err := ioutil.ReadDir(keyPath)
    if err != nil {
        panic(fmt.Errorf("failed to read private key directory: %w", err))
    }
    privateKeyPEM, err := ioutil.ReadFile(path.Join(keyPath, files[0].Name()))

    if err != nil {
        panic(fmt.Errorf("failed to read private key file: %w", err))
    }

    privateKey, err := identity.PrivateKeyFromPEM(privateKeyPEM)
    if err != nil {
        panic(err)
    }

    sign, err := identity.NewPrivateKeySign(privateKey)
    if err != nil {
        panic(err)
    }

    return sign
}

/*
 This type of transaction would typically only be run once by an application the first time it was started after its
 initial deployment. A new version of the chaincode deployed later would likely not need to run an "init" function.
*/
func initLedger(dataContract *client.Contract, keyContract *client.Contract, abeOrg *abe.Org, abeAuthKeys *abe.AuthKeys) {
    fmt.Println("===================================================")
    fmt.Printf("Submit Multiple Transactions to init Ledger: function creates the initial set of assets on the ledger based on policies \n")

    for i, policy := range policies {
        
        now := time.Now()
        assetId := fmt.Sprintf("asset%d", now.Unix()*1e3+int64(now.Nanosecond())/1e6)
        assetData := assetGen()
        privateKey, err := rsa.GenerateKey(crand.Reader, 2048)
        if err != nil {
            panic(fmt.Errorf("failed to generate conversation key: %w", err))
        }
        publicKey := &privateKey.PublicKey
        
        dataJson, err := json.Marshal(assetData)
        fmt.Println(assetId, string(dataJson[:]))
        if err != nil {
            panic(fmt.Errorf("failed to convert data to json: %w", err))
        }
        dataCipher := rsaPrivateEncrypt(string(dataJson[:]), privateKey)
        
        encryptedConvKey := abeKeyGenAndEncrypt(policy, publicKey, abeOrg, abeAuthKeys)
        assetIdList = append(assetIdList, assetId)
        
        _, err = dataContract.SubmitTransaction("CreateAsset", assetId, dataCipher)
        _, err = keyContract.SubmitTransaction("CreateAsset", assetId, encryptedConvKey, fmt.Sprint(i))
        if err != nil {
            panic(fmt.Errorf("failed to submit transaction: %w", err))
        }
        
    }

    fmt.Printf("*** Init successfully\n")
}

// Evaluate a transaction to query ledger state.
func getAllAssets(dataContract *client.Contract, keyContract *client.Contract) {
    fmt.Println("===================================================")
    fmt.Println("Evaluate Transaction: GetAllAssets, function prints all the current assets on both ledger")

    dataEvaluateResult, err := dataContract.EvaluateTransaction("GetAllAssets")
    if err != nil {
        panic(fmt.Errorf("failed to evaluate transaction: %w", err))
    }
    dataResult := formatJSON(dataEvaluateResult)

    fmt.Printf("\n*** Data result:%s\n", dataResult)
    
    keyEvaluateResult, err := keyContract.EvaluateTransaction("GetAllAssets")
    if err != nil {
        panic(fmt.Errorf("failed to evaluate transaction: %w", err))
    }
    keyResult := formatJSON(keyEvaluateResult)

    fmt.Printf("\n*** Key result:%s\n", keyResult)
}

// Submit a transaction synchronously, blocking until it has been committed to the ledger.
func createAsset(dataContract *client.Contract, keyContract *client.Contract, policy int, abeSecret abe.Point) {
    fmt.Println("===================================================")
    fmt.Printf("Submit Transaction: CreateAsset, creates new asset with a sentence and count \n")
    
    now := time.Now()
    assetId := fmt.Sprintf("asset%d", now.Unix()*1e3+int64(now.Nanosecond())/1e6)
    assetData := assetGen()
    privateKey, err := rsa.GenerateKey(crand.Reader, 2048)
    if err != nil {
        panic(fmt.Errorf("failed to generate conversation key: %w", err))
    }
    publicKey := &privateKey.PublicKey
    
    dataJson, err := json.Marshal(assetData)
    fmt.Println(assetId, string(dataJson[:]))
    if err != nil {
        panic(fmt.Errorf("failed to convert data to json: %w", err))
    }
    dataCipher := rsaPrivateEncrypt(string(dataJson[:]), privateKey)
    
    publicKeyString := publicKeyToString(publicKey)
    encryptedConvKey := encryptWithABESecret(publicKeyString, abeSecret)
    assetIdList = append(assetIdList, assetId)
    
    _, err = dataContract.SubmitTransaction("CreateAsset", assetId, dataCipher)
    _, err = keyContract.SubmitTransaction("CreateAsset", assetId, encryptedConvKey, "0")
    if err != nil {
        panic(fmt.Errorf("failed to submit transaction: %w", err))
    }

    fmt.Printf("*** Transaction committed successfully\n")
}

// Evaluate a transaction by assetID and user's policy.
func readAssetByID(dataContract *client.Contract, keyContract *client.Contract, assetId string, abeAuthKeys *abe.AuthKeys, userPolicy string, user string) {
    fmt.Println("===================================================")
    fmt.Printf("Evaluate Transaction: ReadAsset, function returns asset attributes\n")

    dataEvaluateResult, err := dataContract.EvaluateTransaction("ReadAsset", assetId)
    if err != nil {
        panic(fmt.Errorf("failed to evaluate transaction: %w", err))
    }
    
    var data dataAsset
    err = json.Unmarshal(dataEvaluateResult, &data)
    if err != nil {
        panic(fmt.Errorf("failed to parse data result: %w", err))
    }
    
    keyEvaluateResult, err := keyContract.EvaluateTransaction("ReadAsset", assetId)
    if err != nil {
        panic(fmt.Errorf("failed to evaluate transaction: %w", err))
    }
    
    var key keyAsset
    err = json.Unmarshal(keyEvaluateResult, &key)
    if err != nil {
        panic(fmt.Errorf("failed to parse key result: %w", err))
    }
    
    userAttrs := abe.NewRandomUserkey(user, userPolicy, abeAuthKeys.AuthPrv)
    userAttrs.SelectUserAttrs(user, policies[key.Policy])
    secret := abe.Decrypt(abeKeyList[key.Policy], userAttrs)
    if abeKeyHashList[key.Policy] != abe.SecretHash(secret) {
        fmt.Printf("*** Cannot decrypt %s, need %s\n", assetId, policies[key.Policy])
        return
    } else {
        fmt.Printf("*** Policy %s satisfied, %s readable\n", policies[key.Policy], assetId)
    }
    
    convKeyStr := decryptWithABESecret(key.Key, secret)
    convKey := stringToPublicKey(convKeyStr)
    result := rsaPublicDecrypt(data.Content, convKey)
    
    resultToPrint := formatJSON([]byte(result))
    
    fmt.Printf("*** Result:%s\n", resultToPrint)
    return
}

// Format JSON data
func formatJSON(data []byte) string {
    var prettyJSON bytes.Buffer
    if err := json.Indent(&prettyJSON, data, " ", ""); err != nil {
        panic(fmt.Errorf("failed to parse JSON: %w", err))
    }
    return prettyJSON.String()
}

// RSA private encryption used in conversation encryption
func rsaPrivateEncrypt(secretMessage string, privKey *rsa.PrivateKey) string {
    ciphertext, err := rsa.SignPKCS1v15(nil, privKey, crypto.Hash(0), []byte(secretMessage))
    if err != nil {
        panic(fmt.Errorf("failed to encrypt: %w", err))
    }
    return base64.StdEncoding.EncodeToString(ciphertext)
}

// RSA public decryption used in conversation decryption
func rsaPublicDecrypt(cipherText string, pubKey *rsa.PublicKey) string {
    c := new(big.Int)
    m := new(big.Int)
    decode, err := base64.StdEncoding.DecodeString(cipherText)
    if err != nil {
        panic(fmt.Errorf("failed to encode base64: %w", err))
    }
    m.SetBytes(decode)
    e := big.NewInt(int64(pubKey.E))
    c.Exp(m, e, pubKey.N)
    out := c.Bytes()
    skip := 0
    for i := 2; i < len(out); i++ {
        if i+1 >= len(out) {
            break
        }
        if out[i] == 0xff && out[i+1] == 0 {
            skip = i + 2
            break
        }
    }
    return string(out[skip:])
}

// private key to string
func privateKeyToString(priv *rsa.PrivateKey) string {
    privBytes := pem.EncodeToMemory(
        &pem.Block{
            Type:  "RSA PRIVATE KEY",
            Bytes: x509.MarshalPKCS1PrivateKey(priv),
        },
    )

    return base64.StdEncoding.EncodeToString(privBytes[:])
}

// public key to string
func publicKeyToString(pub *rsa.PublicKey) string {
    pubASN1, err := x509.MarshalPKIXPublicKey(pub)
    if err != nil {
        panic(fmt.Errorf("failed to convert public key to string: %w", err))
    }

    pubBytes := pem.EncodeToMemory(&pem.Block{
        Type:  "RSA PUBLIC KEY",
        Bytes: pubASN1,
    })

    return base64.StdEncoding.EncodeToString(pubBytes[:])
}

// string to private key
func stringToPrivateKey(privStr string) *rsa.PrivateKey {
    priv, err := base64.StdEncoding.DecodeString(privStr)
    if err != nil {
        panic(fmt.Errorf("failed to encode base64: %w", err))
    }
    block, _ := pem.Decode(priv)
    enc := x509.IsEncryptedPEMBlock(block)
    b := block.Bytes
    if enc {
        b, err = x509.DecryptPEMBlock(block, nil)
        if err != nil {
            panic(fmt.Errorf("failed to convert string to private key: %w", err))
        }
    }
    key, err := x509.ParsePKCS1PrivateKey(b)
    if err != nil {
        panic(fmt.Errorf("failed to convert string to private key: %w", err))
    }
    return key
}

// string to public key
func stringToPublicKey(pubStr string) *rsa.PublicKey {
    pub, err := base64.StdEncoding.DecodeString(pubStr)
    if err != nil {
        panic(fmt.Errorf("failed to encode base64: %w", err))
    }
    block, _ := pem.Decode(pub)
    enc := x509.IsEncryptedPEMBlock(block)
    b := block.Bytes
    if enc {
        b, err = x509.DecryptPEMBlock(block, nil)
        if err != nil {
            panic(fmt.Errorf("failed to convert string to public key: %w", err))
        }
    }
    ifc, err := x509.ParsePKIXPublicKey(b)
    if err != nil {
        panic(fmt.Errorf("failed to convert string to public key: %w", err))
    }
    key, ok := ifc.(*rsa.PublicKey)
    if !ok {
        fmt.Errorf("key is not ok")
    }
    return key
}

// use policy to generate key and store it
func abeKeyGenAndEncrypt(policy string, pub *rsa.PublicKey, org *abe.Org, authKeys *abe.AuthKeys) string {
    secret := abe.NewRandomSecret(org)
    abeKeyHashList = append(abeKeyHashList, abe.SecretHash(secret))
    
    policy = abe.RewritePolicy(policy)
    authPubs := abe.AuthPubsOfPolicy(policy)
    for attr, _ := range authPubs.AuthPub {
        authPubs.AuthPub[attr] = authKeys.AuthPub
    }
    ct := abe.Encrypt(secret, policy, authPubs)
    abeKeyList = append(abeKeyList, ct)
    
    plain := publicKeyToString(pub)
    return encryptWithABESecret(plain, secret)
}

// use aes to encrypt conversation key with secret point
func encryptWithABESecret(plain string, secret abe.Point) string {
    password := secret.ToJsonObj().GetP()
    encrypted := aes256.Encrypt(plain, password)
    return encrypted
}

// use aes to decrypt conversation key with secret point
func decryptWithABESecret(cipher string, secret abe.Point) string {
    password := secret.ToJsonObj().GetP()
    decrypted := aes256.Decrypt(cipher, password)
    return decrypted
}

// generate a random asset
func assetGen() PlainData {
    
    rand.Seed(time.Now().UnixNano())
    n := rand.Intn(15) + 5
    
    sentence := gofakeit.Sentence(n)
    asset := PlainData {
        Sentence: sentence,
        Count:    n,
    }
    
    return asset
}
