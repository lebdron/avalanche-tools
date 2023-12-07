package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ava-labs/avalanche-network-runner/network"
	"github.com/ava-labs/avalanche-network-runner/utils"
	"github.com/ava-labs/avalanchego/genesis"
	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/utils/constants"
)

type Config struct {
	NetworkId                 string `json:"network-id"`
	PublicIp                  string `json:"public-ip"`
	StakingPort               uint   `json:"staking-port"`
	HttpHost                  string `json:"http-host"`
	HttpPort                  uint   `json:"http-port"`
	StakingTlsCertFileContent []byte `json:"staking-tls-cert-file-content"`
	StakingTlsKeyFileContent  []byte `json:"staking-tls-key-file-content"`
	GenesisFileContent        []byte `json:"genesis-file-content"`
	BootstrapIds              string `json:"bootstrap-ids"`
	BootstrapIps              string `json:"bootstrap-ips"`
	LogLevel                  string `json:"log-level,omitempty"`
}

type CConfig struct {
	LogLevel string `json:"log-level,omitempty"`
}

func NewCertAndKeyBytes(rand io.Reader) ([]byte, []byte, error) {
	// Create key to sign cert with
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand)
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't generate ed25519 key: %w", err)
	}

	// Create self-signed staking cert
	certTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(0),
		NotBefore:             time.Date(2000, time.January, 0, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Now().AddDate(100, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand, certTemplate, certTemplate, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't create certificate: %w", err)
	}
	var certBuff bytes.Buffer
	if err := pem.Encode(&certBuff, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		return nil, nil, fmt.Errorf("couldn't write cert file: %w", err)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't marshal private key: %w", err)
	}

	var keyBuff bytes.Buffer
	if err := pem.Encode(&keyBuff, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return nil, nil, fmt.Errorf("couldn't write private key: %w", err)
	}

	return certBuff.Bytes(), keyBuff.Bytes(), nil
}

func main() {
	fmt.Printf("Start generator, args %v\n", os.Args)
	netroot := os.Args[1]
	nodefile, err := os.Open(os.Args[2])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer nodefile.Close()
	keyfile, err := os.Open(os.Args[3])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer keyfile.Close()

	configs := make([]Config, 0)
	networkID := uint32(1337)
	baseConfig := Config{
		NetworkId: fmt.Sprintf("network-%d", networkID),
		LogLevel:  "debug",
	}
	cConfig := CConfig{
		LogLevel: "trace",
	}

	rand := rand.New(rand.NewSource(0))
	genesisVdrs := make([]ids.NodeID, 0)
	scanner := bufio.NewScanner(nodefile)
	for scanner.Scan() {
		tokens := strings.Split(scanner.Text(), ":")
		crt, key, err := NewCertAndKeyBytes(rand)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		nodeID, err := utils.ToNodeID(key, crt)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		genesisVdrs = append(genesisVdrs, nodeID)
		fmt.Printf("Processing node %v %v\n", tokens, nodeID)

		config := baseConfig
		config.PublicIp = tokens[0]
		config.HttpHost = "0.0.0.0"
		httpPort, err := strconv.Atoi(tokens[1])
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		config.HttpPort = uint(httpPort)
		stakingPort, err := strconv.Atoi(tokens[2])
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		config.StakingPort = uint(stakingPort)
		config.StakingTlsCertFileContent = crt
		config.StakingTlsKeyFileContent = key
		if len(genesisVdrs) == 1 {
			baseConfig.BootstrapIds = nodeID.String()
			baseConfig.BootstrapIps = fmt.Sprintf("%s:%s", tokens[0], tokens[2])
		}
		configs = append(configs, config)
	}

	cChainBalances := make([]network.AddrAndBalance, 0)
	balance, ok := new(big.Int).SetString("0x6d79f82328ea3da61e066ebb2f88a000000000000", 0)
	if !ok {
		fmt.Println("failed to create big.Int")
		os.Exit(1)
	}
	scanner = bufio.NewScanner(keyfile)
	for scanner.Scan() {
		tokens := strings.Split(scanner.Text(), ":")
		addr, err := hex.DecodeString(tokens[0])
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		id, err := ids.ToShortID(addr)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		cChainBalances = append(cChainBalances, network.AddrAndBalance{
			Addr:    id,
			Balance: balance,
		})
	}

	genesisBytes, err := network.NewAvalancheGoGenesis(
		networkID,
		nil,
		cChainBalances,
		genesisVdrs,
	)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Enable upgrades
	var genesisConfig genesis.UnparsedConfig
	err = json.Unmarshal(genesisBytes, &genesisConfig)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	var cChainConfig map[string]interface{}
	err = json.Unmarshal([]byte(genesisConfig.CChainGenesis), &cChainConfig)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	blockConfig := cChainConfig["config"].(map[string]interface{})
	blockConfig["apricotPhase3BlockTimestamp"] = 0
	blockConfig["apricotPhase4BlockTimestamp"] = 0
	blockConfig["apricotPhase5BlockTimestamp"] = 0
	blockConfig["apricotPhasePre6BlockTimestamp"] = 0
	blockConfig["apricotPhase6BlockTimestamp"] = 0
	blockConfig["apricotPhasePost6BlockTimestamp"] = 0
	blockConfig["banffBlockTimestamp"] = 0
	blockConfig["cortinaBlockTimestamp"] = 0
	cChainConfig["config"] = blockConfig
	cChainConfigBytes, err := json.Marshal(cChainConfig)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	genesisConfig.CChainGenesis = string(cChainConfigBytes)
	genesisBytes, err = json.Marshal(genesisConfig)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	for i, config := range configs {
		dir := fmt.Sprintf("%s/n%d/.%s", netroot, i, constants.AppName)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		err = os.MkdirAll(fmt.Sprintf("%s/configs/chains/C", dir), 0755)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		config.GenesisFileContent = genesisBytes
		configJson, err := json.Marshal(config)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		os.WriteFile(fmt.Sprintf("%s/config.json", dir), configJson, 0644)
		cConfigJson, err := json.Marshal(cConfig)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		err = os.WriteFile(fmt.Sprintf("%s/configs/chains/C/config.json", dir), cConfigJson, 0644)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}
}
