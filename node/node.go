// Copyright (C) 2019-2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package node

import (
	"context"
	"crypto"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/cryft-labs/cryftgo/api/admin"
	"github.com/cryft-labs/cryftgo/api/health"
	"github.com/cryft-labs/cryftgo/api/info"
	"github.com/cryft-labs/cryftgo/api/keystore"
	"github.com/cryft-labs/cryftgo/api/metrics"
	"github.com/cryft-labs/cryftgo/api/server"
	"github.com/cryft-labs/cryftgo/chains"
	"github.com/cryft-labs/cryftgo/chains/atomic"
	"github.com/cryft-labs/cryftgo/database"
	"github.com/cryft-labs/cryftgo/database/leveldb"
	"github.com/cryft-labs/cryftgo/database/memdb"
	"github.com/cryft-labs/cryftgo/database/meterdb"
	"github.com/cryft-labs/cryftgo/database/pebble"
	"github.com/cryft-labs/cryftgo/database/prefixdb"
	"github.com/cryft-labs/cryftgo/database/versiondb"
	"github.com/cryft-labs/cryftgo/genesis"
	"github.com/cryft-labs/cryftgo/ids"
	"github.com/cryft-labs/cryftgo/indexer"
	"github.com/cryft-labs/cryftgo/message"
	"github.com/cryft-labs/cryftgo/nat"
	"github.com/cryft-labs/cryftgo/network"
	"github.com/cryft-labs/cryftgo/network/dialer"
	"github.com/cryft-labs/cryftgo/network/peer"
	"github.com/cryft-labs/cryftgo/network/throttling"
	"github.com/cryft-labs/cryftgo/node/runtimeinfo"
	"github.com/cryft-labs/cryftgo/snow"
	"github.com/cryft-labs/cryftgo/snow/networking/benchlist"
	"github.com/cryft-labs/cryftgo/snow/networking/router"
	"github.com/cryft-labs/cryftgo/snow/networking/timeout"
	"github.com/cryft-labs/cryftgo/snow/networking/tracker"
	"github.com/cryft-labs/cryftgo/snow/uptime"
	"github.com/cryft-labs/cryftgo/snow/validators"
	"github.com/cryft-labs/cryftgo/staking"
	"github.com/cryft-labs/cryftgo/trace"
	"github.com/cryft-labs/cryftgo/utils"
	"github.com/cryft-labs/cryftgo/utils/constants"
	"github.com/cryft-labs/cryftgo/utils/crypto/bls"
	"github.com/cryft-labs/cryftgo/utils/dynamicip"
	"github.com/cryft-labs/cryftgo/utils/filesystem"
	"github.com/cryft-labs/cryftgo/utils/hashing"
	"github.com/cryft-labs/cryftgo/utils/ips"
	"github.com/cryft-labs/cryftgo/utils/logging"
	"github.com/cryft-labs/cryftgo/utils/math/meter"
	"github.com/cryft-labs/cryftgo/utils/perms"
	"github.com/cryft-labs/cryftgo/utils/profiler"
	"github.com/cryft-labs/cryftgo/utils/resource"
	"github.com/cryft-labs/cryftgo/utils/set"
	"github.com/cryft-labs/cryftgo/version"
	"github.com/cryft-labs/cryftgo/vms"
	"github.com/cryft-labs/cryftgo/vms/avm"
	"github.com/cryft-labs/cryftgo/vms/platformvm"
	"github.com/cryft-labs/cryftgo/vms/platformvm/signer"
	"github.com/cryft-labs/cryftgo/vms/platformvm/upgrade"
	"github.com/cryft-labs/cryftgo/vms/registry"
	"github.com/cryft-labs/cryftgo/vms/rpcchainvm/runtime"

	coreth "github.com/cryft-labs/coreth/plugin/evm"
	avmconfig "github.com/cryft-labs/cryftgo/vms/avm/config"
	platformconfig "github.com/cryft-labs/cryftgo/vms/platformvm/config"
)

const (
	stakingPortName = constants.AppName + "-staking"
	httpPortName    = constants.AppName + "-http"

	ipResolutionTimeout = 30 * time.Second
)

var (
	genesisHashKey     = []byte("genesisID")
	ungracefulShutdown = []byte("ungracefulShutdown")

	indexerDBPrefix  = []byte{0x00}
	keystoreDBPrefix = []byte("keystore")

	errInvalidTLSKey = errors.New("invalid TLS key")
	errShuttingDown  = errors.New("server shutting down")
)

// Node is an instance of an Avalanche node.
type Node struct {
	Log          logging.Logger
	VMFactoryLog logging.Logger
	LogFactory   logging.Factory

	// This node's unique ID used when communicating with other nodes
	// (in consensus, for example)
	ID ids.NodeID

	StakingTLSSigner crypto.Signer
	StakingTLSCert   *staking.Certificate

	// Storage for this node
	DB database.Database

	router     nat.Router
	portMapper *nat.Mapper
	ipUpdater  dynamicip.Updater

	chainRouter router.Router

	// Profiles the process. Nil if continuous profiling is disabled.
	profiler profiler.ContinuousProfiler

	// Indexes blocks, transactions and blocks
	indexer indexer.Indexer

	// Handles calls to Keystore API
	keystore keystore.Keystore

	// Manages shared memory
	sharedMemory *atomic.Memory

	// Monitors node health and runs health checks
	health health.Health

	// Build and parse messages, for both network layer and chain manager
	msgCreator message.Creator

	// Manages network timeouts
	timeoutManager timeout.Manager

	// Manages creation of blockchains and routing messages to them
	chainManager chains.Manager

	// Manages validator benching
	benchlistManager benchlist.Manager

	uptimeCalculator uptime.LockedCalculator

	// dispatcher for events as they happen in consensus
	BlockAcceptorGroup  snow.AcceptorGroup
	TxAcceptorGroup     snow.AcceptorGroup
	VertexAcceptorGroup snow.AcceptorGroup

	// Net runs the networking stack
	networkNamespace string
	Net              network.Network

	// The staking address will optionally be written to a process context
	// file to enable other nodes to be configured to use this node as a
	// beacon.
	stakingAddress string

	// tlsKeyLogWriterCloser is a debug file handle that writes all the TLS
	// session keys. This value should only be non-nil during debugging.
	tlsKeyLogWriterCloser io.WriteCloser

	// this node's initial connections to the network
	bootstrappers validators.Manager

	// current validators of the network
	vdrs validators.Manager

	apiURI string

	// Handles HTTP API calls
	APIServer server.Server

	// This node's configuration
	Config *Config

	tracer trace.Tracer

	// ensures that we only close the node once.
	shutdownOnce sync.Once

	// True if node is shutting down or is done shutting down
	shuttingDown utils.Atomic[bool]

	// Sets the exit code
	shuttingDownExitCode utils.Atomic[int]

	// Incremented only once on initialization.
	// Decremented when node is done shutting down.
	DoneShuttingDown sync.WaitGroup

	// Metrics Registerer
	MetricsRegisterer *prometheus.Registry
	MetricsGatherer   metrics.MultiGatherer

	VMAliaser ids.Aliaser
	VMManager vms.Manager

	// VM endpoint registry
	VMRegistry registry.VMRegistry

	// Manages shutdown of a VM process
	runtimeManager runtime.Manager

	resourceManager resource.Manager

	// Tracks the CPU/disk usage caused by processing
	// messages of each peer.
	resourceTracker tracker.ResourceTracker

	// Specifies how much CPU usage each peer can cause before
	// we rate-limit them.
	cpuTargeter tracker.Targeter

	// Specifies how much disk usage each peer can cause before
	// we rate-limit them.
	diskTargeter tracker.Targeter

	// Runtime info / Cryftee client. Nil when disabled or misconfigured.
	runtimeClient RuntimeInfoClient

	// CryfteeManager handles lifecycle of the cryftee sidecar when managed by cryftgo.
	// Nil when cryftee is not managed by this node (e.g., external deployment).
	cryfteeManager *CryfteeManager
}

/*
 ******************************************************************************
 *************************** P2P Networking Section ***************************
 ******************************************************************************
 */

// Initialize the networking layer.
// Assumes [n.vdrs], [n.CPUTracker], and [n.CPUTargeter] have been initialized.
func (n *Node) initNetworking() error {
	// Providing either loopback address - `::1` for ipv6 and `127.0.0.1` for ipv4 - as the listen
	// host will avoid the need for a firewall exception on recent MacOS:
	//
	//   - MacOS requires a manually-approved firewall exception [1] for each version of a given
	//   binary that wants to bind to all interfaces (i.e. with an address of `:[port]`). Each
	//   compiled version of cryftgo requires a separate exception to be allowed to bind to all
	//   interfaces.
	//
	//   - A firewall exception is not required to bind to a loopback interface, but the only way for
	//   Listen() to bind to loopback for both ipv4 and ipv6 is to bind to all interfaces [2] which
	//   requires an exception.
	//
	//   - Thus, the only way to start a node on MacOS without approving a firewall exception for the
	//   cryftgo binary is to bind to loopback by specifying the host to be `::1` or `127.0.0.1`.
	//
	// 1: https://apple.stackexchange.com/questions/393715/do-you-want-the-application-main-to-accept-incoming-network-connections-pop
	// 2: https://github.com/golang/go/issues/56998
	listenAddress := net.JoinHostPort(n.Config.ListenHost, strconv.FormatUint(uint64(n.Config.ListenPort), 10))
	listener, err := net.Listen(constants.NetworkType, listenAddress)
	if err != nil {
		return err
	}
	// Wrap listener so it will only accept a certain number of incoming connections per second
	listener = throttling.NewThrottledListener(listener, n.Config.NetworkConfig.ThrottlerConfig.MaxInboundConnsPerSec)

	// Record the bound address to enable inclusion in process context file.
	n.stakingAddress = listener.Addr().String()
	ipPort, err := ips.ToIPPort(n.stakingAddress)
	if err != nil {
		return err
	}

	var dynamicIP ips.DynamicIPPort
	switch {
	case n.Config.PublicIP != "":
		// Use the specified public IP.
		ipPort.IP = net.ParseIP(n.Config.PublicIP)
		if ipPort.IP == nil {
			return fmt.Errorf("invalid IP Address: %s", n.Config.PublicIP)
		}
		dynamicIP = ips.NewDynamicIPPort(ipPort.IP, ipPort.Port)
		n.ipUpdater = dynamicip.NewNoUpdater()
	case n.Config.PublicIPResolutionService != "":
		// Use dynamic IP resolution.
		resolver, err := dynamicip.NewResolver(n.Config.PublicIPResolutionService)
		if err != nil {
			return fmt.Errorf("couldn't create IP resolver: %w", err)
		}

		// Use that to resolve our public IP.
		ctx, cancel := context.WithTimeout(context.Background(), ipResolutionTimeout)
		ipPort.IP, err = resolver.Resolve(ctx)
		cancel()
		if err != nil {
			return fmt.Errorf("couldn't resolve public IP: %w", err)
		}
		dynamicIP = ips.NewDynamicIPPort(ipPort.IP, ipPort.Port)
		n.ipUpdater = dynamicip.NewUpdater(dynamicIP, resolver, n.Config.PublicIPResolutionFreq)
	default:
		ipPort.IP, err = n.router.ExternalIP()
		if err != nil {
			return fmt.Errorf("public IP / IP resolution service not given and failed to resolve IP with NAT: %w", err)
		}
		dynamicIP = ips.NewDynamicIPPort(ipPort.IP, ipPort.Port)
		n.ipUpdater = dynamicip.NewNoUpdater()
	}

	if ipPort.IP.IsLoopback() || ipPort.IP.IsPrivate() {
		n.Log.Warn("P2P IP is private, you will not be publicly discoverable",
			zap.Stringer("ip", ipPort),
		)
	}

	// Regularly update our public IP and port mappings.
	n.portMapper.Map(
		ipPort.Port,
		ipPort.Port,
		stakingPortName,
		dynamicIP,
		n.Config.PublicIPResolutionFreq,
	)
	go n.ipUpdater.Dispatch(n.Log)

	n.Log.Info("initializing networking",
		zap.Stringer("ip", ipPort),
	)

	tlsKey, ok := n.Config.StakingTLSCert.PrivateKey.(crypto.Signer)
	if !ok {
		return errInvalidTLSKey
	}

	if n.Config.NetworkConfig.TLSKeyLogFile != "" {
		n.tlsKeyLogWriterCloser, err = perms.Create(n.Config.NetworkConfig.TLSKeyLogFile, perms.ReadWrite)
		if err != nil {
			return err
		}
		n.Log.Warn("TLS key logging is enabled",
			zap.String("filename", n.Config.NetworkConfig.TLSKeyLogFile),
		)
	}

	// We allow nodes to gossip unknown ACPs in case the current ACPs constant
	// becomes out of date.
	var unknownACPs set.Set[uint32]
	for acp := range n.Config.NetworkConfig.SupportedACPs {
		if !constants.CurrentACPs.Contains(acp) {
			unknownACPs.Add(acp)
		}
	}
	for acp := range n.Config.NetworkConfig.ObjectedACPs {
		if !constants.CurrentACPs.Contains(acp) {
			unknownACPs.Add(acp)
		}
	}
	if unknownACPs.Len() > 0 {
		n.Log.Warn("gossiping unknown ACPs",
			zap.Reflect("acps", unknownACPs),
		)
	}

	// Choose TLS config:
	//   - If a RemoteTLSSigner is provided and Web3Signer is enabled, use it.
	//   - Otherwise, fall back to the local staking TLS certificate.
	var tlsConfig *tls.Config
	if n.Config.Web3SignerEnabled && n.Config.RemoteTLSSigner != nil {
		n.Log.Info("using remote TLS signer for staking transport (Cryftee/Web3Signer-backed)")
		cfg, err := n.Config.RemoteTLSSigner.TLSConfig()
		if err != nil {
			return fmt.Errorf("failed to initialize remote TLS signer: %w", err)
		}
		tlsConfig = cfg
		// In this mode, tlsKey will typically also be backed by Web3Signer
		// via the tls.Config's certificate/private key; keep TLSKey set
		// for now so downstream code doesn't change.
	} else {
		tlsConfig = peer.TLSConfig(n.Config.StakingTLSCert, n.tlsKeyLogWriterCloser)
	}

	// Create chain router
	n.chainRouter = &router.ChainRouter{}
	if n.Config.TraceConfig.Enabled {
		n.chainRouter = router.Trace(n.chainRouter, n.tracer)
	}

	// Configure benchlist
	n.Config.BenchlistConfig.Validators = n.vdrs
	n.Config.BenchlistConfig.Benchable = n.chainRouter
	n.benchlistManager = benchlist.NewManager(&n.Config.BenchlistConfig)

	n.uptimeCalculator = uptime.NewLockedCalculator()

	consensusRouter := n.chainRouter
	if !n.Config.SybilProtectionEnabled {
		// Sybil protection is disabled so we don't have a txID that added us as
		// a validator. Because each validator needs a txID associated with it,
		// we hack one together by just padding our nodeID with zeroes.
		dummyTxID := ids.Empty
		copy(dummyTxID[:], n.ID.Bytes())

		err := n.vdrs.AddStaker(
			constants.PrimaryNetworkID,
			n.ID,
			bls.PublicFromSecretKey(n.Config.StakingSigningKey),
			dummyTxID,
			n.Config.SybilProtectionDisabledWeight,
		)
		if err != nil {
			return err
		}

		consensusRouter = &insecureValidatorManager{
			log:    n.Log,
			Router: consensusRouter,
			vdrs:   n.vdrs,
			weight: n.Config.SybilProtectionDisabledWeight,
		}
	}

	numBootstrappers := n.bootstrappers.Count(constants.PrimaryNetworkID)
	requiredConns := (3*numBootstrappers + 3) / 4

	if requiredConns > 0 {
		onSufficientlyConnected := make(chan struct{})
		consensusRouter = &beaconManager{
			Router:                  consensusRouter,
			beacons:                 n.bootstrappers,
			requiredConns:           int64(requiredConns),
			onSufficientlyConnected: onSufficientlyConnected,
		}

		// Log a warning if we aren't able to connect to a sufficient portion of
		// nodes.
		go func() {
			timer := time.NewTimer(n.Config.BootstrapBeaconConnectionTimeout)
			defer timer.Stop()

			select {
			case <-timer.C:
				if n.shuttingDown.Get() {
					return
				}
				n.Log.Warn("failed to connect to bootstrap nodes",
					zap.Stringer("bootstrappers", n.bootstrappers),
					zap.Duration("duration", n.Config.BootstrapBeaconConnectionTimeout),
				)
			case <-onSufficientlyConnected:
			}
		}()
	}

	// add node configs to network config
	n.Config.NetworkConfig.Namespace = n.networkNamespace
	n.Config.NetworkConfig.MyNodeID = n.ID
	n.Config.NetworkConfig.MyIPPort = dynamicIP
	n.Config.NetworkConfig.NetworkID = n.Config.NetworkID
	n.Config.NetworkConfig.Validators = n.vdrs
	n.Config.NetworkConfig.Beacons = n.bootstrappers
	n.Config.NetworkConfig.TLSConfig = tlsConfig
	n.Config.NetworkConfig.TLSKey = tlsKey

	// When Web3Signer / Cryftee-backed staking is enabled, BLS staking
	// signatures are expected to be produced by the external signer. In that
	// mode we intentionally do not wire a local BLS key into the networking
	// config to avoid accidental local signing. A future Cryftee/Web3Signer
	// client can instead attach a remote-signer-backed BLS provider here.
	if n.Config.Web3SignerEnabled {
		n.Log.Info("web3signer-backed staking is enabled; skipping wiring of local BLS staking key into network config")
		n.Config.NetworkConfig.BLSKey = nil
	} else {
		n.Config.NetworkConfig.BLSKey = n.Config.StakingSigningKey
	}

	n.Config.NetworkConfig.TrackedSubnets = n.Config.TrackedSubnets
	n.Config.NetworkConfig.UptimeCalculator = n.uptimeCalculator
	n.Config.NetworkConfig.UptimeRequirement = n.Config.UptimeRequirement
	n.Config.NetworkConfig.ResourceTracker = n.resourceTracker
	n.Config.NetworkConfig.CPUTargeter = n.cpuTargeter
	n.Config.NetworkConfig.DiskTargeter = n.diskTargeter

	n.Net, err = network.NewNetwork(
		&n.Config.NetworkConfig,
		n.msgCreator,
		n.MetricsRegisterer,
		n.Log,
		listener,
		dialer.NewDialer(constants.NetworkType, n.Config.NetworkConfig.DialerConfig, n.Log),
		consensusRouter,
	)

	return err
}

/*
 ******************************************************************************
 *********************** End P2P Networking Section ***************************
 ******************************************************************************
 */

// Set the node IDs of the peers this node should first connect to
func (n *Node) initBootstrappers() error {
	n.bootstrappers = validators.NewManager()
	for _, bootstrapper := range n.Config.Bootstrappers {
		// Note: The beacon connection manager will treat all beaconIDs as
		//       equal.
		// Invariant: We never use the TxID or BLS keys populated here.
		if err := n.bootstrappers.AddStaker(constants.PrimaryNetworkID, bootstrapper.ID, nil, ids.Empty, 1); err != nil {
			return err
		}
	}
	return nil
}

// Create the EventDispatcher used for hooking events
// into the general process flow.
func (n *Node) initEventDispatchers() {
	n.BlockAcceptorGroup = snow.NewAcceptorGroup(n.Log)
	n.TxAcceptorGroup = snow.NewAcceptorGroup(n.Log)
	n.VertexAcceptorGroup = snow.NewAcceptorGroup(n.Log)
}

// Initialize [n.indexer].
// Should only be called after [n.DB], [n.DecisionAcceptorGroup],
// [n.ConsensusAcceptorGroup], [n.Log], [n.APIServer], [n.chainManager] are
// initialized
func (n *Node) initIndexer() error {
	txIndexerDB := prefixdb.New(indexerDBPrefix, n.DB)
	var err error
	n.indexer, err = indexer.NewIndexer(indexer.Config{
		IndexingEnabled:      n.Config.IndexAPIEnabled,
		AllowIncompleteIndex: n.Config.IndexAllowIncomplete,
		DB:                   txIndexerDB,
		Log:                  n.Log,
		BlockAcceptorGroup:   n.BlockAcceptorGroup,
		TxAcceptorGroup:      n.TxAcceptorGroup,
		VertexAcceptorGroup:  n.VertexAcceptorGroup,
		APIServer:            n.APIServer,
		ShutdownF: func() {
			n.Shutdown(0) // TODO put exit code here
		},
	})
	if err != nil {
		return fmt.Errorf("couldn't create index for txs: %w", err)
	}

	// Chain manager will notify indexer when a chain is created
	n.chainManager.AddRegistrant(n.indexer)

	return nil
}

// Initializes the Platform chain.
// Its genesis data specifies the other chains that should be created.
func (n *Node) initChains(genesisBytes []byte) error {
	n.Log.Info("initializing chains")

	platformChain := chains.ChainParameters{
		ID:            constants.PlatformChainID,
		SubnetID:      constants.PrimaryNetworkID,
		GenesisData:   genesisBytes, // Specifies other chains to create
		VMID:          constants.PlatformVMID,
		CustomBeacons: n.bootstrappers,
	}

	// Start the chain creator with the Platform Chain
	return n.chainManager.StartChainCreator(platformChain)
}

func (n *Node) initMetrics() {
	n.MetricsRegisterer = prometheus.NewRegistry()
	n.MetricsGatherer = metrics.NewMultiGatherer()
}

func (n *Node) initNAT() {
	n.Log.Info("initializing NAT")

	if n.Config.PublicIP == "" && n.Config.PublicIPResolutionService == "" {
		n.router = nat.GetRouter()
		if !n.router.SupportsNAT() {
			n.Log.Warn("UPnP and NAT-PMP router attach failed, " +
				"you may not be listening publicly. " +
				"Please confirm the settings in your router")
		}
	} else {
		n.router = nat.NewNoRouter()
	}

	n.portMapper = nat.NewPortMapper(n.Log, n.router)
}

// initAPIServer initializes the server that handles HTTP calls
func (n *Node) initAPIServer() error {
	n.Log.Info("initializing API server")

	// An empty host is treated as a wildcard to match all addresses, so it is
	// considered public.
	hostIsPublic := n.Config.HTTPHost == ""
	if !hostIsPublic {
		ip, err := ips.Lookup(n.Config.HTTPHost)
		if err != nil {
			n.Log.Fatal("failed to lookup HTTP host",
				zap.String("host", n.Config.HTTPHost),
				zap.Error(err),
			)
			return err
		}
		hostIsPublic = !ip.IsLoopback() && !ip.IsPrivate()

		n.Log.Debug("finished HTTP host lookup",
			zap.String("host", n.Config.HTTPHost),
			zap.Stringer("ip", ip),
			zap.Bool("isPublic", hostIsPublic),
		)
	}

	listenAddress := net.JoinHostPort(n.Config.HTTPHost, strconv.FormatUint(uint64(n.Config.HTTPPort), 10))
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return err
	}

	addr := listener.Addr().String()
	ipPort, err := ips.ToIPPort(addr)
	if err != nil {
		return err
	}

	// Don't open the HTTP port if the HTTP server is private
	if hostIsPublic {
		n.Log.Warn("HTTP server is binding to a potentially public host. "+
			"You may be vulnerable to a DoS attack if your HTTP port is publicly accessible",
			zap.String("host", n.Config.HTTPHost),
		)

		n.portMapper.Map(
			ipPort.Port,
			ipPort.Port,
			httpPortName,
			nil,
			n.Config.PublicIPResolutionFreq,
		)
	}

	protocol := "http"
	if n.Config.HTTPSEnabled {
		cert, err := tls.X509KeyPair(n.Config.HTTPSCert, n.Config.HTTPSKey)
		if err != nil {
			return err
		}
		config := &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		}
		listener = tls.NewListener(listener, config)

		protocol = "https"
	}
	n.apiURI = fmt.Sprintf("%s://%s", protocol, listener.Addr())

	n.APIServer, err = server.New(
		n.Log,
		n.LogFactory,
		listener,
		n.Config.HTTPAllowedOrigins,
		n.Config.ShutdownTimeout,
		n.ID,
		n.Config.TraceConfig.Enabled,
		n.tracer,
		"api",
		n.MetricsRegisterer,
		n.Config.HTTPConfig.HTTPConfig,
		n.Config.HTTPAllowedHosts,
	)
	return err
}

// Add the default VM aliases
func (n *Node) addDefaultVMAliases() error {
	n.Log.Info("adding the default VM aliases")

	for vmID, aliases := range genesis.VMAliases {
		for _, alias := range aliases {
			if err := n.VMAliaser.Alias(vmID, alias); err != nil {
				return err
			}
		}
	}
	return nil
}

// Create the chainManager and register the following VMs:
// AVM, Simple Payments DAG, Simple Payments Chain, and Platform VM
// Assumes n.DBManager, n.vdrs all initialized (non-nil)
func (n *Node) initChainManager(cryftAssetID ids.ID) error {
	createAVMTx, err := genesis.VMGenesis(n.Config.GenesisBytes, constants.AVMID)
	if err != nil {
		return err
	}
	xChainID := createAVMTx.ID()

	createEVMTx, err := genesis.VMGenesis(n.Config.GenesisBytes, constants.EVMID)
	if err != nil {
		return err
	}
	cChainID := createEVMTx.ID()

	// If any of these chains die, the node shuts down
	criticalChains := set.Of(
		constants.PlatformChainID,
		xChainID,
		cChainID,
	)

	n.timeoutManager, err = timeout.NewManager(
		&n.Config.AdaptiveTimeoutConfig,
		n.benchlistManager,
		"requests",
		n.MetricsRegisterer,
	)
	if err != nil {
		return err
	}
	go n.Log.RecoverAndPanic(n.timeoutManager.Dispatch)

	// Routes incoming messages from peers to the appropriate chain
	err = n.chainRouter.Initialize(
		n.ID,
		n.Log,
		n.timeoutManager,
		n.Config.ConsensusShutdownTimeout,
		criticalChains,
		n.Config.SybilProtectionEnabled,
		n.Config.TrackedSubnets,
		n.Shutdown,
		n.Config.RouterHealthConfig,
		"requests",
		n.MetricsRegisterer,
	)
	if err != nil {
		return fmt.Errorf("couldn't initialize chain router: %w", err)
	}

	subnets, err := chains.NewSubnets(n.ID, n.Config.SubnetConfigs)
	if err != nil {
		return fmt.Errorf("failed to initialize subnets: %w", err)
	}
	n.chainManager = chains.New(
		&chains.ManagerConfig{
			SybilProtectionEnabled:                  n.Config.SybilProtectionEnabled,
			StakingTLSSigner:                        n.StakingTLSSigner,
			StakingTLSCert:                          n.StakingTLSCert,
			StakingBLSKey:                           n.Config.StakingSigningKey,
			Log:                                     n.Log,
			LogFactory:                              n.LogFactory,
			VMManager:                               n.VMManager,
			BlockAcceptorGroup:                      n.BlockAcceptorGroup,
			TxAcceptorGroup:                         n.TxAcceptorGroup,
			VertexAcceptorGroup:                     n.VertexAcceptorGroup,
			DB:                                      n.DB,
			MsgCreator:                              n.msgCreator,
			Router:                                  n.chainRouter,
			Net:                                     n.Net,
			Validators:                              n.vdrs,
			PartialSyncPrimaryNetwork:               n.Config.PartialSyncPrimaryNetwork,
			NodeID:                                  n.ID,
			NetworkID:                               n.Config.NetworkID,
			Server:                                  n.APIServer,
			Keystore:                                n.keystore,
			AtomicMemory:                            n.sharedMemory,
			CRYFTAssetID:                            cryftAssetID,
			XChainID:                                xChainID,
			CChainID:                                cChainID,
			CriticalChains:                          criticalChains,
			TimeoutManager:                          n.timeoutManager,
			Health:                                  n.health,
			ShutdownNodeFunc:                        n.Shutdown,
			MeterVMEnabled:                          n.Config.MeterVMEnabled,
			Metrics:                                 n.MetricsGatherer,
			SubnetConfigs:                           n.Config.SubnetConfigs,
			ChainConfigs:                            n.Config.ChainConfigs,
			FrontierPollFrequency:                   n.Config.FrontierPollFrequency,
			ConsensusAppConcurrency:                 n.Config.ConsensusAppConcurrency,
			BootstrapMaxTimeGetAncestors:            n.Config.BootstrapMaxTimeGetAncestors,
			BootstrapAncestorsMaxContainersSent:     n.Config.BootstrapAncestorsMaxContainersSent,
			BootstrapAncestorsMaxContainersReceived: n.Config.BootstrapAncestorsMaxContainersReceived,
			ApricotPhase4Time:                       version.GetApricotPhase4Time(n.Config.NetworkID),
			ApricotPhase4MinPChainHeight:            version.ApricotPhase4MinPChainHeight[n.Config.NetworkID],
			ResourceTracker:                         n.resourceTracker,
			StateSyncBeacons:                        n.Config.StateSyncIDs,
			TracingEnabled:                          n.Config.TraceConfig.Enabled,
			Tracer:                                  n.tracer,
			ChainDataDir:                            n.Config.ChainDataDir,
			Subnets:                                 subnets,
		},
	)

	// Notify the API server when new chains are created
	n.chainManager.AddRegistrant(n.APIServer)
	return nil
}

// initVMs initializes the VMs Avalanche supports + any additional vms installed as plugins.
func (n *Node) initVMs() error {
	n.Log.Info("initializing VMs")

	vdrs := n.vdrs

	// If sybil protection is disabled, we provide the P-chain its own local
	// validator manager that will not be used by the rest of the node. This
	// allows the node's validator sets to be determined by network connections.
	if !n.Config.SybilProtectionEnabled {
		vdrs = validators.NewManager()
	}

	// Register the VMs that Avalanche supports
	eUpgradeTime := version.GetEUpgradeTime(n.Config.NetworkID)
	err := utils.Err(
		n.VMManager.RegisterFactory(context.TODO(), constants.PlatformVMID, &platformvm.Factory{
			Config: platformconfig.Config{
				Chains:                    n.chainManager,
				Validators:                vdrs,
				UptimeLockedCalculator:    n.uptimeCalculator,
				SybilProtectionEnabled:    n.Config.SybilProtectionEnabled,
				PartialSyncPrimaryNetwork: n.Config.PartialSyncPrimaryNetwork,
				TrackedSubnets:            n.Config.TrackedSubnets,
				StaticFeeConfig:           n.Config.StaticConfig,
				UptimePercentage:          n.Config.UptimeRequirement,
				MinValidatorStake:         n.Config.MinValidatorStake,
				MaxValidatorStake:         n.Config.MaxValidatorStake,
				MinDelegatorStake:         n.Config.MinDelegatorStake,
				MinDelegationFee:          n.Config.MinDelegationFee,
				MinStakeDuration:          n.Config.MinStakeDuration,
				MaxStakeDuration:          n.Config.MaxStakeDuration,
				RewardConfig:              n.Config.RewardConfig,
				UpgradeConfig: upgrade.Config{
					ApricotPhase3Time: version.GetApricotPhase3Time(n.Config.NetworkID),
					ApricotPhase5Time: version.GetApricotPhase5Time(n.Config.NetworkID),
					BanffTime:         version.GetBanffTime(n.Config.NetworkID),
					CortinaTime:       version.GetCortinaTime(n.Config.NetworkID),
					DurangoTime:       version.GetDurangoTime(n.Config.NetworkID),
					EUpgradeTime:      eUpgradeTime,
				},
				UseCurrentHeight: n.Config.UseCurrentHeight,
			},
		}),
		n.VMManager.RegisterFactory(context.TODO(), constants.AVMID, &avm.Factory{
			Config: avmconfig.Config{
				TxFee:            n.Config.TxFee,
				CreateAssetTxFee: n.Config.CreateAssetTxFee,
				EUpgradeTime:     eUpgradeTime,
			},
		}),
		n.VMManager.RegisterFactory(context.TODO(), constants.EVMID, &coreth.Factory{}),
	)
	if err != nil {
		return err
	}

	// initialize vm runtime manager
	n.runtimeManager = runtime.NewManager()

	// initialize the vm registry
	n.VMRegistry = registry.NewVMRegistry(registry.VMRegistryConfig{
		VMGetter: registry.NewVMGetter(registry.VMGetterConfig{
			FileReader:      filesystem.NewReader(),
			Manager:         n.VMManager,
			PluginDirectory: n.Config.PluginDir,
			CPUTracker:      n.resourceManager,
			RuntimeTracker:  n.runtimeManager,
		}),
		VMManager: n.VMManager,
	})

	// register any vms that need to be installed as plugins from disk
	_, failedVMs, err := n.VMRegistry.Reload(context.TODO())
	for failedVM, err := range failedVMs {
		n.Log.Error("failed to register VM",
			zap.Stringer("vmID", failedVM),
			zap.Error(err),
		)
	}
	return err
}

// initSharedMemory initializes the shared memory for cross chain interation
func (n *Node) initSharedMemory() {
	n.Log.Info("initializing SharedMemory")
	sharedMemoryDB := prefixdb.New([]byte("shared memory"), n.DB)
	n.sharedMemory = atomic.NewMemory(sharedMemoryDB)
}

// initKeystoreAPI initializes the keystore service, which is an on-node wallet.
// Assumes n.APIServer is already set
func (n *Node) initKeystoreAPI() error {
	n.Log.Info("initializing keystore")
	n.keystore = keystore.New(n.Log, prefixdb.New(keystoreDBPrefix, n.DB))
	handler, err := n.keystore.CreateHandler()
	if err != nil {
		return err
	}
	if !n.Config.KeystoreAPIEnabled {
		n.Log.Info("skipping keystore API initialization because it has been disabled")
		return nil
	}
	n.Log.Warn("initializing deprecated keystore API")
	return n.APIServer.AddRoute(handler, "keystore", "")
}

// initMetricsAPI initializes the Metrics API
// Assumes n.APIServer is already set
func (n *Node) initMetricsAPI() error {
	if !n.Config.MetricsAPIEnabled {
		n.Log.Info("skipping metrics API initialization because it has been disabled")
		return nil
	}

	if err := n.MetricsGatherer.Register(constants.PlatformName, n.MetricsRegisterer); err != nil {
		return err
	}

	// Current state of process metrics.
	processCollector := collectors.NewProcessCollector(collectors.ProcessCollectorOpts{})
	if err := n.MetricsRegisterer.Register(processCollector); err != nil {
		return err
	}

	// Go process metrics using debug.GCStats.
	goCollector := collectors.NewGoCollector()
	if err := n.MetricsRegisterer.Register(goCollector); err != nil {
		return err
	}

	n.Log.Info("initializing metrics API")

	return n.APIServer.AddRoute(
		promhttp.HandlerFor(
			n.MetricsGatherer,
			promhttp.HandlerOpts{},
		),
		"metrics",
		"",
	)
}

// initAdminAPI initializes the Admin API service
// Assumes n.log, n.chainManager, and n.ValidatorAPI already initialized
func (n *Node) initAdminAPI() error {
	if !n.Config.AdminAPIEnabled {
		n.Log.Info("skipping admin API initialization because it has been disabled")
		return nil
	}
	n.Log.Info("initializing admin API")
	service, err := admin.NewService(
		admin.Config{
			Log:          n.Log,
			DB:           n.DB,
			ChainManager: n.chainManager,
			HTTPServer:   n.APIServer,
			ProfileDir:   n.Config.ProfilerConfig.Dir,
			LogFactory:   n.LogFactory,
			NodeConfig:   n.Config,
			VMManager:    n.VMManager,
			VMRegistry:   n.VMRegistry,
		},
	)
	if err != nil {
		return err
	}
	return n.APIServer.AddRoute(
		service,
		"admin",
		"",
	)
}

// initProfiler initializes the continuous profiling
func (n *Node) initProfiler() {
	if !n.Config.ProfilerConfig.Enabled {
		n.Log.Info("skipping profiler initialization because it has been disabled")
		return
	}

	n.Log.Info("initializing continuous profiler")
	n.profiler = profiler.NewContinuous(
		filepath.Join(n.Config.ProfilerConfig.Dir, "continuous"),
		n.Config.ProfilerConfig.Freq,
		n.Config.ProfilerConfig.MaxNumFiles,
	)
	go n.Log.RecoverAndPanic(func() {
		err := n.profiler.Dispatch()
		if err != nil {
			n.Log.Fatal("continuous profiler failed",
				zap.Error(err),
			)
		}
		n.Shutdown(1)
	})
}

func (n *Node) initInfoAPI() error {
	if !n.Config.InfoAPIEnabled {
		n.Log.Info("skipping info API initialization because it has been disabled")
		return nil
	}

	n.Log.Info("initializing info API")

	service, err := info.NewService(
		info.Parameters{
			Version:                       version.CurrentApp,
			NodeID:                        n.ID,
			NodePOP:                       signer.NewProofOfPossession(n.Config.StakingSigningKey),
			NetworkID:                     n.Config.NetworkID,
			TxFee:                         n.Config.TxFee,
			CreateAssetTxFee:              n.Config.CreateAssetTxFee,
			CreateSubnetTxFee:             n.Config.CreateSubnetTxFee,
			TransformSubnetTxFee:          n.Config.TransformSubnetTxFee,
			CreateBlockchainTxFee:         n.Config.CreateBlockchainTxFee,
			AddPrimaryNetworkValidatorFee: n.Config.AddPrimaryNetworkValidatorFee,
			AddPrimaryNetworkDelegatorFee: n.Config.AddPrimaryNetworkDelegatorFee,
			AddSubnetValidatorFee:         n.Config.AddSubnetValidatorFee,
			AddSubnetDelegatorFee:         n.Config.AddSubnetDelegatorFee,
			VMManager:                     n.VMManager,
			// Optional hook; safe even if runtimeClient is nil.
			GetRuntimeInfoFn: func(r *http.Request) (*runtimeinfo.RuntimeInfo, error) {
				return n.GetRuntimeInfo(r.Context())
			},
		},
		n.Log,
		n.vdrs,
		n.chainManager,
		n.VMManager,
		n.Config.NetworkConfig.MyIPPort,
		n.Net,
		n.benchlistManager,
	)
	if err != nil {
		return err
	}
	return n.APIServer.AddRoute(service, "info", "")
}

// initHealthAPI initializes the Health API service
// Assumes n.Log, n.Net, n.APIServer, n.HTTPLog already initialized
func (n *Node) initHealthAPI() error {
	healthChecker, err := health.New(n.Log, n.MetricsRegisterer)
	if err != nil {
		return err
	}
	n.health = healthChecker

	if !n.Config.HealthAPIEnabled {
		n.Log.Info("skipping health API initialization because it has been disabled")
		return nil
	}

	n.Log.Info("initializing Health API")
	err = healthChecker.RegisterHealthCheck("network", n.Net, health.ApplicationTag)
	if err != nil {
		return fmt.Errorf("couldn't register network health check: %w", err)
	}

	err = healthChecker.RegisterHealthCheck("router", n.chainRouter, health.ApplicationTag)
	if err != nil {
		return fmt.Errorf("couldn't register router health check: %w", err)
	}

	// TODO: add database health to liveness check
	err = healthChecker.RegisterHealthCheck("database", n.DB, health.ApplicationTag)
	if err != nil {
		return fmt.Errorf("couldn't register database health check: %w", err)
	}

	diskSpaceCheck := health.CheckerFunc(func(context.Context) (interface{}, error) {
		// confirm that the node has enough disk space to continue operating
		// if there is too little disk space remaining, first report unhealthy and then shutdown the node

		availableDiskBytes := n.resourceTracker.DiskTracker().AvailableDiskBytes()

		var err error
		if availableDiskBytes < n.Config.RequiredAvailableDiskSpace {
			n.Log.Fatal("low on disk space. Shutting down...",
				zap.Uint64("remainingDiskBytes", availableDiskBytes),
			)
			err = fmt.Errorf("remaining available disk space (%d) is below minimum required available space (%d)", availableDiskBytes, n.Config.RequiredAvailableDiskSpace)
		} else if availableDiskBytes < n.Config.WarningThresholdAvailableDiskSpace {
			err = fmt.Errorf("remaining available disk space (%d) is below the warning threshold of disk space (%d)", availableDiskBytes, n.Config.WarningThresholdAvailableDiskSpace)
		}

		return map[string]interface{}{
			"availableDiskBytes": availableDiskBytes,
		}, err
	})

	err = n.health.RegisterHealthCheck("diskspace", diskSpaceCheck, health.ApplicationTag)
	if err != nil {
		return fmt.Errorf("couldn't register resource health check: %w", err)
	}

	handler, err := health.NewGetAndPostHandler(n.Log, healthChecker)
	if err != nil {
		return err
	}

	err = n.APIServer.AddRoute(
		handler,
		"health",
		"",
	)
	if err != nil {
		return err
	}

	err = n.APIServer.AddRoute(
		health.NewGetHandler(healthChecker.Readiness),
		"health",
		"/readiness",
	)
	if err != nil {
		return err
	}

	err = n.APIServer.AddRoute(
		health.NewGetHandler(healthChecker.Health),
		"health",
		"/health",
	)
	if err != nil {
		return err
	}

	return n.APIServer.AddRoute(
		health.NewGetHandler(healthChecker.Liveness),
		"health",
		"/liveness",
	)
}

// Give chains aliases as specified by the genesis information
func (n *Node) initChainAliases(genesisBytes []byte) error {
	n.Log.Info("initializing chain aliases")
	_, chainAliases, err := genesis.Aliases(genesisBytes)
	if err != nil {
		return err
	}

	for chainID, aliases := range chainAliases {
		for _, alias := range aliases {
			if err := n.chainManager.Alias(chainID, alias); err != nil {
				return err
			}
		}
	}

	for chainID, aliases := range n.Config.ChainAliases {
		for _, alias := range aliases {
			if err := n.chainManager.Alias(chainID, alias); err != nil {
				return err
			}
		}
	}

	return nil
}

// APIs aliases as specified by the genesis information
func (n *Node) initAPIAliases(genesisBytes []byte) error {
	n.Log.Info("initializing API aliases")
	apiAliases, _, err := genesis.Aliases(genesisBytes)
	if err != nil {
		return err
	}

	for url, aliases := range apiAliases {
		if err := n.APIServer.AddAliases(url, aliases...); err != nil {
			return err
		}
	}
	return nil
}

// Initialize [n.resourceManager].
func (n *Node) initResourceManager(reg prometheus.Registerer) error {
	resourceManager, err := resource.NewManager(
		n.Log,
		n.Config.DatabaseConfig.Path,
		n.Config.SystemTrackerFrequency,
		n.Config.SystemTrackerCPUHalflife,
		n.Config.SystemTrackerDiskHalflife,
		reg,
	)
	if err != nil {
		return err
	}
	n.resourceManager = resourceManager
	n.resourceManager.TrackProcess(os.Getpid())

	n.resourceTracker, err = tracker.NewResourceTracker(reg, n.resourceManager, &meter.ContinuousFactory{}, n.Config.SystemTrackerProcessingHalflife)
	return err
}

// Initialize [n.cpuTargeter].
// Assumes [n.resourceTracker] is already initialized.
func (n *Node) initCPUTargeter(
	config *tracker.TargeterConfig,
) {
	n.cpuTargeter = tracker.NewTargeter(
		n.Log,
		config,
		n.vdrs,
		n.resourceTracker.CPUTracker(),
	)
}

// Initialize [n.diskTargeter].
// Assumes [n.resourceTracker] is already initialized.
func (n *Node) initDiskTargeter(
	config *tracker.TargeterConfig,
) {
	n.diskTargeter = tracker.NewTargeter(
		n.Log,
		config,
		n.vdrs,
		n.resourceTracker.DiskTracker(),
	)
}

// New returns an instance of Node
func New(
	config *Config,
	logFactory logging.Factory,
	logger logging.Logger,
) (*Node, error) {
	tlsCert := config.StakingTLSCert.Leaf
	stakingCert, err := staking.ParseCertificate(tlsCert.Raw)
	if err != nil {
		return nil, fmt.Errorf("invalid staking certificate: %w", err)
	}

	n := &Node{
		Log:              logger,
		LogFactory:       logFactory,
		StakingTLSSigner: config.StakingTLSCert.PrivateKey.(crypto.Signer),
		StakingTLSCert:   stakingCert,
		ID:               ids.NodeIDFromCert(stakingCert),
		Config:           config,
	}

	// Cryftee manager - only if Web3Signer is enabled
	if config.Web3SignerEnabled {
		if config.CryfteeBinaryPath == "" {
			return nil, fmt.Errorf("--staking-web3signer-enabled requires --cryftee-binary-path to be set")
		}

		// Determine transport settings
		transport := CryfteeTransport(config.RuntimeCryfteeTransport)
		if transport == "" {
			transport = TransportUDS
		}

		// Create managed cryftee sidecar manager
		n.cryfteeManager = NewCryfteeManager(CryfteeManagerConfig{
			BinaryPath:               config.CryfteeBinaryPath,
			Transport:                transport,
			SocketPath:               config.RuntimeCryfteeSocket,
			HTTPAddr:                 config.RuntimeCryfteeHTTPAddr,
			Web3SignerURL:            config.Web3SignerURL,
			StartupTimeout:           config.CryfteeStartupTimeout,
			ExpectedHashes:           config.CryfteeExpectedHashes,
			Web3SignerEnabled:        config.Web3SignerEnabled,
			Web3SignerEphemeral:      config.Web3SignerEphemeral,
			Web3SignerKeyMaterialB64: config.Web3SignerKeyMaterialB64,
			KeyDataDir:               filepath.Join(config.DatabaseConfig.Path, "..", "staking"),
		}, logger)

		ctx, cancel := context.WithTimeout(context.Background(), config.CryfteeStartupTimeout)
		defer cancel()

		// Start cryftee if we're managing the binary
		if err := n.cryfteeManager.Start(ctx); err != nil {
			return nil, fmt.Errorf("failed to start cryftee: %w", err)
		}

		// Verify Web3Signer is connected and ready
		status, err := n.cryfteeManager.VerifySignerReady(ctx)
		if err != nil {
			_ = n.cryfteeManager.Stop()
			return nil, fmt.Errorf("Web3Signer not ready: %w", err)
		}

		// Initialize keys using the new verify/generate flow
		// CryftGo's local store is authoritative - verify existing or generate new
		blsKeyInfo, tlsKeyInfo, err := n.cryfteeManager.InitKeys(ctx, status)
		if err != nil {
			_ = n.cryfteeManager.Stop()
			return nil, fmt.Errorf("key initialization failed: %w", err)
		}

		// Parse NodeID from the TLS key info
		nodeID, err := ids.NodeIDFromString(tlsKeyInfo.NodeID)
		if err != nil {
			_ = n.cryfteeManager.Stop()
			return nil, fmt.Errorf("invalid NodeID from cryftee: %s: %w", tlsKeyInfo.NodeID, err)
		}

		n.ID = nodeID
		logger.Info("node identity obtained from cryftee/Web3Signer",
			zap.Stringer("nodeID", n.ID),
			zap.String("blsPubkey", truncateKey(blsKeyInfo.PublicKey)),
			zap.String("tlsPubkey", truncateKey(tlsKeyInfo.PublicKey)),
		)

		// Start heartbeat goroutine
		go n.startCryfteeHeartbeat()
	} else if config.CryfteeBinaryPath != "" {
		// Cryftee binary specified but Web3Signer not enabled - just start for runtime info
		logger.Info("starting cryftee for runtime info only (Web3Signer disabled)")

		transport := CryfteeTransport(config.RuntimeCryfteeTransport)
		if transport == "" {
			transport = TransportUDS
		}

		n.cryfteeManager = NewCryfteeManager(CryfteeManagerConfig{
			BinaryPath:     config.CryfteeBinaryPath,
			Transport:      transport,
			SocketPath:     config.RuntimeCryfteeSocket,
			HTTPAddr:       config.RuntimeCryfteeHTTPAddr,
			StartupTimeout: config.CryfteeStartupTimeout,
			ExpectedHashes: config.CryfteeExpectedHashes,
		}, logger)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := n.cryfteeManager.Start(ctx); err != nil {
			return nil, fmt.Errorf("failed to start cryftee sidecar: %w", err)
		}

		logger.Info("cryftee sidecar started (runtime info mode)",
			zap.String("verifiedHash", n.cryfteeManager.VerifiedHash()),
		)
	}

	// Runtime info client - only if explicitly enabled
	if config.RuntimeCryfteeEnabled {
		logger.Info("initializing Cryftee runtime client",
			zap.String("transport", config.RuntimeCryfteeTransport),
			zap.String("socket", config.RuntimeCryfteeSocket),
			zap.String("httpAddr", config.RuntimeCryfteeHTTPAddr),
			zap.Duration("timeout", config.RuntimeCryfteeTimeout),
		)
		n.runtimeClient = NewRuntimeInfoClient(RuntimeInfoClientConfig{
			Transport: config.RuntimeCryfteeTransport,
			Socket:    config.RuntimeCryfteeSocket,
			URL:       config.RuntimeCryfteeHTTPAddr,
			Timeout:   config.RuntimeCryfteeTimeout,
		})
	}

	n.DoneShuttingDown.Add(1)

	// In local-signing mode, we can construct and log a proof of possession
	// derived from the in-process BLS signing key. When Web3Signer / Cryftee-
	// backed staking is enabled, the BLS key and POP are owned by the remote
	// signer. In that case we avoid constructing a POP here; a future Cryftee
	// client can surface the POP via runtime info APIs instead.
	var pop *signer.ProofOfPossession
	if n.Config.StakingSigningKey != nil {
		// Local mode - construct POP from local key
		pop = signer.NewProofOfPossession(n.Config.StakingSigningKey)
	} else if n.Config.Web3SignerEnabled {
		// Remote mode - POP managed by cryftee (not constructed locally)
		logger.Info("web3signer-backed staking enabled; local BLS staking key/POP are managed externally via Cryftee/Web3Signer")
	}

	logger.Info("initializing node",
		zap.Stringer("version", version.CurrentApp),
		zap.Stringer("nodeID", n.ID),
		zap.Stringer("stakingKeyType", tlsCert.PublicKeyAlgorithm),
		zap.Reflect("nodePOP", pop),
		zap.Reflect("providedFlags", n.Config.ProvidedFlags),
		zap.Reflect("config", n.Config),
	)

	n.VMFactoryLog, err = logFactory.Make("vm-factory")
	if err != nil {
		return nil, fmt.Errorf("problem creating vm logger: %w", err)
	}

	n.VMAliaser = ids.NewAliaser()
	for vmID, aliases := range config.VMAliases {
		for _, alias := range aliases {
			if err := n.VMAliaser.Alias(vmID, alias); err != nil {
				return nil, err
			}
		}
	}
	n.VMManager = vms.NewManager(n.VMFactoryLog, n.VMAliaser)

	if err := n.initBootstrappers(); err != nil { // Configure the bootstrappers
		return nil, fmt.Errorf("problem initializing node beacons: %w", err)
	}

	// Set up tracer
	n.tracer, err = trace.New(n.Config.TraceConfig)
	if err != nil {
		return nil, fmt.Errorf("couldn't initialize tracer: %w", err)
	}

	n.initMetrics()
	n.initNAT()
	if err := n.initAPIServer(); err != nil { // Start the API Server
		return nil, fmt.Errorf("couldn't initialize API server: %w", err)
	}

	if err := n.initMetricsAPI(); err != nil { // Start the Metrics API
		return nil, fmt.Errorf("couldn't initialize metrics API: %w", err)
	}

	if err := n.initDatabase(); err != nil { // Set up the node's database
		return nil, fmt.Errorf("problem initializing database: %w", err)
	}

	if err := n.initKeystoreAPI(); err != nil { // Start the Keystore API
		return nil, fmt.Errorf("couldn't initialize keystore API: %w", err)
	}

	n.initSharedMemory() // Initialize shared memory

	// message.Creator is shared between networking, chainManager and the engine.
	// It must be initiated before networking (initNetworking), chain manager (initChainManager)
	// and the engine (initChains) but after the metrics (initMetricsAPI)
	// message.Creator currently record metrics under network namespace
	n.networkNamespace = "network"
	n.msgCreator, err = message.NewCreator(
		n.Log,
		n.MetricsRegisterer,
		n.networkNamespace,
		n.Config.NetworkConfig.CompressionType,
		n.Config.NetworkConfig.MaximumInboundMessageTimeout,
	)
	if err != nil {
		return nil, fmt.Errorf("problem initializing message creator: %w", err)
	}

	n.vdrs = validators.NewManager()
	if !n.Config.SybilProtectionEnabled {
		logger.Warn("sybil control is not enforced")
		n.vdrs = newOverriddenManager(constants.PrimaryNetworkID, n.vdrs)
	}
	if err := n.initResourceManager(n.MetricsRegisterer); err != nil {
		return nil, fmt.Errorf("problem initializing resource manager: %w", err)
	}
	n.initCPUTargeter(&config.CPUTargeterConfig)
	n.initDiskTargeter(&config.DiskTargeterConfig)
	if err := n.initNetworking(); err != nil { // Set up networking layer.
		return nil, fmt.Errorf("problem initializing networking: %w", err)
	}

	n.initEventDispatchers()

	// Start the Health API
	// Has to be initialized before chain manager
	// [n.Net] must already be set
	if err := n.initHealthAPI(); err != nil {
		return nil, fmt.Errorf("couldn't initialize health API: %w", err)
	}
	if err := n.addDefaultVMAliases(); err != nil {
		return nil, fmt.Errorf("couldn't initialize API aliases: %w", err)
	}
	if err := n.initChainManager(n.Config.CryftAssetID); err != nil { // Set up the chain manager
		return nil, fmt.Errorf("couldn't initialize chain manager: %w", err)
	}
	if err := n.initVMs(); err != nil { // Initialize the VM registry.
		return nil, fmt.Errorf("couldn't initialize VM registry: %w", err)
	}
	if err := n.initAdminAPI(); err != nil { // Start the Admin API
		return nil, fmt.Errorf("couldn't initialize admin API: %w", err)
	}
	if err := n.initInfoAPI(); err != nil { // Start the Info API
		return nil, fmt.Errorf("couldn't initialize info API: %w", err)
	}
	if err := n.initChainAliases(n.Config.GenesisBytes); err != nil {
		return nil, fmt.Errorf("couldn't initialize chain aliases: %w", err)
	}
	if err := n.initAPIAliases(n.Config.GenesisBytes); err != nil {
		return nil, fmt.Errorf("couldn't initialize API aliases: %w", err)
	}
	if err := n.initIndexer(); err != nil {
		return nil, fmt.Errorf("couldn't initialize indexer: %w", err)
	}

	n.health.Start(context.TODO(), n.Config.HealthCheckFreq)
	n.initProfiler()

	// Start the Platform chain
	if err := n.initChains(n.Config.GenesisBytes); err != nil {
		return nil, fmt.Errorf("couldn't initialize chains: %w", err)
	}
	return n, nil
}

// extractHostPort extracts host:port from a URL string.
// Returns empty string if URL is invalid.
func extractHostPort(urlStr string) string {
	if urlStr == "" {
		return ""
	}
	// Simple extraction - assumes format http://host:port or https://host:port
	// For production, use net/url.Parse
	if len(urlStr) > 7 && urlStr[:7] == "http://" {
		return urlStr[7:]
	}
	if len(urlStr) > 8 && urlStr[:8] == "https://" {
		return urlStr[8:]
	}
	return urlStr
}

// NodeProcessContext is used to store information about the node's process
type NodeProcessContext struct {
	// The process id of the node
	PID int `json:"pid"`
	// URI to access the node API
	// Format: [https|http]://[host]:[port]
	URI string `json:"uri"`
	// Address other nodes can use to communicate with this node
	// Format: [host]:[port]
	StakingAddress string `json:"stakingAddress"`
}

// Write process context to the configured path. Supports the use of
// dynamically chosen network ports with local network orchestration.
func (n *Node) writeProcessContext() error {
	n.Log.Info("writing process context", zap.String("path", n.Config.ProcessContextFilePath))

	// Write the process context to disk
	processContext := &NodeProcessContext{
		PID:            os.Getpid(),
		URI:            n.apiURI,
		StakingAddress: n.stakingAddress, // Set by network initialization
	}
	bytes, err := json.MarshalIndent(processContext, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal process context: %w", err)
	}
	if err := perms.WriteFile(n.Config.ProcessContextFilePath, bytes, perms.ReadWrite); err != nil {
		return fmt.Errorf("failed to write process context: %w", err)
	}
	return nil
}

// Dispatch starts the node's servers.
// Returns when the node exits.
func (n *Node) Dispatch() error {
	if err := n.writeProcessContext(); err != nil {
		return err
	}

	// Start the HTTP API server
	go n.Log.RecoverAndPanic(func() {
		n.Log.Info("API server listening",
			zap.String("uri", n.apiURI),
		)
		err := n.APIServer.Dispatch()
		// When [n].Shutdown() is called, [n.APIServer].Close() is called.
		// This causes [n.APIServer].Dispatch() to return an error.
		// If that happened, don't log/return an error here.
		if !n.shuttingDown.Get() {
			n.Log.Fatal("API server dispatch failed",
				zap.Error(err),
			)
		}
		// If the API server isn't running, shut down the node.
		// If node is already shutting down, this does nothing.
		n.Shutdown(1)
	})

	// Add state sync nodes to the peer network
	for i, peerIP := range n.Config.StateSyncIPs {
		n.Net.ManuallyTrack(n.Config.StateSyncIDs[i], peerIP)
	}

	// Add bootstrap nodes to the peer network
	for _, bootstrapper := range n.Config.Bootstrappers {
		n.Net.ManuallyTrack(bootstrapper.ID, ips.IPPort(bootstrapper.IP))
	}

	// Start P2P connections
	err := n.Net.Dispatch()

	// If the P2P server isn't running, shut down the node.
	// If node is already shutting down, this does nothing.
	n.Shutdown(1)

	if n.tlsKeyLogWriterCloser != nil {
		err := n.tlsKeyLogWriterCloser.Close()
		if err != nil {
			n.Log.Error("closing TLS key log file failed",
				zap.String("filename", n.Config.NetworkConfig.TLSKeyLogFile),
				zap.Error(err),
			)
		}
	}

	// Wait until the node is done shutting down before returning
	n.DoneShuttingDown.Wait()

	// Remove the process context file to communicate to an orchestrator
	// that the node is no longer running.
	if err := os.Remove(n.Config.ProcessContextFilePath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		n.Log.Error("removal of process context file failed",
			zap.String("path", n.Config.ProcessContextFilePath),
			zap.Error(err),
		)
	}

	return err
}

/*
 ******************************************************************************
 *********************** End P2P Networking Section ***************************
 ******************************************************************************
 */

// Shutdown this node
// May be called multiple times
func (n *Node) Shutdown(exitCode int) {
	if !n.shuttingDown.Get() { // only set the exit code once
		n.shuttingDownExitCode.Set(exitCode)
	}
	n.shuttingDown.Set(true)
	n.shutdownOnce.Do(n.shutdown)
}

func (n *Node) shutdown() {
	n.Log.Info("shutting down node",
		zap.Int("exitCode", n.ExitCode()),
	)

	if n.health != nil {
		// Passes if the node is not shutting down
		shuttingDownCheck := health.CheckerFunc(func(context.Context) (interface{}, error) {
			return map[string]interface{}{
				"isShuttingDown": true,
			}, errShuttingDown
		})

		err := n.health.RegisterHealthCheck("shuttingDown", shuttingDownCheck, health.ApplicationTag)
		if err != nil {
			n.Log.Debug("couldn't register shuttingDown health check",
				zap.Error(err),
			)
		}

		time.Sleep(n.Config.ShutdownWait)
	}

	if n.resourceManager != nil {
		n.resourceManager.Shutdown()
	}
	if n.timeoutManager != nil {
		n.timeoutManager.Stop()
	}
	if n.chainManager != nil {
		n.chainManager.Shutdown()
	}
	if n.profiler != nil {
		n.profiler.Shutdown()
	}
	if n.Net != nil {
		n.Net.StartClose()
	}
	if n.APIServer != nil {
		if err := n.APIServer.Shutdown(); err != nil {
			n.Log.Debug("error during API shutdown",
				zap.Error(err),
			)
		}
	}
	if n.portMapper != nil {
		n.portMapper.UnmapAllPorts()
	}
	if n.ipUpdater != nil {
		n.ipUpdater.Stop()
	}
	if n.indexer != nil {
		if err := n.indexer.Close(); err != nil {
			n.Log.Debug("error closing tx indexer",
				zap.Error(err),
			)
		}
	}

	// Ensure all runtimes are shutdown
	if n.runtimeManager != nil {
		n.Log.Info("cleaning up plugin runtimes")
		n.runtimeManager.Stop(context.TODO())
	}

	// Stop managed cryftee sidecar if running
	if n.cryfteeManager != nil {
		if err := n.cryfteeManager.Stop(); err != nil {
			n.Log.Warn("error stopping cryftee sidecar",
				zap.Error(err),
			)
		}
	}

	if n.DB != nil {
		if err := n.DB.Delete(ungracefulShutdown); err != nil {
			n.Log.Error(
				"failed to delete ungraceful shutdown key",
				zap.Error(err),
			)
		}

		if err := n.DB.Close(); err != nil {
			n.Log.Warn("error during DB shutdown",
				zap.Error(err),
			)
		}
	}

	if n.Config.TraceConfig.Enabled {
		n.Log.Info("shutting down tracing")
	}

	if n.tracer != nil {
		if err := n.tracer.Close(); err != nil {
			n.Log.Warn("error during tracer shutdown",
				zap.Error(err),
			)
		}
	}

	n.DoneShuttingDown.Done()
	n.Log.Info("finished node shutdown")
}

func (n *Node) ExitCode() int {
	return n.shuttingDownExitCode.Get()
}

// GetRuntimeInfo proxies runtime/pin health from the configured Cryftee sidecar.
// If the runtime client is not configured, it just returns an error.
func (n *Node) GetRuntimeInfo(ctx context.Context) (*runtimeinfo.RuntimeInfo, error) {
	if n.runtimeClient == nil {
		return nil, errors.New("runtime info client not configured")
	}
	return n.runtimeClient.GetRuntimeInfo(ctx)
}

// Add this function somewhere after initEventDispatchers and before initIndexer
// (around line 540 based on current structure)

func (n *Node) initDatabase() error {
	// start the db
	switch n.Config.DatabaseConfig.Name {
	case leveldb.Name:
		// Prior to v1.10.15, the only on-disk database was leveldb, and its
		// files went to [dbPath]/[networkID]/v1.4.5.
		dbPath := filepath.Join(n.Config.DatabaseConfig.Path, version.CurrentDatabase.String())
		var err error
		n.DB, err = leveldb.New(dbPath, n.Config.DatabaseConfig.Config, n.Log, "db_internal", n.MetricsRegisterer)
		if err != nil {
			return fmt.Errorf("couldn't create leveldb at %s: %w", dbPath, err)
		}
	case memdb.Name:
		n.DB = memdb.New()
	case pebble.Name:
		dbPath := filepath.Join(n.Config.DatabaseConfig.Path, pebble.Name)
		var err error
		n.DB, err = pebble.New(dbPath, n.Config.DatabaseConfig.Config, n.Log, "db_internal", n.MetricsRegisterer)
		if err != nil {
			return fmt.Errorf("couldn't create pebbledb at %s: %w", dbPath, err)
		}
	default:
		return fmt.Errorf(
			"db-type was %q but should have been one of {%s, %s, %s}",
			n.Config.DatabaseConfig.Name,
			leveldb.Name,
			memdb.Name,
			pebble.Name,
		)
	}

	if n.Config.ReadOnly && n.Config.DatabaseConfig.Name != memdb.Name {
		n.DB = versiondb.New(n.DB)
	}

	var err error
	n.DB, err = meterdb.New("db", n.MetricsRegisterer, n.DB)
	if err != nil {
		return err
	}

	rawExpectedGenesisHash := hashing.ComputeHash256(n.Config.GenesisBytes)

	rawGenesisHash, err := n.DB.Get(genesisHashKey)
	if err == database.ErrNotFound {
		rawGenesisHash = rawExpectedGenesisHash
		err = n.DB.Put(genesisHashKey, rawGenesisHash)
	}
	if err != nil {
		return err
	}

	genesisHash, err := ids.ToID(rawGenesisHash)
	if err != nil {
		return err
	}
	expectedGenesisHash, err := ids.ToID(rawExpectedGenesisHash)
	if err != nil {
		return err
	}

	if genesisHash != expectedGenesisHash {
		return fmt.Errorf("db contains invalid genesis hash. DB Genesis: %s Generated Genesis: %s", genesisHash, expectedGenesisHash)
	}

	n.Log.Info("initializing database",
		zap.Stringer("genesisHash", genesisHash),
	)

	ok, err := n.DB.Has(ungracefulShutdown)
	if err != nil {
		return fmt.Errorf("failed to read ungraceful shutdown key: %w", err)
	}

	if ok {
		n.Log.Warn("detected previous ungraceful shutdown")
	}

	if err := n.DB.Put(ungracefulShutdown, nil); err != nil {
		return fmt.Errorf(
			"failed to write ungraceful shutdown key at: %w",
			err,
		)
	}

	return nil
}

// initCryfttee initializes the CryftTEE sidecar client for key management
func (n *Node) initCryfttee() error {
	n.Log.Info("initializing CryftTEE integration",
		zap.Bool("web3SignerEnabled", n.Config.Web3SignerEnabled),
		zap.String("transport", n.Config.RuntimeCryfteeTransport),
		zap.String("socketPath", n.Config.RuntimeCryfteeSocket),
		zap.String("httpAddr", n.Config.RuntimeCryfteeHTTPAddr),
		zap.Duration("timeout", n.Config.RuntimeCryfteeTimeout),
		zap.Bool("runtimeEnabled", n.Config.RuntimeCryfteeEnabled),
	)

	if !n.Config.RuntimeCryfteeEnabled && !n.Config.Web3SignerEnabled {
		n.Log.Info("CryftTEE integration disabled, using local key management")
		return nil
	}

	// Use the existing CryfteeManager if already initialized (Web3Signer mode)
	if n.cryfteeManager != nil {
		n.Log.Info("CryftTEE manager already initialized via Web3Signer mode")
		return nil
	}

	// For standalone runtime info mode, create a runtime info client
	if n.Config.RuntimeCryfteeEnabled && n.runtimeClient == nil {
		n.Log.Info("creating standalone CryftTEE runtime info client")
		n.runtimeClient = NewRuntimeInfoClient(RuntimeInfoClientConfig{
			Transport: n.Config.RuntimeCryfteeTransport,
			Socket:    n.Config.RuntimeCryfteeSocket,
			URL:       n.Config.RuntimeCryfteeHTTPAddr,
			Timeout:   n.Config.RuntimeCryfteeTimeout,
		})
	}

	return nil
}

// startCryfteeHeartbeat sends periodic heartbeats to CryftTEE
func (n *Node) startCryfteeHeartbeat() {
	if n.cryfteeManager == nil {
		return
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if n.shuttingDown.Get() {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			if err := n.cryfteeManager.SendHeartbeat(ctx, n.ID.String(), version.CurrentApp.String()); err != nil {
				n.Log.Warn("CryftTEE heartbeat failed", zap.Error(err))
			}
			cancel()
		}
	}
}
