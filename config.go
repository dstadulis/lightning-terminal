package terminal

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/jessevdk/go-flags"
	"github.com/lightninglabs/faraday"
	"github.com/lightninglabs/faraday/chain"
	"github.com/lightninglabs/faraday/frdrpcserver"
	mid "github.com/lightninglabs/lightning-terminal/rpcmiddleware"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/loop/loopd"
	"github.com/lightninglabs/pool"
	"github.com/lightningnetwork/lnd"
	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/cert"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/signal"
	"github.com/mwitkow/go-conntrack/connhelpers"
	"golang.org/x/crypto/acme/autocert"
)

const (
	defaultHTTPSListen = "127.0.0.1:8443"

	uiPasswordMinLength = 8

	ModeIntegrated = "integrated"
	ModeRemote     = "remote"

	DefaultLndMode     = ModeRemote
	defaultFaradayMode = ModeIntegrated
	defaultLoopMode    = ModeIntegrated
	defaultPoolMode    = ModeIntegrated

	defaultConfigFilename = "lit.conf"

	defaultLogLevel       = "info"
	defaultMaxLogFiles    = 3
	defaultMaxLogFileSize = 10

	defaultLetsEncryptSubDir          = "letsencrypt"
	defaultLetsEncryptListen          = ":80"
	defaultSelfSignedCertOrganization = "litd autogenerated cert"

	defaultLogDirname  = "logs"
	defaultLogFilename = "litd.log"

	DefaultTLSCertFilename = "tls.cert"
	DefaultTLSKeyFilename  = "tls.key"

	DefaultNetwork                = "mainnet"
	defaultRemoteLndRpcServer     = "localhost:10009"
	defaultRemoteFaradayRpcServer = "localhost:8465"
	defaultRemoteLoopRpcServer    = "localhost:11010"
	defaultRemotePoolRpcServer    = "localhost:12010"
	defaultLndChainSubDir         = "chain"
	defaultLndChain               = "bitcoin"
	defaultLndMacaroon            = "admin.macaroon"

	// DefaultAutogenValidity is the default validity of a self-signed
	// certificate. The value corresponds to 14 months
	// (14 months * 30 days * 24 hours).
	DefaultAutogenValidity = 14 * 30 * 24 * time.Hour

	// DefaultMacaroonFilename is the default file name for the
	// autogenerated lit macaroon.
	DefaultMacaroonFilename = "lit.macaroon"
)

var (
	lndDefaultConfig     = lnd.DefaultConfig()
	faradayDefaultConfig = faraday.DefaultConfig()
	loopDefaultConfig    = loopd.DefaultConfig()
	poolDefaultConfig    = pool.DefaultConfig()

	// DefaultLitDir is the default directory where LiT tries to find its
	// configuration file and store its data (in remote lnd node). This is a
	// directory in the user's application data, for example:
	//   C:\Users\<username>\AppData\Local\Lit on Windows
	//   ~/.lit on Linux
	//   ~/Library/Application Support/Lit on MacOS
	DefaultLitDir = btcutil.AppDataDir("lit", false)

	// DefaultTLSCertPath is the default full path of the autogenerated TLS
	// certificate that is created in remote lnd mode.
	DefaultTLSCertPath = filepath.Join(
		DefaultLitDir, DefaultTLSCertFilename,
	)

	// defaultTLSKeyPath is the default full path of the autogenerated TLS
	// key that is created in remote lnd mode.
	defaultTLSKeyPath = filepath.Join(DefaultLitDir, DefaultTLSKeyFilename)

	// defaultConfigFile is the default path for the LiT configuration file
	// that is always attempted to be loaded.
	defaultConfigFile = filepath.Join(DefaultLitDir, defaultConfigFilename)

	// defaultLogDir is the default directory in which LiT writes its log
	// files in remote lnd mode.
	defaultLogDir = filepath.Join(DefaultLitDir, defaultLogDirname)

	// defaultLetsEncryptDir is the default directory in which LiT writes
	// its Let's Encrypt files.
	defaultLetsEncryptDir = filepath.Join(
		DefaultLitDir, defaultLetsEncryptSubDir,
	)

	// DefaultRemoteLndMacaroonPath is the default path we assume for a
	// local lnd node to store its admin.macaroon file at.
	DefaultRemoteLndMacaroonPath = filepath.Join(
		lndDefaultConfig.DataDir, defaultLndChainSubDir,
		defaultLndChain, DefaultNetwork, defaultLndMacaroon,
	)

	// DefaultMacaroonPath is the default full path of the base lit
	// macaroon.
	DefaultMacaroonPath = filepath.Join(
		DefaultLitDir, DefaultNetwork, DefaultMacaroonFilename,
	)
)

// Config is the main configuration struct of lightning-terminal. It contains
// all config items of its enveloping subservers, each prefixed with their
// daemon's short name.
type Config struct {
	HTTPSListen    string   `long:"httpslisten" description:"The host:port to listen for incoming HTTP/2 connections on for the web UI only."`
	HTTPListen     string   `long:"insecure-httplisten" description:"The host:port to listen on with TLS disabled. This is dangerous to enable as credentials will be submitted without encryption. Should only be used in combination with Tor hidden services or other external encryption."`
	EnableREST     bool     `long:"enablerest" description:"Also allow REST requests to be made to the main HTTP(s) port(s) configured above."`
	RestCORS       []string `long:"restcors" description:"Add an ip:port/hostname to allow cross origin access from. To allow all origins, set as \"*\"."`
	UIPassword     string   `long:"uipassword" description:"The password that must be entered when using the loop UI. use a strong password to protect your node from unauthorized access through the web UI."`
	UIPasswordFile string   `long:"uipassword_file" description:"Same as uipassword but instead of passing in the value directly, read the password from the specified file."`
	UIPasswordEnv  string   `long:"uipassword_env" description:"Same as uipassword but instead of passing in the value directly, read the password from the specified environment variable."`

	LetsEncrypt       bool   `long:"letsencrypt" description:"Use Let's Encrypt to create a TLS certificate for the UI instead of using lnd's TLS certificate. Port 80 must be free to listen on and must be reachable from the internet for this to work."`
	LetsEncryptHost   string `long:"letsencrypthost" description:"The host name to create a Let's Encrypt certificate for."`
	LetsEncryptDir    string `long:"letsencryptdir" description:"The directory where the Let's Encrypt library will store its key and certificate."`
	LetsEncryptListen string `long:"letsencryptlisten" description:"The IP:port on which LiT will listen for Let's Encrypt challenges. Let's Encrypt will always try to contact on port 80. Often non-root processes are not allowed to bind to ports lower than 1024. This configuration option allows a different port to be used, but must be used in combination with port forwarding from port 80. This configuration can also be used to specify another IP address to listen on, for example an IPv6 address."`

	LitDir     string `long:"lit-dir" description:"The main directory where LiT looks for its configuration file. If LiT is running in 'remote' lnd mode, this is also the directory where the TLS certificates and log files are stored by default."`
	ConfigFile string `long:"configfile" description:"Path to LiT's configuration file."`

	MacaroonPath string `long:"macaroonpath" description:"Path to write the macaroon for litd's RPC and REST services if it doesn't exist."`

	// Network is the Bitcoin network we're running on. This will be parsed
	// before the configuration is loaded and will set the correct flag on
	// `lnd.bitcoin.mainnet|testnet|regtest` and also for the other daemons.
	// That way only one global network flag is needed.
	Network string `long:"network" description:"The network the UI and all its components run on" choice:"regtest" choice:"testnet" choice:"mainnet" choice:"simnet"`

	Remote *RemoteConfig `group:"Remote mode options (use when lnd-mode=remote)" namespace:"remote"`

	// LndMode is the selected mode to run lnd in. The supported modes are
	// 'integrated' and 'remote'. We only use a string instead of a bool
	// here (and for all the other daemons) to make the CLI more user
	// friendly. Because then we can reference the explicit modes in the
	// help descriptions of the section headers. We'll parse the mode into
	// a bool for internal use for better code readability.
	LndMode string      `long:"lnd-mode" description:"The mode to run lnd in, either 'remote' (default) or 'integrated'. 'integrated' means lnd is started alongside the UI and everything is stored in lnd's main data directory, configure everything by using the --lnd.* flags. 'remote' means the UI connects to an existing lnd node and acts as a proxy for gRPC calls to it. In the remote node LiT creates its own directory for log and configuration files, configure everything using the --remote.* flags." choice:"integrated" choice:"remote"`
	Lnd     *lnd.Config `group:"Integrated lnd (use when lnd-mode=integrated)" namespace:"lnd"`

	FaradayMode string          `long:"faraday-mode" description:"The mode to run faraday in, either 'integrated' (default) or 'remote'. 'integrated' means faraday is started alongside the UI and everything is stored in faraday's main data directory, configure everything by using the --faraday.* flags. 'remote' means the UI connects to an existing faraday node and acts as a proxy for gRPC calls to it." choice:"integrated" choice:"remote"`
	Faraday     *faraday.Config `group:"Integrated faraday options (use when faraday-mode=integrated)" namespace:"faraday"`

	LoopMode string        `long:"loop-mode" description:"The mode to run loop in, either 'integrated' (default) or 'remote'. 'integrated' means loopd is started alongside the UI and everything is stored in loop's main data directory, configure everything by using the --loop.* flags. 'remote' means the UI connects to an existing loopd node and acts as a proxy for gRPC calls to it." choice:"integrated" choice:"remote"`
	Loop     *loopd.Config `group:"Integrated loop options (use when loop-mode=integrated)" namespace:"loop"`

	PoolMode string       `long:"pool-mode" description:"The mode to run pool in, either 'integrated' (default) or 'remote'. 'integrated' means poold is started alongside the UI and everything is stored in pool's main data directory, configure everything by using the --pool.* flags. 'remote' means the UI connects to an existing poold node and acts as a proxy for gRPC calls to it." choice:"integrated" choice:"remote"`
	Pool     *pool.Config `group:"Integrated pool options (use when pool-mode=integrated)" namespace:"pool"`

	RPCMiddleware *mid.Config `group:"RPC middleware options" namespace:"rpcmiddleware"`

	// faradayRpcConfig is a subset of faraday's full configuration that is
	// passed into faraday's RPC server.
	faradayRpcConfig *frdrpcserver.Config

	// lndRemote is a convenience bool variable that is parsed from the
	// LndMode string variable on startup.
	lndRemote     bool
	faradayRemote bool
	loopRemote    bool
	poolRemote    bool

	// lndAdminMacaroon is the admin macaroon that is given to us by lnd
	// over an in-memory connection on startup. This is only set in
	// integrated lnd mode.
	lndAdminMacaroon []byte
}

// RemoteConfig holds the configuration parameters that are needed when running
// LiT in the "remote" lnd mode.
type RemoteConfig struct {
	LitTLSCertPath string `long:"lit-tlscertpath" description:"For lnd remote mode only: Path to write the self signed TLS certificate for LiT's RPC and REST proxy service (if Let's Encrypt is not used)."`
	LitTLSKeyPath  string `long:"lit-tlskeypath" description:"For lnd remote mode only: Path to write the self signed TLS private key for LiT's RPC and REST proxy service (if Let's Encrypt is not used)."`

	LitLogDir         string `long:"lit-logdir" description:"For lnd remote mode only: Directory to log output."`
	LitMaxLogFiles    int    `long:"lit-maxlogfiles" description:"For lnd remote mode only: Maximum logfiles to keep (0 for no rotation)"`
	LitMaxLogFileSize int    `long:"lit-maxlogfilesize" description:"For lnd remote mode only: Maximum logfile size in MB"`

	LitDebugLevel string `long:"lit-debuglevel" description:"For lnd remote mode only: Logging level for all subsystems {trace, debug, info, warn, error, critical} -- You may also specify <subsystem>=<level>,<subsystem2>=<level>,... to set the log level for individual subsystems."`

	Lnd     *RemoteDaemonConfig `group:"Remote lnd (use when lnd-mode=remote)" namespace:"lnd"`
	Faraday *RemoteDaemonConfig `group:"Remote faraday (use when faraday-mode=remote)" namespace:"faraday"`
	Loop    *RemoteDaemonConfig `group:"Remote loop (use when loop-mode=remote)" namespace:"loop"`
	Pool    *RemoteDaemonConfig `group:"Remote pool (use when pool-mode=remote)" namespace:"pool"`
}

// RemoteDaemonConfig holds the configuration parameters that are needed to
// connect to a remote daemon like lnd for example.
type RemoteDaemonConfig struct {
	// RPCServer is host:port that the remote daemon's RPC server is
	// listening on.
	RPCServer string `long:"rpcserver" description:"The host:port that the remote daemon is listening for RPC connections on."`

	// MacaroonPath is the path to the single macaroon that should be used
	// instead of needing to specify the macaroon directory that contains
	// all of the daemon's macaroons. The specified macaroon MUST have all
	// permissions that all the subservers use, otherwise permission errors
	// will occur.
	MacaroonPath string `long:"macaroonpath" description:"The full path to the single macaroon to use, either the main (admin.macaroon in lnd's case) or a custom baked one. A custom macaroon must contain ALL permissions required for all subservers to work, otherwise permission errors will occur."`

	// TLSCertPath is the path to the tls cert of the remote daemon that
	// should be used to verify the TLS identity of the remote RPC server.
	TLSCertPath string `long:"tlscertpath" description:"The full path to the remote daemon's TLS cert to use for RPC connection verification."`
}

// lndConnectParams returns the connection parameters to connect to the local
// lnd instance.
func (c *Config) lndConnectParams() (string, lndclient.Network, string,
	string, []byte) {

	// In remote lnd mode, we just pass along what was configured in the
	// remote section of the lnd config.
	if c.LndMode == ModeRemote {
		return c.Remote.Lnd.RPCServer,
			lndclient.Network(c.Network),
			lncfg.CleanAndExpandPath(c.Remote.Lnd.TLSCertPath),
			lncfg.CleanAndExpandPath(c.Remote.Lnd.MacaroonPath),
			nil
	}

	// When we start lnd internally, we take the listen address as
	// the client dial address. But with TLS enabled by default, we
	// cannot call 0.0.0.0 internally when dialing lnd as that IP
	// address isn't in the cert. We need to rewrite it to the
	// loopback address.
	lndDialAddr := c.Lnd.RPCListeners[0].String()
	switch {
	case strings.Contains(lndDialAddr, "0.0.0.0"):
		lndDialAddr = strings.Replace(
			lndDialAddr, "0.0.0.0", "127.0.0.1", 1,
		)

	case strings.Contains(lndDialAddr, "[::]"):
		lndDialAddr = strings.Replace(
			lndDialAddr, "[::]", "[::1]", 1,
		)
	}

	return lndDialAddr, lndclient.Network(c.Network), "", "",
		c.lndAdminMacaroon
}

// defaultConfig returns a configuration struct with all default values set.
func defaultConfig() *Config {
	return &Config{
		HTTPSListen: defaultHTTPSListen,
		Remote: &RemoteConfig{
			LitTLSCertPath:    DefaultTLSCertPath,
			LitTLSKeyPath:     defaultTLSKeyPath,
			LitDebugLevel:     defaultLogLevel,
			LitLogDir:         defaultLogDir,
			LitMaxLogFiles:    defaultMaxLogFiles,
			LitMaxLogFileSize: defaultMaxLogFileSize,
			Lnd: &RemoteDaemonConfig{
				RPCServer:    defaultRemoteLndRpcServer,
				MacaroonPath: DefaultRemoteLndMacaroonPath,
				TLSCertPath:  lndDefaultConfig.TLSCertPath,
			},
			Faraday: &RemoteDaemonConfig{
				RPCServer:    defaultRemoteFaradayRpcServer,
				MacaroonPath: faradayDefaultConfig.MacaroonPath,
				TLSCertPath:  faradayDefaultConfig.TLSCertPath,
			},
			Loop: &RemoteDaemonConfig{
				RPCServer:    defaultRemoteLoopRpcServer,
				MacaroonPath: loopDefaultConfig.MacaroonPath,
				TLSCertPath:  loopDefaultConfig.TLSCertPath,
			},
			Pool: &RemoteDaemonConfig{
				RPCServer:    defaultRemotePoolRpcServer,
				MacaroonPath: poolDefaultConfig.MacaroonPath,
				TLSCertPath:  poolDefaultConfig.TLSCertPath,
			},
		},
		Network:           DefaultNetwork,
		LndMode:           DefaultLndMode,
		Lnd:               &lndDefaultConfig,
		LitDir:            DefaultLitDir,
		LetsEncryptListen: defaultLetsEncryptListen,
		LetsEncryptDir:    defaultLetsEncryptDir,
		MacaroonPath:      DefaultMacaroonPath,
		ConfigFile:        defaultConfigFile,
		FaradayMode:       defaultFaradayMode,
		Faraday:           &faradayDefaultConfig,
		faradayRpcConfig:  &frdrpcserver.Config{},
		LoopMode:          defaultLoopMode,
		Loop:              &loopDefaultConfig,
		PoolMode:          defaultPoolMode,
		Pool:              &poolDefaultConfig,
		RPCMiddleware:     mid.DefaultConfig(),
	}
}

// loadAndValidateConfig loads the terminal's main configuration and validates
// its content.
func loadAndValidateConfig(interceptor signal.Interceptor) (*Config, error) {
	// Start with the default configuration.
	preCfg := defaultConfig()

	// Override the default configuration to enable the firewall.
	// TODO(elle): should we not only do this if the macaroon firewall is
	//  enabled?
	preCfg.Lnd.RPCMiddleware.Enable = true

	// Pre-parse the command line options to pick up an alternative config
	// file.
	_, err := flags.Parse(preCfg)
	if err != nil {
		return nil, fmt.Errorf("error parsing flags: %w", err)
	}

	// Show the version and exit if the version flag was specified.
	appName := filepath.Base(os.Args[0])
	appName = strings.TrimSuffix(appName, filepath.Ext(appName))
	if preCfg.Lnd.ShowVersion {
		fmt.Println(appName, "version", build.Version(),
			"commit="+build.Commit)
		os.Exit(0)
	}

	// Load the main configuration file and parse any command line options.
	// This function will also set up logging properly.
	cfg, err := loadConfigFile(preCfg, interceptor)
	if err != nil {
		return nil, err
	}

	// With the validated config obtained, we now know that the root logging
	// system of lnd is initialized and we can hook up our own loggers now.
	SetupLoggers(cfg.Lnd.LogWriter, interceptor)

	// Translate the more user friendly string modes into the more developer
	// friendly internal bool variables now.
	cfg.lndRemote = cfg.LndMode == ModeRemote
	cfg.faradayRemote = cfg.FaradayMode == ModeRemote
	cfg.loopRemote = cfg.LoopMode == ModeRemote
	cfg.poolRemote = cfg.PoolMode == ModeRemote

	// Now that we've registered all loggers, let's parse, validate, and set
	// the debug log level(s). In remote lnd mode we have a global log level
	// that overwrites all others. In integrated mode we use the lnd log
	// level as the master level.
	if cfg.lndRemote {
		err = build.ParseAndSetDebugLevels(
			cfg.Remote.LitDebugLevel, cfg.Lnd.LogWriter,
		)
	} else {
		err = build.ParseAndSetDebugLevels(
			cfg.Lnd.DebugLevel, cfg.Lnd.LogWriter,
		)
	}
	if err != nil {
		return nil, err
	}

	// Validate the lightning-terminal config options.
	litDir := lnd.CleanAndExpandPath(preCfg.LitDir)
	cfg.LetsEncryptDir = lncfg.CleanAndExpandPath(cfg.LetsEncryptDir)
	if litDir != DefaultLitDir {
		if cfg.LetsEncryptDir == defaultLetsEncryptDir {
			cfg.LetsEncryptDir = filepath.Join(
				litDir, defaultLetsEncryptSubDir,
			)
		}
	}
	if cfg.LetsEncrypt {
		if cfg.LetsEncryptHost == "" {
			return nil, fmt.Errorf("host must be set when using " +
				"let's encrypt")
		}

		// Create the directory if we're going to use Let's Encrypt.
		if err := makeDirectories(cfg.LetsEncryptDir); err != nil {
			return nil, err
		}
	}
	err = readUIPassword(cfg)
	if err != nil {
		return nil, fmt.Errorf("could not read UI password: %v", err)
	}
	if len(cfg.UIPassword) < uiPasswordMinLength {
		return nil, fmt.Errorf("please set a strong password for the "+
			"UI, at least %d characters long", uiPasswordMinLength)
	}

	if cfg.Network != DefaultNetwork {
		if cfg.MacaroonPath == DefaultMacaroonPath {
			cfg.MacaroonPath = filepath.Join(
				litDir, cfg.Network, DefaultMacaroonFilename,
			)
		}
	}

	// Initiate our listeners. For now, we only support listening on one
	// port at a time because we can only pass in one pre-configured RPC
	// listener into lnd.
	if len(cfg.Lnd.RPCListeners) > 1 {
		return nil, fmt.Errorf("litd only supports one RPC listener " +
			"at a time")
	}

	// Some of the subservers' configuration options won't have any effect
	// (like the log or lnd options) as they will be taken from lnd's config
	// struct. Others we want to force to be the same as lnd so the user
	// doesn't have to set them manually, like the network for example.
	cfg.Faraday.Lnd.MacaroonPath = faraday.DefaultLndMacaroonPath
	if err := faraday.ValidateConfig(cfg.Faraday); err != nil {
		return nil, err
	}

	defaultLoopCfg := loopd.DefaultConfig()
	cfg.Loop.Lnd.MacaroonPath = defaultLoopCfg.Lnd.MacaroonPath
	if err := loopd.Validate(cfg.Loop); err != nil {
		return nil, err
	}

	cfg.Pool.Lnd.MacaroonPath = pool.DefaultLndMacaroonPath
	if err := pool.Validate(cfg.Pool); err != nil {
		return nil, err
	}

	// We've set the network before and have now validated the loop config
	// which updated its default paths for that network. So if we're in
	// remote mode and not mainnet, we want to update our default paths for
	// the remote connection as well.
	defaultFaradayCfg := faraday.DefaultConfig()
	if cfg.faradayRemote && cfg.Network != DefaultNetwork {
		if cfg.Remote.Faraday.MacaroonPath == defaultFaradayCfg.MacaroonPath {
			cfg.Remote.Faraday.MacaroonPath = cfg.Faraday.MacaroonPath
		}
		if cfg.Remote.Faraday.TLSCertPath == defaultFaradayCfg.TLSCertPath {
			cfg.Remote.Faraday.TLSCertPath = cfg.Faraday.TLSCertPath
		}
	}

	// If the client chose to connect to a bitcoin client, get one now.
	if !cfg.faradayRemote {
		cfg.faradayRpcConfig.FaradayDir = cfg.Faraday.FaradayDir
		cfg.faradayRpcConfig.MacaroonPath = cfg.Faraday.MacaroonPath

		if cfg.Faraday.ChainConn {
			cfg.faradayRpcConfig.BitcoinClient, err = chain.NewBitcoinClient(
				cfg.Faraday.Bitcoin,
			)
			if err != nil {
				return nil, err
			}
		}
	}

	if cfg.loopRemote && cfg.Network != DefaultNetwork {
		if cfg.Remote.Loop.MacaroonPath == defaultLoopCfg.MacaroonPath {
			cfg.Remote.Loop.MacaroonPath = cfg.Loop.MacaroonPath
		}
		if cfg.Remote.Loop.TLSCertPath == defaultLoopCfg.TLSCertPath {
			cfg.Remote.Loop.TLSCertPath = cfg.Loop.TLSCertPath
		}
	}

	defaultPoolCfg := pool.DefaultConfig()
	if cfg.poolRemote && cfg.Network != DefaultNetwork {
		if cfg.Remote.Pool.MacaroonPath == defaultPoolCfg.MacaroonPath {
			cfg.Remote.Pool.MacaroonPath = cfg.Pool.MacaroonPath
		}
		if cfg.Remote.Pool.TLSCertPath == defaultPoolCfg.TLSCertPath {
			cfg.Remote.Pool.TLSCertPath = cfg.Pool.TLSCertPath
		}
	}

	return cfg, nil
}

// loadConfigFile loads and sanitizes the lit main configuration from the config
// file or command line arguments (or both).
func loadConfigFile(preCfg *Config, interceptor signal.Interceptor) (*Config,
	error) {

	// If the config file path has not been modified by the user, then we'll
	// use the default config file path. However, if the user has modified
	// their litdir, then we should assume they intend to use the config
	// file within it.
	litDir := lnd.CleanAndExpandPath(preCfg.LitDir)
	configFilePath := lnd.CleanAndExpandPath(preCfg.ConfigFile)
	if litDir != DefaultLitDir {
		if configFilePath == defaultConfigFile {
			configFilePath = filepath.Join(
				litDir, defaultConfigFilename,
			)
		}
	}

	// Next, load any additional configuration options from the file.
	var configFileError error
	cfg := preCfg
	fileParser := flags.NewParser(cfg, flags.Default)
	err := flags.NewIniParser(fileParser).ParseFile(configFilePath)
	if err != nil {
		// If it's a parsing related error, then we'll return
		// immediately, otherwise we can proceed as possibly the config
		// file doesn't exist which is OK.
		if _, ok := err.(*flags.IniError); ok {
			return nil, err
		}

		configFileError = err
	}

	// Finally, parse the remaining command line options again to ensure
	// they take precedence.
	flagParser := flags.NewParser(cfg, flags.Default)
	if _, err := flagParser.Parse(); err != nil {
		return nil, err
	}

	// Now make sure we create the LiT directory if it doesn't yet exist.
	if err := makeDirectories(litDir); err != nil {
		return nil, err
	}

	// Parse the global/top-level network and propagate it to all sub config
	// structs.
	if err := setNetwork(cfg); err != nil {
		return nil, err
	}

	switch cfg.LndMode {
	// In case we are running lnd in-process, let's make sure its
	// configuration is fully valid. This also sets up the main logger that
	// logs to a sub-directory in the .lnd folder.
	case ModeIntegrated:
		var err error
		cfg.Lnd, err = lnd.ValidateConfig(
			*cfg.Lnd, interceptor, fileParser, flagParser,
		)
		if err != nil {
			return nil, err
		}

	// In remote lnd mode we skip the validation of the lnd configuration
	// and instead just set up the logging (that would be done by lnd if it
	// were running in the same process).
	case ModeRemote:
		if err := validateRemoteModeConfig(cfg); err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("invalid lnd mode %v", cfg.LndMode)
	}

	// Warn about missing config file only after all other configuration is
	// done. This prevents the warning on help messages and invalid options.
	// Note this should go directly before the return.
	if configFileError != nil {
		log.Warnf("%v", configFileError)
	}

	return cfg, nil
}

// validateRemoteModeConfig validates the terminal's own configuration
// parameters that are only used in the "remote" lnd mode.
func validateRemoteModeConfig(cfg *Config) error {
	r := cfg.Remote

	// When referring to the default lnd configuration later on, let's make
	// sure we use the actual default values and not the lndDefaultConfig
	// variable which could've been overwritten by the user. Otherwise this
	// could lead to weird behavior and hard to catch bugs.
	defaultLndCfg := lnd.DefaultConfig()

	// If the remote lnd's network isn't the default, we also check if we
	// need to adjust the default macaroon directory so the user can only
	// specify --network=testnet for example if everything else is using
	// the defaults.
	if cfg.Network != DefaultNetwork &&
		r.Lnd.MacaroonPath == DefaultRemoteLndMacaroonPath {

		r.Lnd.MacaroonPath = filepath.Join(
			defaultLndCfg.DataDir, defaultLndChainSubDir,
			defaultLndChain, cfg.Network,
			path.Base(defaultLndCfg.AdminMacPath),
		)
	}

	// If the provided lit directory is not the default, we'll modify the
	// path to all of the files and directories that will live within it.
	litDir := lnd.CleanAndExpandPath(cfg.LitDir)
	if litDir != DefaultLitDir {
		r.LitTLSCertPath = filepath.Join(litDir, DefaultTLSCertFilename)
		r.LitTLSKeyPath = filepath.Join(litDir, DefaultTLSKeyFilename)
		r.LitLogDir = filepath.Join(litDir, defaultLogDirname)
	}

	r.LitTLSCertPath = lncfg.CleanAndExpandPath(r.LitTLSCertPath)
	r.LitTLSKeyPath = lncfg.CleanAndExpandPath(r.LitTLSKeyPath)
	r.LitLogDir = lncfg.CleanAndExpandPath(r.LitLogDir)

	// Make sure the parent directories of our certificate files exist. We
	// don't need to do the same for the log dir as the log rotator will do
	// just that.
	if err := makeDirectories(filepath.Dir(r.LitTLSCertPath)); err != nil {
		return err
	}
	if err := makeDirectories(filepath.Dir(r.LitTLSKeyPath)); err != nil {
		return err
	}

	// In remote mode, we don't call lnd's ValidateConfig that sets up a
	// logging backend for us. We need to manually create and start one. The
	// root logger should've already been created as part of the default
	// config though.
	if cfg.Lnd.LogWriter == nil {
		cfg.Lnd.LogWriter = build.NewRotatingLogWriter()
	}
	err := cfg.Lnd.LogWriter.InitLogRotator(
		filepath.Join(r.LitLogDir, cfg.Network, defaultLogFilename),
		r.LitMaxLogFileSize, r.LitMaxLogFiles,
	)
	if err != nil {
		return fmt.Errorf("log rotation setup failed: %v", err.Error())
	}

	return nil
}

// setNetwork parses the top-level network config options and, if valid, sets it
// in all sub configuration structs. We also set the Bitcoin chain to active by
// default as LiT won't support Litecoin in the foreseeable future.
func setNetwork(cfg *Config) error {
	switch cfg.Network {
	case "mainnet":
		cfg.Lnd.Bitcoin.MainNet = true

	case "testnet", "testnet3":
		cfg.Lnd.Bitcoin.TestNet3 = true

	case "regtest":
		cfg.Lnd.Bitcoin.RegTest = true

	case "simnet":
		cfg.Lnd.Bitcoin.SimNet = true

	default:
		return fmt.Errorf("unknown network: %v", cfg.Network)
	}

	cfg.Lnd.Bitcoin.Active = true
	cfg.Faraday.Network = cfg.Network
	cfg.Loop.Network = cfg.Network
	cfg.Pool.Network = cfg.Network

	return nil
}

// readUIPassword reads the password for the UI either from the command line
// flag, a file specified or an environment variable.
func readUIPassword(config *Config) error {
	// A password is passed in as a command line flag (or config file
	// variable) directly.
	if len(strings.TrimSpace(config.UIPassword)) > 0 {
		config.UIPassword = strings.TrimSpace(config.UIPassword)
		return nil
	}

	// A file that contains the password is specified.
	if len(strings.TrimSpace(config.UIPasswordFile)) > 0 {
		content, err := ioutil.ReadFile(strings.TrimSpace(
			config.UIPasswordFile,
		))
		if err != nil {
			return fmt.Errorf("could not read file %s: %v",
				config.UIPasswordFile, err)
		}
		config.UIPassword = strings.TrimSpace(string(content))
		return nil
	}

	// The name of an environment variable was specified.
	if len(strings.TrimSpace(config.UIPasswordEnv)) > 0 {
		content := os.Getenv(strings.TrimSpace(config.UIPasswordEnv))
		if len(content) == 0 {
			return fmt.Errorf("environment variable %s is empty",
				config.UIPasswordEnv)
		}
		config.UIPassword = strings.TrimSpace(content)
		return nil
	}

	return fmt.Errorf("mandatory password for UI not configured. specify " +
		"either a password directly or a file or environment " +
		"variable that contains the password")
}

func buildTLSConfigForHttp2(config *Config) (*tls.Config, error) {
	var tlsConfig *tls.Config

	switch {
	case config.LetsEncrypt:
		serverName := config.LetsEncryptHost
		if serverName == "" {
			return nil, errors.New("let's encrypt host name " +
				"option is required for using let's encrypt")
		}

		log.Infof("Setting up Let's Encrypt for server %v", serverName)

		certDir := config.LetsEncryptDir
		log.Infof("Setting up Let's Encrypt with cache dir %v", certDir)

		manager := autocert.Manager{
			Cache:      autocert.DirCache(certDir),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(serverName),
		}

		go func() {
			log.Infof("Listening for Let's Encrypt challenges on "+
				"%v", config.LetsEncryptListen)

			err := http.ListenAndServe(
				config.LetsEncryptListen,
				manager.HTTPHandler(nil),
			)
			if err != nil {
				log.Errorf("Error starting Let's Encrypt "+
					"HTTP listener on port 80: %v", err)
			}
		}()
		tlsConfig = &tls.Config{
			GetCertificate: manager.GetCertificate,
		}

	case config.LndMode == ModeRemote:
		tlsCertPath := config.Remote.LitTLSCertPath
		tlsKeyPath := config.Remote.LitTLSKeyPath

		if !lnrpc.FileExists(tlsCertPath) &&
			!lnrpc.FileExists(tlsKeyPath) {

			err := cert.GenCertPair(
				defaultSelfSignedCertOrganization, tlsCertPath,
				tlsKeyPath, nil, nil, false,
				DefaultAutogenValidity,
			)
			if err != nil {
				return nil, fmt.Errorf("failed creating "+
					"self-signed cert: %v", err)
			}
		}

		tlsCert, _, err := cert.LoadCert(tlsCertPath, tlsKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed reading TLS server "+
				"keys: %v", err)
		}
		tlsConfig = cert.TLSConfFromCert(tlsCert)

	default:
		tlsCert, _, err := cert.LoadCert(
			config.Lnd.TLSCertPath, config.Lnd.TLSKeyPath,
		)
		if err != nil {
			return nil, fmt.Errorf("failed reading TLS server "+
				"keys: %v", err)
		}
		tlsConfig = cert.TLSConfFromCert(tlsCert)
	}

	// lnd's cipher suites are too restrictive for HTTP/2, we need to add
	// one of the default suites back to stop the HTTP/2 lib from
	// complaining.
	tlsConfig.CipherSuites = append(
		tlsConfig.CipherSuites,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	)
	tlsConfig, err := connhelpers.TlsConfigWithHttp2Enabled(tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("can't configure h2 handling: %v", err)
	}
	return tlsConfig, nil
}

// makeDirectories creates the directory given and if necessary any parent
// directories as well.
func makeDirectories(fullDir string) error {
	err := os.MkdirAll(fullDir, 0700)
	if err != nil {
		// Show a nicer error message if it's because a symlink is
		// linked to a directory that does not exist (probably because
		// it's not mounted).
		if e, ok := err.(*os.PathError); ok && os.IsExist(err) {
			if link, lerr := os.Readlink(e.Path); lerr == nil {
				str := "is symlink %s -> %s mounted?"
				err = fmt.Errorf(str, e.Path, link)
			}
		}

		err := fmt.Errorf("failed to create directory %v: %v", fullDir,
			err)
		_, _ = fmt.Fprintln(os.Stderr, err)
		return err
	}

	return nil
}

// onDemandListener is a net.Listener that only actually starts to listen on a
// network port once the Accept method is called.
type onDemandListener struct {
	addr net.Addr
	lis  net.Listener
}

// Accept waits for and returns the next connection to the listener.
func (l *onDemandListener) Accept() (net.Conn, error) {
	if l.lis == nil {
		var err error
		l.lis, err = net.Listen(parseNetwork(l.addr), l.addr.String())
		if err != nil {
			return nil, err
		}
	}
	return l.lis.Accept()
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
func (l *onDemandListener) Close() error {
	if l.lis != nil {
		return l.lis.Close()
	}

	return nil
}

// Addr returns the listener's network address.
func (l *onDemandListener) Addr() net.Addr {
	return l.addr
}

// parseNetwork parses the network type of the given address.
func parseNetwork(addr net.Addr) string {
	switch addr := addr.(type) {
	// TCP addresses resolved through net.ResolveTCPAddr give a default
	// network of "tcp", so we'll map back the correct network for the given
	// address. This ensures that we can listen on the correct interface
	// (IPv4 vs IPv6).
	case *net.TCPAddr:
		if addr.IP.To4() != nil {
			return "tcp4"
		}
		return "tcp6"

	default:
		return addr.Network()
	}
}
