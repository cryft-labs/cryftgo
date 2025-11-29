// Copyright (C) 2019-2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package config

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const EnvPrefix = "avago"

var DashesToUnderscores = strings.NewReplacer("-", "_")

// BuildViper returns the viper environment from parsing config file from
// default search paths and any parsed command line flags
func BuildViper(fs *pflag.FlagSet, args []string) (*viper.Viper, error) {
	if err := deprecateFlags(fs); err != nil {
		return nil, err
	}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	v := viper.New()
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(DashesToUnderscores)
	v.SetEnvPrefix(EnvPrefix)
	if err := v.BindPFlags(fs); err != nil {
		return nil, err
	}

	// load node configs from flags or file, depending on which flags are set
	switch {
	case v.IsSet(ConfigContentKey):
		configContentB64 := v.GetString(ConfigContentKey)
		configBytes, err := base64.StdEncoding.DecodeString(configContentB64)
		if err != nil {
			return nil, fmt.Errorf("unable to decode base64 content: %w", err)
		}

		v.SetConfigType(v.GetString(ConfigContentTypeKey))
		if err := v.ReadConfig(bytes.NewBuffer(configBytes)); err != nil {
			return nil, err
		}

	case v.IsSet(ConfigFileKey):
		filename := GetExpandedArg(v, ConfigFileKey)
		v.SetConfigFile(filename)
		if err := v.ReadInConfig(); err != nil {
			return nil, err
		}
	}

	// Config deprecations must be after v.ReadInConfig
	deprecateConfigs(v, os.Stdout)
	return v, nil
}

func deprecateConfigs(v *viper.Viper, output io.Writer) {
	for key, message := range deprecatedKeys {
		if v.InConfig(key) {
			fmt.Fprintf(output, "Config %s has been deprecated, %s\n", key, message)
		}
	}
}

func BindFlags(fs *pflag.FlagSet, v *viper.Viper) error {
	// Runtime / Cryftee
	if err := v.BindPFlag(RuntimeCryfteeEnabledKey, fs.Lookup(RuntimeCryfteeEnabledKey)); err != nil {
		return err
	}
	if err := v.BindPFlag(RuntimeCryfteeTransportKey, fs.Lookup(RuntimeCryfteeTransportKey)); err != nil {
		return err
	}
	if err := v.BindPFlag(RuntimeCryfteeSocketKey, fs.Lookup(RuntimeCryfteeSocketKey)); err != nil {
		return err
	}
	if err := v.BindPFlag(RuntimeCryfteeHTTPAddrKey, fs.Lookup(RuntimeCryfteeHTTPAddrKey)); err != nil {
		return err
	}
	if err := v.BindPFlag(RuntimeCryfteeTimeoutKey, fs.Lookup(RuntimeCryfteeTimeoutKey)); err != nil {
		return err
	}

	// Cryftee binary management
	if err := v.BindPFlag(CryfteeBinaryPathKey, fs.Lookup(CryfteeBinaryPathKey)); err != nil {
		return err
	}
	if err := v.BindPFlag(CryfteeExpectedHashesKey, fs.Lookup(CryfteeExpectedHashesKey)); err != nil {
		return err
	}
	if err := v.BindPFlag(CryfteeStartupTimeoutKey, fs.Lookup(CryfteeStartupTimeoutKey)); err != nil {
		return err
	}

	// Web3Signer / Cryftee-backed staking
	if err := v.BindPFlag(StakingWeb3SignerEnabledKey, fs.Lookup(StakingWeb3SignerEnabledKey)); err != nil {
		return err
	}
	if err := v.BindPFlag(StakingWeb3SignerEphemeralKey, fs.Lookup(StakingWeb3SignerEphemeralKey)); err != nil {
		return err
	}
	if err := v.BindPFlag(StakingWeb3SignerKeyMaterialB64Key, fs.Lookup(StakingWeb3SignerKeyMaterialB64Key)); err != nil {
		return err
	}
	if err := v.BindPFlag(StakingWeb3SignerURLKey, fs.Lookup(StakingWeb3SignerURLKey)); err != nil {
		return err
	}

	return nil
}
