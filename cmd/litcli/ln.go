package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/tapchannel"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightningnetwork/lnd/cmd/commands"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/urfave/cli"
)

const (
	// minAssetAmount is the minimum amount of an asset that can be put into
	// a channel. We choose an arbitrary value that allows for at least a
	// couple of HTLCs to be created without leading to fractions of assets
	// (which doesn't exist).
	minAssetAmount = 100
)

func copyCommand(command cli.Command, action interface{},
	flags ...cli.Flag) cli.Command {

	command.Flags = append(command.Flags, flags...)
	command.Action = action

	return command
}

var fundChannelCommand = cli.Command{
	Name:     "fundchannel",
	Category: "Channels",
	Usage: "Open a Taproot Asset channel with a node on the Lightning " +
		"Network.",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: "node_key",
			Usage: "the identity public key of the target " +
				"node/peer serialized in compressed format, " +
				"must already be connected to",
		},
		cli.Uint64Flag{
			Name: "sat_per_vbyte",
			Usage: "(optional) a manual fee expressed in " +
				"sat/vByte that should be used when crafting " +
				"the transaction",
			Value: 1,
		},
		cli.Uint64Flag{
			Name: "asset_amount",
			Usage: "The amount of the asset to commit to the " +
				"channel.",
		},
		cli.StringFlag{
			Name:  "asset_id",
			Usage: "The asset ID to commit to the channel.",
		},
	},
	Action: fundChannel,
}

var lnCommands = []cli.Command{
	{
		Name:     "ln",
		Usage:    "Interact with the Lightning Network.",
		Category: "Taproot Assets on LN",
		Subcommands: []cli.Command{
			fundChannelCommand,
			copyCommand(
				commands.ListChannelsCommand,
				func(c *cli.Context) error {
					return commands.ListChannels(
						c,
						listChannelsResponseDecorator,
					)
				},
			),
		},
	},
}

func fundChannel(c *cli.Context) error {
	tapdConn, cleanup, err := connectTapdClient(c)
	if err != nil {
		return fmt.Errorf("error creating tapd connection: %w", err)
	}

	defer cleanup()

	ctxb := context.Background()
	tapdClient := taprpc.NewTaprootAssetsClient(tapdConn)
	assets, err := tapdClient.ListAssets(ctxb, &taprpc.ListAssetRequest{})
	if err != nil {
		return fmt.Errorf("error fetching assets: %w", err)
	}

	assetIDBytes, err := hex.DecodeString(c.String("asset_id"))
	if err != nil {
		return fmt.Errorf("error hex decoding asset ID: %w", err)
	}

	requestedAmount := c.Uint64("asset_amount")
	if requestedAmount < minAssetAmount {
		return fmt.Errorf("requested amount must be at least %d",
			minAssetAmount)
	}

	nodePubBytes, err := hex.DecodeString(c.String("node_key"))
	if err != nil {
		return fmt.Errorf("unable to decode node public key: %w", err)
	}

	assetFound := false
	for _, rpcAsset := range assets.Assets {
		if !bytes.Equal(rpcAsset.AssetGenesis.AssetId, assetIDBytes) {
			continue
		}

		if rpcAsset.Amount < requestedAmount {
			continue
		}

		assetFound = true
	}

	if !assetFound {
		return fmt.Errorf("asset with ID %x not found or no UTXO with "+
			"at least amount %d is available", assetIDBytes,
			requestedAmount)
	}

	resp, err := tapdClient.FundChannel(
		ctxb, &taprpc.FundChannelRequest{
			Amount:             requestedAmount,
			AssetId:            assetIDBytes,
			PeerPubkey:         nodePubBytes,
			FeeRateSatPerVbyte: uint32(c.Uint64("sat_per_vbyte")),
		},
	)
	if err != nil {
		return fmt.Errorf("error funding channel: %w", err)
	}

	printJSON(resp)

	return nil
}

type assetGenesis struct {
	GenesisPoint string `json:"genesis_point"`
	Name         string `json:"name"`
	MetaHash     string `json:"meta_hash"`
	AssetID      string `json:"asset_id"`
}

type assetUtxo struct {
	Version      int64        `json:"version"`
	AssetGenesis assetGenesis `json:"asset_genesis"`
	Amount       int64        `json:"amount"`
	ScriptKey    string       `json:"script_key"`
}

type AssetChanInfo struct {
	AssetInfo     assetUtxo `json:"asset_utxo"`
	Capacity      int64     `json:"capacity"`
	LocalBalance  int64     `json:"local_balance"`
	RemoteBalance int64     `json:"remote_balance"`
}

type assetChannelResp struct {
	Assets []AssetChanInfo `json:"assets"`
}

func listChannelsResponseDecorator(c *cli.Context,
	resp *lnrpc.ListChannelsResponse) error {

	for idx := range resp.Channels {
		channel := resp.Channels[idx]

		if len(channel.CustomChannelData) > 0 {
			chanDataReader := bytes.NewReader(
				channel.CustomChannelData,
			)

			// The custom channel data is encoded as two var byte
			// blobs. One for the static funding data, one for the
			// state of our current local commitment.
			openChanData, err := wire.ReadVarBytes(
				chanDataReader, 0, 1_000_000, "chan data",
			)
			if err != nil {
				return fmt.Errorf("unable to read open "+
					"chan data: %v", err)
			}
			localCommitData, err := wire.ReadVarBytes(
				chanDataReader, 0, 1_000_000, "commit data",
			)
			if err != nil {
				return fmt.Errorf("unable to read open "+
					"chan data: %v", err)
			}

			var openChannelRecord tapchannel.OpenChannel
			err = openChannelRecord.Decode(bytes.NewReader(
				openChanData,
			))
			if err != nil {
				return fmt.Errorf("error decoding custom "+
					"channel data: %w", err)
			}

			var localCommit tapchannel.Commitment
			err = localCommit.Decode(bytes.NewReader(
				localCommitData,
			))
			if err != nil {
				return fmt.Errorf("error decoding custom "+
					"commit data: %w", err)
			}

			rpcAssetList := &assetChannelResp{}
			for _, output := range openChannelRecord.Assets() {
				chanAsset := output.Proof.Val.Asset

				assetID := chanAsset.ID()
				assetInfo := AssetChanInfo{
					AssetInfo: assetUtxo{
						Version: int64(chanAsset.Version),
						AssetGenesis: assetGenesis{
							GenesisPoint: chanAsset.FirstPrevOut.String(),
							Name:         chanAsset.Tag,
							MetaHash:     hex.EncodeToString(chanAsset.MetaHash[:]),
							AssetID:      hex.EncodeToString(assetID[:]),
						},
						Amount: int64(chanAsset.Amount),
						ScriptKey: hex.EncodeToString(
							chanAsset.ScriptKey.PubKey.SerializeCompressed(),
						),
					},
					Capacity:      int64(output.Amount.Val),
					LocalBalance:  int64(localCommit.LocalAssets.Val.Sum()),
					RemoteBalance: int64(localCommit.RemoteAssets.Val.Sum()),
				}

				rpcAssetList.Assets = append(
					rpcAssetList.Assets, assetInfo,
				)
			}

			jsonBytes, err := json.Marshal(rpcAssetList)
			if err != nil {
				return fmt.Errorf("error marshaling custom "+
					"channel data: %w", err)
			}

			channel.CustomChannelData = jsonBytes
		}
	}

	return nil
}
