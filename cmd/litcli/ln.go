package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

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

func listChannelsResponseDecorator(c *cli.Context,
	resp *lnrpc.ListChannelsResponse) error {

	ctxb := context.Background()
	for idx := range resp.Channels {
		channel := resp.Channels[idx]

		if len(channel.CustomChannelData) > 0 {
			var openChannelRecord tapchannel.OpenChannel
			err := openChannelRecord.Decode(bytes.NewReader(
				channel.CustomChannelData,
			))
			if err != nil {
				return fmt.Errorf("error decoding custom "+
					"channel data: %w", err)
			}

			rpcAssetList := &taprpc.ListAssetResponse{}
			for _, output := range openChannelRecord.Assets() {
				rpcAsset, err := taprpc.MarshalAsset(
					ctxb, &output.Proof.Val.Asset,
					false, false, nil,
				)
				if err != nil {
					return fmt.Errorf("error marshaling "+
						"asset: %w", err)
				}

				rpcAssetList.Assets = append(
					rpcAssetList.Assets, rpcAsset,
				)
			}

			jsonBytes, err := lnrpc.ProtoJSONMarshalOpts.Marshal(
				rpcAssetList,
			)
			if err != nil {
				return fmt.Errorf("error marshaling custom "+
					"channel data: %w", err)
			}

			channel.CustomChannelData = jsonBytes
		}
	}

	return nil
}
