package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/tapchannel"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
	"github.com/lightningnetwork/lnd/cmd/commands"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/record"
	"github.com/lightningnetwork/lnd/tlv"
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

var lnCommands = []cli.Command{
	{
		Name:     "ln",
		Usage:    "Interact with the Lightning Network.",
		Category: "Taproot Assets on LN",
		Subcommands: []cli.Command{
			fundChannelCommand,
			sendPaymentCommand,
			copyCommand(
				commands.ListChannelsCommand,
				func(c *cli.Context) error {
					return commands.ListChannels(
						c,
						listChannelsResponseDecorator,
					)
				},
			),
			copyCommand(
				commands.ChannelBalanceCommand,
				func(c *cli.Context) error {
					return commands.ChannelBalance(
						c,
						channelBalanceResponseDecorator,
					)
				},
			),
			payInvoiceCommand,
		},
	},
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

type customChanData struct {
	openChan    tapchannel.OpenChannel
	localCommit tapchannel.Commitment
}

func readCustomChanData(chanData []byte) (*customChanData, error) {
	chanDataReader := bytes.NewReader(chanData)

	// The custom channel data is encoded as two var byte blobs. One for
	// the static funding data, one for the state of our current local
	// commitment.
	openChanData, err := wire.ReadVarBytes(
		chanDataReader, 0, 1_000_000, "chan data",
	)
	if err != nil {
		return nil, fmt.Errorf("unable to read open chan data: %v", err)
	}
	localCommitData, err := wire.ReadVarBytes(
		chanDataReader, 0, 1_000_000, "commit data",
	)
	if err != nil {
		return nil, fmt.Errorf("unable to read open chan data: %v", err)
	}

	var openChannelRecord tapchannel.OpenChannel
	err = openChannelRecord.Decode(bytes.NewReader(openChanData))
	if err != nil {
		return nil, fmt.Errorf("error decoding custom channel data: %w", err)
	}

	var localCommit tapchannel.Commitment
	err = localCommit.Decode(bytes.NewReader(localCommitData))
	if err != nil {
		return nil, fmt.Errorf("error decoding custom commit data: %w", err)
	}

	return &customChanData{
		openChan:    openChannelRecord,
		localCommit: localCommit,
	}, nil
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

type AssetBalance struct {
	AssetID       string `json:"asset_id"`
	Name          string `json:"name"`
	LocalBalance  uint64 `json:"local_balance"`
	RemoteBalance uint64 `json:"remote_balance"`
	channelID     uint64
	peerPubKey    string
}

type channelBalResp struct {
	Assets map[string]*AssetBalance `json:"assets"`
}

func computeAssetBalances(lnd lnrpc.LightningClient) (*channelBalResp, error) {
	ctxb := context.Background()
	openChans, err := lnd.ListChannels(
		ctxb, &lnrpc.ListChannelsRequest{},
	)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch channels: %w", err)
	}

	balanceResp := &channelBalResp{
		Assets: make(map[string]*AssetBalance),
	}
	for _, openChan := range openChans.Channels {
		if len(openChan.CustomChannelData) == 0 {
			continue
		}

		assetData, err := readCustomChanData(openChan.CustomChannelData)
		if err != nil {
			return nil, err
		}

		for _, assetOutput := range assetData.localCommit.LocalOutputs() {
			assetID := assetOutput.Proof.Val.Asset.ID()

			assetIDStr := hex.EncodeToString(assetID[:])
			assetName := assetOutput.Proof.Val.Asset.Tag

			assetBalance, ok := balanceResp.Assets[assetIDStr]
			if !ok {
				assetBalance = &AssetBalance{
					AssetID:    assetIDStr,
					Name:       assetName,
					channelID:  openChan.ChanId,
					peerPubKey: openChan.RemotePubkey,
				}
				balanceResp.Assets[assetIDStr] = assetBalance
			}

			assetBalance.LocalBalance += assetOutput.Amount.Val
		}

		for _, assetOutput := range assetData.localCommit.RemoteOutputs() {
			assetID := assetOutput.Proof.Val.Asset.ID()

			assetIDStr := hex.EncodeToString(assetID[:])
			assetName := assetOutput.Proof.Val.Asset.Tag

			assetBalance, ok := balanceResp.Assets[assetIDStr]
			if !ok {
				assetBalance = &AssetBalance{
					AssetID: assetIDStr,
					Name:    assetName,
				}
				balanceResp.Assets[assetIDStr] = assetBalance
			}

			assetBalance.RemoteBalance += assetOutput.Amount.Val
		}
	}

	return balanceResp, nil
}

func channelBalanceResponseDecorator(c *cli.Context,
	resp *lnrpc.ChannelBalanceResponse) error {

	// For the channel balance, we'll hit ListChannels ourselves, then use
	// all the blobs to sum up a total balance for each asset across all
	// channels.
	lndConn, cleanup, err := connectClient(c, false)
	if err != nil {
		return fmt.Errorf("unable to make rpc con: %w", err)
	}

	defer cleanup()

	lndClient := lnrpc.NewLightningClient(lndConn)

	balanceResp, err := computeAssetBalances(lndClient)
	if err != nil {
		return fmt.Errorf("unable to compute asset balances: %w", err)
	}

	jsonBytes, err := json.Marshal(balanceResp)
	if err != nil {
		return fmt.Errorf("error marshaling custom "+
			"channel data: %w", err)
	}

	resp.CustomChannelData = jsonBytes

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

			assetData, err := readCustomChanData(
				channel.CustomChannelData,
			)
			if err != nil {
				return err
			}

			localCommit := assetData.localCommit
			openChannelRecord := assetData.openChan

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

var (
	assetIDFlag = cli.StringFlag{
		Name: "asset_id",
		Usage: "the asset ID of the asset to use when sending " +
			"payments with assets",
	}
)

var sendPaymentCommand = cli.Command{
	Name:     "sendpayment",
	Category: commands.SendPaymentCommand.Category,
	Usage: "Send a payment over Lightning, potentially using a " +
		"mulit-asset channel as the first hop",
	Description: commands.SendPaymentCommand.Description + `
	To send an multi-asset LN payment to a single hop, the --asset_id=X
	argument should be used.

	Note that this will only work in concert with the --keysend argument.
	`,
	ArgsUsage: commands.SendPaymentCommand.ArgsUsage + " --asset_id=X",
	Flags:     append(commands.SendPaymentCommand.Flags, assetIDFlag),
	Action:    sendPayment,
}

func sendPayment(ctx *cli.Context) error {
	// Show command help if no arguments provided
	if ctx.NArg() == 0 && ctx.NumFlags() == 0 {
		_ = cli.ShowCommandHelp(ctx, "sendpayment")
		return nil
	}

	lndConn, cleanup, err := connectClient(ctx, false)
	if err != nil {
		return fmt.Errorf("unable to make rpc con: %w", err)
	}

	defer cleanup()

	lndClient := lnrpc.NewLightningClient(lndConn)

	switch {
	case !ctx.IsSet(assetIDFlag.Name):
		return fmt.Errorf("the --asset_id flag must be set")
	case !ctx.IsSet("keysend"):
		return fmt.Errorf("the --keysend flag must be set")
	case !ctx.IsSet("amt"):
		return fmt.Errorf("--amt must be set")
	}

	assetIDStr := ctx.String(assetIDFlag.Name)

	assetIDBytes, err := hex.DecodeString(assetIDStr)
	if err != nil {
		return fmt.Errorf("unable to decode assetID: %v", err)
	}

	// First, based on the asset ID and amount, we'll make sure that this
	// channel even has enough funds to send.
	assetBalances, err := computeAssetBalances(lndClient)
	if err != nil {
		return fmt.Errorf("unable to compute asset balances: %w", err)
	}

	assetBalance, ok := assetBalances.Assets[assetIDStr]
	if !ok {
		return fmt.Errorf("unable to send asset_id=%v, not in "+
			"channel", assetIDStr)
	}

	amtToSend := ctx.Uint64("amt")
	if amtToSend > assetBalance.LocalBalance {
		return fmt.Errorf("insufficient balance, want to send %v, "+
			"only have %v", amtToSend, assetBalance.LocalBalance)
	}

	var assetID asset.ID
	copy(assetID[:], assetIDBytes)

	// Now that we know the amount we need to send, we'll convert that into
	// an HTLC tlv, which'll be used as the first hop TLV value.
	assetAmts := []*tapchannel.AssetBalance{
		tapchannel.NewAssetBalance(assetID, amtToSend),
	}

	htlc := tapchannel.NewHtlc(assetAmts, tapchannel.NoneRfqID())

	// We'll now map the HTLC struct into a set of TLV records, which we
	// can then encode into the map format expected.
	htlcMapRecords, err := tlv.RecordsToMap(htlc.Records())
	if err != nil {
		return fmt.Errorf("unable to encode records as map: %w", err)
	}

	// With the asset specific work out of the way, we'll parse the rest of
	// the command as normal.
	var (
		destNode []byte
		rHash    []byte
	)

	switch {
	case ctx.IsSet("dest"):
		destNode, err = hex.DecodeString(ctx.String("dest"))
	default:
		return fmt.Errorf("destination txid argument missing")
	}
	if err != nil {
		return err
	}

	if len(destNode) != 33 {
		return fmt.Errorf("dest node pubkey must be exactly 33 bytes, is "+
			"instead: %v", len(destNode))
	}

	// We use a constant amount of 500 to carry the asset HTLCs. In the
	// future, we can use the double HTLC trick here, though it consumes
	// more commitment space.
	const htlcCarrierAmt = 500
	req := &routerrpc.SendPaymentRequest{
		Dest:                  destNode,
		Amt:                   htlcCarrierAmt,
		DestCustomRecords:     make(map[uint64][]byte),
		FirstHopCustomRecords: htlcMapRecords,
	}

	if ctx.IsSet("payment_hash") {
		return errors.New("cannot set payment hash when using " +
			"keysend")
	}

	// Read out the custom preimage for the keysend payment.
	var preimage lntypes.Preimage
	if _, err := rand.Read(preimage[:]); err != nil {
		return err
	}

	// Set the preimage. If the user supplied a preimage with the data
	// flag, the preimage that is set here will be overwritten later.
	req.DestCustomRecords[record.KeySendType] = preimage[:]

	hash := preimage.Hash()
	rHash = hash[:]

	req.PaymentHash = rHash

	return commands.SendPaymentRequest(ctx, req)
}

var payInvoiceCommand = cli.Command{
	Name:     "payinvoice",
	Category: "Payments",
	Usage:    "Pay an invoice over lightning using an asset.",
	Description: `
	This command attempts to pay an invoice using an asset channel as the
	source of the payment. The asset ID of the channel must be specified
	using the --asset_id flag.
	`,
	ArgsUsage: "pay_req --asset_id=X",
	Flags: append(commands.PaymentFlags(),
		cli.Int64Flag{
			Name: "amt",
			Usage: "(optional) number of satoshis to fulfill the " +
				"invoice",
		},
		assetIDFlag,
	),
	Action: payInvoice,
}

func payInvoice(ctx *cli.Context) error {
	args := ctx.Args()
	ctxb := context.Background()

	var payReq string
	switch {
	case ctx.IsSet("pay_req"):
		payReq = ctx.String("pay_req")
	case args.Present():
		payReq = args.First()
	default:
		return fmt.Errorf("pay_req argument missing")
	}

	lndConn, cleanup, err := connectClient(ctx, false)
	if err != nil {
		return fmt.Errorf("unable to make rpc con: %w", err)
	}

	defer cleanup()

	lndClient := lnrpc.NewLightningClient(lndConn)

	decodeReq := &lnrpc.PayReqString{PayReq: payReq}
	decodeResp, err := lndClient.DecodePayReq(ctxb, decodeReq)
	if err != nil {
		return err
	}

	if !ctx.IsSet(assetIDFlag.Name) {
		return fmt.Errorf("the --asset_id flag must be set")
	}

	assetIDStr := ctx.String(assetIDFlag.Name)

	assetIDBytes, err := hex.DecodeString(assetIDStr)
	if err != nil {
		return fmt.Errorf("unable to decode assetID: %v", err)
	}

	// First, based on the asset ID and amount, we'll make sure that this
	// channel even has enough funds to send.
	assetBalances, err := computeAssetBalances(lndClient)
	if err != nil {
		return fmt.Errorf("unable to compute asset balances: %w", err)
	}

	assetBalance, ok := assetBalances.Assets[assetIDStr]
	if !ok {
		return fmt.Errorf("unable to send asset_id=%v, not in "+
			"channel", assetIDStr)
	}

	if assetBalance.LocalBalance == 0 {
		return fmt.Errorf("no asset balance available for asset_id=%v",
			assetIDStr)
	}

	var assetID asset.ID
	copy(assetID[:], assetIDBytes)

	tapdConn, cleanup, err := connectTapdClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating tapd connection: %w", err)
	}

	defer cleanup()

	peerPubKey, err := hex.DecodeString(assetBalance.peerPubKey)
	if err != nil {
		return fmt.Errorf("unable to decode peer pubkey: %w", err)
	}

	rfqClient := rfqrpc.NewRfqClient(tapdConn)

	timeoutSeconds := uint32(60)
	fmt.Printf("Asking peer %x for quote to sell assets to pay for "+
		"invoice over %d msats; waiting up to %ds\n", peerPubKey,
		decodeResp.NumMsat, timeoutSeconds)

	resp, err := rfqClient.AddAssetSellOrder(
		ctxb, &rfqrpc.AddAssetSellOrderRequest{
			AssetSpecifier: &rfqrpc.AssetSpecifier{
				Id: &rfqrpc.AssetSpecifier_AssetIdStr{
					AssetIdStr: assetIDStr,
				},
			},
			MaxAssetAmount: assetBalance.LocalBalance,
			MinAsk:         uint64(decodeResp.NumMsat),
			Expiry:         uint64(decodeResp.Expiry),
			PeerPubKey:     peerPubKey,
			TimeoutSeconds: timeoutSeconds,
		},
	)
	if err != nil {
		return fmt.Errorf("error adding sell order: %w", err)
	}

	msatPerUnit := resp.AcceptedQuote.BidPrice
	numUnits := uint64(decodeResp.NumMsat) / msatPerUnit

	fmt.Printf("Got quote for %v asset units at %v msat/unit from peer "+
		"%x with SCID %d\n", numUnits, msatPerUnit, peerPubKey,
		resp.AcceptedQuote.Scid)

	var rfqID rfqmsg.ID
	copy(rfqID[:], resp.AcceptedQuote.Id)
	htlc := tapchannel.NewHtlc(nil, tapchannel.SomeRfqID(rfqID))

	// We'll now map the HTLC struct into a set of TLV records, which we
	// can then encode into the map format expected.
	htlcMapRecords, err := tlv.RecordsToMap(htlc.Records())
	if err != nil {
		return fmt.Errorf("unable to encode records as map: %w", err)
	}

	req := &routerrpc.SendPaymentRequest{
		PaymentRequest:        commands.StripPrefix(payReq),
		FirstHopCustomRecords: htlcMapRecords,
	}

	return commands.SendPaymentRequest(ctx, req)
}
