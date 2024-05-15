package itest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/tapchannel"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/tapdevrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/rpc"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/macaroons"
	"github.com/lightningnetwork/lnd/record"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/macaroon.v2"
)

var (
	dummyMetaData = &taprpc.AssetMeta{
		Data: []byte("some metadata"),
	}

	itestAsset = &mintrpc.MintAsset{
		AssetType: taprpc.AssetType_NORMAL,
		Name:      "itest-asset-cents",
		AssetMeta: dummyMetaData,
		Amount:    500_000_000,
	}
)

// testCustomChannels tests that we can create a network with custom channels
// and send asset payments over them.
func testCustomChannels(ctx context.Context, net *NetworkHarness,
	t *harnessTest) {

	ctxb := context.Background()
	lndArgs := []string{
		"--trickledelay=50",
		"--gossip.sub-batch-delay=5ms",
		"--caches.rpc-graph-cache-duration=100ms",
		"--default-remote-max-htlcs=483",
		"--dust-threshold=5000000",
		"--rpcmiddleware.enable",
		"--protocol.anchors",
		"--protocol.option-scid-alias",
		"--protocol.zero-conf",
		"--protocol.simple-taproot-chans",
		"--accept-keysend",
	}
	litdArgs := []string{
		"--taproot-assets.allow-public-uni-proof-courier",
		"--taproot-assets.universe.public-access",
		"--taproot-assets.universerpccourier.skipinitdelay",
		"--taproot-assets.universerpccourier.backoffresetwait=1s",
		"--taproot-assets.universerpccourier.numtries=5",
		"--taproot-assets.universerpccourier.initialbackoff=300ms",
		"--taproot-assets.universerpccourier.maxbackoff=600ms",
	}

	// The topology we are going for looks like the following:
	// Charlie -- (CC) --> Dave -- (NC) --> Erin -- (CC) --> Fabia
	// With CC being a custom channel and NC being a normal channel.
	// All 4 nodes need to be full litd nodes running in integrated mode
	// with tapd included. We also need specific flags to be enabled, so we
	// create 4 completely new nodes, ignoring the two default nodes that
	// are created by the harness.
	charlie, err := net.NewNode(
		t.t, "Charlie", lndArgs, false, true, litdArgs...,
	)
	require.NoError(t.t, err)

	dave, err := net.NewNode(t.t, "Dave", lndArgs, false, true, litdArgs...)
	require.NoError(t.t, err)
	erin, err := net.NewNode(t.t, "Erin", lndArgs, false, true, litdArgs...)
	require.NoError(t.t, err)
	fabia, err := net.NewNode(
		t.t, "Fabia", lndArgs, false, true, litdArgs...,
	)
	require.NoError(t.t, err)

	nodes := []*HarnessNode{charlie, dave, erin, fabia}
	connectAllNodes(t.t, net, nodes)
	fundAllNodes(t.t, net, nodes)

	charlieTap := newTapClient(t.t, charlie)
	erinTap := newTapClient(t.t, erin)

	// Mint an asset on Charlie and sync all nodes to Charlie as the
	// universe.
	mintedAssets := itest.MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner.Client, charlieTap,
		[]*mintrpc.MintAssetRequest{
			{
				Asset: itestAsset,
			},
		},
	)
	cents := mintedAssets[0]

	t.Logf("Minted %d lightning cents, syncing universes...", cents.Amount)
	syncUniverses(t.t, charlieTap, dave, erin, fabia)
	t.Logf("Universes synced between all nodes, distributing assets...")

	// We need to send some assets to Erin, so he can fund an asset channel
	// with Fabia.
	const (
		fundingAmount = 25_000
		startAmount   = fundingAmount * 2
	)
	erinAddr, err := erinTap.NewAddr(ctxb, &taprpc.NewAddrRequest{
		Amt:     startAmount,
		AssetId: cents.AssetGenesis.AssetId,
		ProofCourierAddr: fmt.Sprintf(
			"%s://%s", proof.UniverseRpcCourierType,
			charlie.Cfg.LitAddr(),
		),
	})
	require.NoError(t.t, err)

	// Send the assets to Erin.
	itest.AssertAddrCreated(t.t, erinTap, cents, erinAddr)
	sendResp, err := charlieTap.SendAsset(ctxb, &taprpc.SendAssetRequest{
		TapAddrs: []string{erinAddr.Encoded},
	})
	require.NoError(t.t, err)
	itest.ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner.Client, charlieTap, sendResp,
		cents.AssetGenesis.AssetId,
		[]uint64{cents.Amount - startAmount, startAmount}, 0, 1,
	)
	itest.AssertNonInteractiveRecvComplete(t.t, erinTap, 1)

	// Create the normal channel between Dave and Erin.
	channelOp := openChannelAndAssert(
		t, net, dave, erin, lntest.OpenChannelParams{
			Amt:         5_000_000,
			SatPerVByte: 5,
		},
	)
	defer closeChannelAndAssert(t, net, dave, channelOp, false)

	// This is the only public channel, we need everyone to be aware of it.
	assertChannelKnown(t.t, charlie, channelOp)

	fundResp, err := charlieTap.FundChannel(
		ctxb, &taprpc.FundChannelRequest{
			Amount:             fundingAmount,
			AssetId:            cents.AssetGenesis.AssetId,
			PeerPubkey:         dave.PubKey[:],
			FeeRateSatPerVbyte: 5,
		},
	)
	require.NoError(t.t, err)
	t.Logf("Funded channel between Charlie and Dave: %v", fundResp)

	fundResp2, err := erinTap.FundChannel(
		ctxb, &taprpc.FundChannelRequest{
			Amount:             fundingAmount,
			AssetId:            cents.AssetGenesis.AssetId,
			PeerPubkey:         fabia.PubKey[:],
			FeeRateSatPerVbyte: 5,
		},
	)
	require.NoError(t.t, err)
	t.Logf("Funded channel between Erin and Fabia: %v", fundResp2)

	mineBlocks(t, net, 6, 2)

	// Make sure the channel shows the correct asset information.
	assertAssetChan(
		t.t, charlie, dave, fundingAmount, cents.AssetGenesis.AssetId,
	)
	assertAssetChan(
		t.t, erin, fabia, fundingAmount, cents.AssetGenesis.AssetId,
	)

	// Print initial channel balances.
	balanceCharlie, err := getChannelCustomData(charlie, dave)
	require.NoError(t.t, err)
	t.Logf("Charlie initial balance: %v", toJSON(t.t, balanceCharlie))
	balanceErin, err := getChannelCustomData(erin, fabia)
	require.NoError(t.t, err)
	t.Logf("Erin initial balance: %v", toJSON(t.t, balanceErin))

	// ------------
	// Test case 1: Send a direct keysend payment from Charlie to Dave.
	// ------------
	sendKeySendPayment(t.t, charlie, dave, 100, cents.AssetGenesis.AssetId)
	balanceCharlie, err = getChannelCustomData(charlie, dave)
	require.NoError(t.t, err)
	t.Logf("Charlie balance after keysend payment: %v",
		toJSON(t.t, balanceCharlie))
	balanceDave, err := getChannelCustomData(dave, charlie)
	require.NoError(t.t, err)
	t.Logf("Dave balance after keysend payment: %v",
		toJSON(t.t, balanceDave))

	// ------------
	// Test case 2: Pay a normal invoice from Erin by Charlie.
	// ------------
	payNormalInvoice(t.t, charlie, erin, 20_000, cents.AssetGenesis.AssetId)
	balanceCharlie, err = getChannelCustomData(charlie, dave)
	require.NoError(t.t, err)
	t.Logf("Charlie balance after invoice payment: %v",
		toJSON(t.t, balanceCharlie))
}

func connectAllNodes(t *testing.T, net *NetworkHarness, nodes []*HarnessNode) {
	for i, node := range nodes {
		for j := i + 1; j < len(nodes); j++ {
			peer := nodes[j]
			net.ConnectNodes(t, node, peer)
		}
	}
}

func fundAllNodes(t *testing.T, net *NetworkHarness, nodes []*HarnessNode) {
	for _, node := range nodes {
		net.SendCoins(t, btcutil.SatoshiPerBitcoin, node)
	}
}

func syncUniverses(t *testing.T, universe *tapClient, nodes ...*HarnessNode) {
	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()

	for _, node := range nodes {
		nodeTapClient := newTapClient(t, node)

		universeHostAddr := universe.node.Cfg.LitAddr()
		t.Logf("Syncing node %v with universe %v", node.Cfg.Name,
			universeHostAddr)

		itest.SyncUniverses(
			ctxt, t, nodeTapClient, universe, universeHostAddr,
			defaultTimeout,
		)
	}
}

func assertAssetChan(t *testing.T, src, dst *HarnessNode, fundingAmount uint64,
	assetID []byte) {

	assetIDStr := hex.EncodeToString(assetID)
	err := wait.NoError(func() error {
		a, err := getChannelCustomData(src, dst)
		if err != nil {
			return err
		}

		if a.AssetInfo.AssetGenesis.AssetID != assetIDStr {
			return fmt.Errorf("expected asset ID %s, got %s",
				assetIDStr, a.AssetInfo.AssetGenesis.AssetID)
		}
		if a.Capacity != fundingAmount {
			return fmt.Errorf("expected capacity %d, got %d",
				fundingAmount, a.Capacity)
		}

		return nil
	}, defaultTimeout)
	require.NoError(t, err)
}

func assertChannelKnown(t *testing.T, node *HarnessNode,
	chanPoint *lnrpc.ChannelPoint) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()

	txid, err := chainhash.NewHash(chanPoint.GetFundingTxidBytes())
	require.NoError(t, err)
	targetChanPoint := fmt.Sprintf(
		"%v:%d", txid.String(), chanPoint.OutputIndex,
	)

	err = wait.NoError(func() error {
		graphResp, err := node.DescribeGraph(
			ctxt, &lnrpc.ChannelGraphRequest{},
		)
		if err != nil {
			return err
		}

		found := false
		for _, edge := range graphResp.Edges {
			if edge.ChanPoint == targetChanPoint {
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("channel %v not found",
				targetChanPoint)
		}

		return nil

	}, defaultTimeout)
	require.NoError(t, err)
}

func getChannelCustomData(src, dst *HarnessNode) (*tapchannel.JsonAssetChanInfo,
	error) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()

	srcDestChannels, err := src.ListChannels(
		ctxt, &lnrpc.ListChannelsRequest{
			Peer: dst.PubKey[:],
		},
	)
	if err != nil {
		return nil, err
	}

	if len(srcDestChannels.Channels) != 1 {
		return nil, fmt.Errorf("expected 1 channel, got %d",
			len(srcDestChannels.Channels))
	}

	targetChan := srcDestChannels.Channels[0]

	var assetData tapchannel.JsonAssetChannel
	err = json.Unmarshal(targetChan.CustomChannelData, &assetData)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal asset data: %w",
			err)
	}

	if len(assetData.Assets) != 1 {
		return nil, fmt.Errorf("expected 1 asset, got %d",
			len(assetData.Assets))
	}

	return &assetData.Assets[0], nil
}

func sendKeySendPayment(t *testing.T, src, dst *HarnessNode, amt uint64,
	assetID []byte) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()

	var id asset.ID
	copy(id[:], assetID)

	// Now that we know the amount we need to send, we'll convert that into
	// an HTLC tlv, which'll be used as the first hop TLV value.
	assetAmts := []*tapchannel.AssetBalance{
		tapchannel.NewAssetBalance(id, amt),
	}

	htlc := tapchannel.NewHtlc(assetAmts, tapchannel.NoneRfqID())

	// Read out the custom preimage for the keysend payment.
	var preimage lntypes.Preimage
	_, err := rand.Read(preimage[:])
	require.NoError(t, err)

	hash := preimage.Hash()

	// We'll now map the HTLC struct into a set of TLV records, which we
	// can then encode into the map format expected.
	htlcMapRecords, err := tlv.RecordsToMap(htlc.Records())
	require.NoError(t, err)

	// Set the preimage. If the user supplied a preimage with the data
	// flag, the preimage that is set here will be overwritten later.
	customRecords := make(map[uint64][]byte)
	customRecords[record.KeySendType] = preimage[:]

	const htlcCarrierAmt = 500
	req := &routerrpc.SendPaymentRequest{
		Dest:                  dst.PubKey[:],
		Amt:                   htlcCarrierAmt,
		DestCustomRecords:     customRecords,
		FirstHopCustomRecords: htlcMapRecords,
		PaymentHash:           hash[:],
		TimeoutSeconds:        3,
	}

	stream, err := src.RouterClient.SendPaymentV2(ctxt, req)
	require.NoError(t, err)

	time.Sleep(time.Second)

	result, err := getPaymentResult(stream)
	require.NoError(t, err)
	require.Equal(t, lnrpc.Payment_SUCCEEDED, result.Status)
}

func payNormalInvoice(t *testing.T, src, dst *HarnessNode, amt int64,
	assetID []byte) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()

	amtMsat := lnwire.NewMSatFromSatoshis(btcutil.Amount(amt))
	expirySeconds := 10
	expiryUnix := time.Now().Add(
		time.Duration(expirySeconds) * time.Second,
	).Unix()

	invoiceResp, err := dst.AddInvoice(ctxt, &lnrpc.Invoice{
		Value:  amt,
		Memo:   "normal invoice",
		Expiry: int64(expirySeconds),
	})
	require.NoError(t, err)

	srcTapd := newTapClient(t, src)

	timeoutSeconds := uint32(60)
	resp, err := srcTapd.AddAssetSellOrder(
		ctxb, &rfqrpc.AddAssetSellOrderRequest{
			AssetSpecifier: &rfqrpc.AssetSpecifier{
				Id: &rfqrpc.AssetSpecifier_AssetId{
					AssetId: assetID,
				},
			},
			MaxAssetAmount: 9999999,
			MinAsk:         uint64(amtMsat),
			Expiry:         uint64(expiryUnix),
			PeerPubKey:     dst.PubKey[:],
			TimeoutSeconds: timeoutSeconds,
		},
	)
	require.NoError(t, err)

	mSatPerUnit := resp.AcceptedQuote.BidPrice
	numUnits := uint64(amtMsat) / mSatPerUnit

	t.Logf("Got quote for %v asset units at %v msat/unit from peer "+
		"%x with SCID %d\n", numUnits, mSatPerUnit, dst.PubKey[:],
		resp.AcceptedQuote.Scid)

	var rfqID rfqmsg.ID
	copy(rfqID[:], resp.AcceptedQuote.Id)
	htlc := tapchannel.NewHtlc(nil, tapchannel.SomeRfqID(rfqID))

	// We'll now map the HTLC struct into a set of TLV records, which we
	// can then encode into the map format expected.
	htlcMapRecords, err := tlv.RecordsToMap(htlc.Records())
	require.NoError(t, err)

	sendReq := &routerrpc.SendPaymentRequest{
		PaymentRequest:        invoiceResp.PaymentRequest,
		TimeoutSeconds:        2,
		FirstHopCustomRecords: htlcMapRecords,
		FeeLimitMsat:          1000,
	}
	stream, err := src.RouterClient.SendPaymentV2(ctxt, sendReq)
	require.NoError(t, err)

	time.Sleep(time.Second)

	result, err := getPaymentResult(stream)
	require.NoError(t, err)
	require.Equal(t, lnrpc.Payment_SUCCEEDED, result.Status)
}

type tapClient struct {
	node *HarnessNode
	lnd  *rpc.HarnessRPC
	taprpc.TaprootAssetsClient
	assetwalletrpc.AssetWalletClient
	tapdevrpc.TapDevClient
	mintrpc.MintClient
	rfqrpc.RfqClient
	universerpc.UniverseClient
}

func newTapClient(t *testing.T, node *HarnessNode) *tapClient {
	cfg := node.Cfg
	superMacFile, err := bakeSuperMacaroon(cfg, false)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, os.Remove(superMacFile))
	})

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()

	rawConn, err := connectRPCWithMac(
		ctxt, cfg.LitAddr(), cfg.LitTLSCertPath, superMacFile,
	)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = rawConn.Close()
	})

	assetsClient := taprpc.NewTaprootAssetsClient(rawConn)
	assetWalletClient := assetwalletrpc.NewAssetWalletClient(rawConn)
	devClient := tapdevrpc.NewTapDevClient(rawConn)
	mintMintClient := mintrpc.NewMintClient(rawConn)
	rfqClient := rfqrpc.NewRfqClient(rawConn)
	universeClient := universerpc.NewUniverseClient(rawConn)

	return &tapClient{
		node:                node,
		TaprootAssetsClient: assetsClient,
		AssetWalletClient:   assetWalletClient,
		TapDevClient:        devClient,
		MintClient:          mintMintClient,
		RfqClient:           rfqClient,
		UniverseClient:      universeClient,
	}
}

func connectRPCWithMac(ctx context.Context, hostPort, tlsCertPath,
	macFilePath string) (*grpc.ClientConn, error) {

	tlsCreds, err := credentials.NewClientTLSFromFile(tlsCertPath, "")
	if err != nil {
		return nil, err
	}

	opts := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithTransportCredentials(tlsCreds),
	}

	macOption, err := readMacaroon(macFilePath)
	if err != nil {
		return nil, err
	}

	opts = append(opts, macOption)

	return grpc.DialContext(ctx, hostPort, opts...)
}

// readMacaroon tries to read the macaroon file at the specified path and create
// gRPC dial options from it.
func readMacaroon(macPath string) (grpc.DialOption, error) {
	// Load the specified macaroon file.
	macBytes, err := os.ReadFile(macPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read macaroon path : %w", err)
	}

	return macFromBytes(macBytes)
}

// macFromBytes returns a macaroon from the given byte slice.
func macFromBytes(macBytes []byte) (grpc.DialOption, error) {
	mac := &macaroon.Macaroon{}
	if err := mac.UnmarshalBinary(macBytes); err != nil {
		return nil, fmt.Errorf("unable to decode macaroon: %w", err)
	}

	// Now we append the macaroon credentials to the dial options.
	cred, err := macaroons.NewMacaroonCredential(mac)
	if err != nil {
		return nil, fmt.Errorf("error creating macaroon credential: %w",
			err)
	}
	return grpc.WithPerRPCCredentials(cred), nil
}

func toJSON(t *testing.T, v interface{}) string {
	t.Helper()

	b, err := json.MarshalIndent(v, "", "  ")
	require.NoError(t, err)

	return string(b)
}
