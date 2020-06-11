package kernel

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/mixin/config"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/kernel/internal/clock"
	"github.com/MixinNetwork/mixin/logger"
)

const (
	CosiActionSelfEmpty = iota
	CosiActionSelfCommitment
	CosiActionSelfResponse
	CosiActionExternalAnnouncement
	CosiActionExternalChallenge
	CosiActionFinalization
)

type CosiAction struct {
	Action       int
	PeerId       crypto.Hash
	SnapshotHash crypto.Hash
	Snapshot     *common.Snapshot
	Commitment   *crypto.Commitment
	Signature    *crypto.CosiSignature
	Response     *crypto.Response
	Transaction  *common.VersionedTransaction
	WantTx       bool
}

type CosiAggregator struct {
	Snapshot    *common.Snapshot
	Transaction *common.VersionedTransaction
	WantTxs     map[crypto.Hash]bool
	Commitments map[int]*crypto.Commitment
	Responses   map[int]*crypto.Response
	committed   map[crypto.Hash]bool
	responsed   map[crypto.Hash]bool
}

type CosiVerifier struct {
	Snapshot *common.Snapshot
	random   crypto.PrivateKey
}

func (node *Node) CosiLoop() error {
	defer close(node.clc)

	for {
		select {
		case <-node.done:
			return nil
		case m := <-node.cosiActionsChan:
			err := node.cosiHandleAction(m)
			if err != nil {
				return err
			}
		}
	}
}

func (node *Node) cosiHandleAction(m *CosiAction) error {
	defer node.Graph.UpdateFinalCache(node.IdForNetwork)

	switch m.Action {
	case CosiActionSelfEmpty:
		return node.cosiSendAnnouncement(m)
	case CosiActionSelfCommitment:
		return node.cosiHandleCommitment(m)
	case CosiActionSelfResponse:
		return node.cosiHandleResponse(m)
	case CosiActionExternalAnnouncement:
		return node.cosiHandleAnnouncement(m)
	case CosiActionExternalChallenge:
		return node.cosiHandleChallenge(m)
	case CosiActionFinalization:
		return node.handleFinalization(m)
	}

	return nil
}

func (node *Node) cosiSendAnnouncement(m *CosiAction) error {
	logger.Verbosef("CosiLoop cosiHandleAction cosiSendAnnouncement %v\n", m.Snapshot)
	s := m.Snapshot
	if s.NodeId != node.IdForNetwork || s.NodeId != m.PeerId {
		panic("should never be here")
	}
	if s.Version != common.SnapshotVersion || s.Signature != nil || s.Timestamp != 0 {
		return nil
	}
	if !node.CheckCatchUpWithPeers() && !node.checkInitialAcceptSnapshotWeak(m.Snapshot) {
		logger.Verbosef("CosiLoop cosiHandleAction cosiSendAnnouncement CheckCatchUpWithPeers\n")
		return nil
	}

	tx, finalized, err := node.checkCacheSnapshotTransaction(s)
	if err != nil || finalized || tx == nil {
		return nil
	}

	agg := &CosiAggregator{
		Snapshot:    s,
		Transaction: tx,
		WantTxs:     make(map[crypto.Hash]bool),
		Commitments: make(map[int]*crypto.Commitment),
		Responses:   make(map[int]*crypto.Response),
		committed:   make(map[crypto.Hash]bool),
		responsed:   make(map[crypto.Hash]bool),
	}

	if node.checkInitialAcceptSnapshot(s, tx) {
		s.Timestamp = uint64(clock.Now().UnixNano())
		s.Hash = s.PayloadHash()
		v := &CosiVerifier{Snapshot: s, random: crypto.NewPrivateKeyFromReader(rand.Reader)}
		R := crypto.Commitment(v.random.Public().Key())
		node.CosiVerifiers[s.Hash] = v
		agg.Commitments[len(node.SortedConsensusNodes)] = &R
		agg.responsed[node.IdForNetwork] = true
		node.CosiAggregators.Set(s.Hash, agg)
		for peerId := range node.ConsensusNodes {
			err := node.Peer.SendSnapshotAnnouncementMessage(peerId, s, crypto.Key(R))
			if err != nil {
				return err
			}
		}
		return nil
	}

	if node.ConsensusIndex < 0 || node.Graph.FinalRound[s.NodeId] == nil {
		return nil
	}

	cache := node.Graph.CacheRound[s.NodeId].Copy()
	final := node.Graph.FinalRound[s.NodeId].Copy()

	if len(cache.Snapshots) == 0 && !node.CheckBroadcastedToPeers() {
		return node.clearAndQueueSnapshotOrPanic(s)
	}
	for {
		s.Timestamp = uint64(clock.Now().UnixNano())
		if s.Timestamp > cache.Timestamp {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if len(cache.Snapshots) == 0 {
		external, err := node.persistStore.ReadRound(cache.References.External)
		if err != nil {
			return err
		}
		best := node.determinBestRound(s.NodeId, s.Timestamp)
		threshold := external.Timestamp + config.SnapshotReferenceThreshold*config.SnapshotRoundGap*36
		if best != nil && best.NodeId != final.NodeId && threshold < best.Start {
			logger.Verbosef("CosiLoop cosiHandleAction cosiSendAnnouncement new best external %s:%d:%d => %s:%d:%d\n", external.NodeId, external.Number, external.Timestamp, best.NodeId, best.Number, best.Start)
			link, err := node.persistStore.ReadLink(cache.NodeId, best.NodeId)
			if err != nil {
				return err
			}
			if best.Number <= link {
				return node.clearAndQueueSnapshotOrPanic(s)
			}
			cache.References = &common.RoundLink{
				Self:     final.Hash,
				External: best.Hash,
			}
			err = node.persistStore.UpdateEmptyHeadRound(cache.NodeId, cache.Number, cache.References)
			if err != nil {
				panic(err)
			}
			node.assignNewGraphRound(final, cache)
			return node.clearAndQueueSnapshotOrPanic(s)
		}
	} else if start, _ := cache.Gap(); s.Timestamp >= start+config.SnapshotRoundGap {
		best := node.determinBestRound(s.NodeId, s.Timestamp)
		if best == nil {
			logger.Verbosef("CosiLoop cosiHandleAction cosiSendAnnouncement no best available\n")
			return node.clearAndQueueSnapshotOrPanic(s)
		}
		if best.NodeId == final.NodeId {
			panic("should never be here")
		}

		final = cache.asFinal()
		cache = &CacheRound{
			NodeId: s.NodeId,
			Number: final.Number + 1,
			References: &common.RoundLink{
				Self:     final.Hash,
				External: best.Hash,
			},
		}
		err := node.persistStore.StartNewRound(cache.NodeId, cache.Number, cache.References, final.Start)
		if err != nil {
			panic(err)
		}
	}
	cache.Timestamp = s.Timestamp

	if len(cache.Snapshots) > 0 && s.Timestamp > cache.Snapshots[0].Timestamp+uint64(config.SnapshotRoundGap*4/5) {
		return node.clearAndQueueSnapshotOrPanic(s)
	}

	s.RoundNumber = cache.Number
	s.References = cache.References
	s.Hash = s.PayloadHash()
	v := &CosiVerifier{Snapshot: s, random: crypto.NewPrivateKeyFromReader(rand.Reader)}
	R := crypto.Commitment(v.random.Public().Key())
	node.CosiVerifiers[s.Hash] = v
	agg.Commitments[node.ConsensusIndex] = &R
	agg.responsed[node.IdForNetwork] = true
	node.assignNewGraphRound(final, cache)
	node.CosiAggregators.Set(s.Hash, agg)
	for peerId := range node.ConsensusNodes {
		err := node.Peer.SendSnapshotAnnouncementMessage(peerId, m.Snapshot, crypto.Key(R))
		if err != nil {
			return err
		}
	}
	return nil
}

func (node *Node) cosiHandleAnnouncement(m *CosiAction) error {
	logger.Verbosef("CosiLoop cosiHandleAction cosiHandleAnnouncement %s %v\n", m.PeerId, m.Snapshot)
	if node.ConsensusIndex < 0 || !node.CheckCatchUpWithPeers() {
		logger.Verbosef("CosiLoop cosiHandleAction cosiHandleAnnouncement CheckCatchUpWithPeers\n")
		return nil
	}
	cn := node.getPeerConsensusNode(m.PeerId)
	if cn == nil {
		return nil
	}
	if cn.Timestamp+uint64(config.KernelNodeAcceptPeriodMinimum) >= m.Snapshot.Timestamp && !node.genesisNodesMap[cn.IdForNetwork(node.networkId)] {
		return nil
	}

	s := m.Snapshot
	if s.NodeId == node.IdForNetwork || s.NodeId != m.PeerId {
		panic(fmt.Errorf("should never be here %s %s %s", node.IdForNetwork, s.NodeId, s.Signature))
	}
	if s.Version != common.SnapshotVersion || s.Signature != nil || s.Timestamp == 0 {
		return nil
	}
	threshold := config.SnapshotRoundGap * config.SnapshotReferenceThreshold
	if s.Timestamp > uint64(clock.Now().UnixNano())+threshold {
		return nil
	}
	if s.Timestamp+threshold*2 < node.Graph.GraphTimestamp {
		return nil
	}

	tx, finalized, err := node.checkCacheSnapshotTransaction(s)
	if err != nil || finalized {
		return nil
	}

	v := &CosiVerifier{Snapshot: s, random: crypto.NewPrivateKeyFromReader(rand.Reader)}
	if node.checkInitialAcceptSnapshotWeak(s) {
		node.CosiVerifiers[s.Hash] = v
		return node.Peer.SendSnapshotCommitmentMessage(s.NodeId, s.Hash, v.random.Public().Key(), tx == nil)
	}

	if s.RoundNumber == 0 || node.Graph.FinalRound[s.NodeId] == nil {
		return nil
	}

	cache := node.Graph.CacheRound[s.NodeId].Copy()
	final := node.Graph.FinalRound[s.NodeId].Copy()

	if s.RoundNumber < cache.Number {
		return nil
	}
	if s.RoundNumber > cache.Number+1 {
		return node.queueSnapshotOrPanic(m.PeerId, s)
	}
	if s.Timestamp <= final.Start+config.SnapshotRoundGap {
		return nil
	}
	if s.RoundNumber == cache.Number && !s.References.Equal(cache.References) {
		if len(cache.Snapshots) > 0 {
			return nil
		}
		if s.References.Self != cache.References.Self {
			return nil
		}
		external, err := node.persistStore.ReadRound(s.References.External)
		if err != nil || external == nil {
			return err
		}
		link, err := node.persistStore.ReadLink(cache.NodeId, external.NodeId)
		if err != nil {
			return err
		}
		if external.Number < link {
			return nil
		}
		cache.References = &common.RoundLink{
			Self:     s.References.Self,
			External: s.References.External,
		}
		err = node.persistStore.UpdateEmptyHeadRound(cache.NodeId, cache.Number, cache.References)
		if err != nil {
			panic(err)
		}
		node.assignNewGraphRound(final, cache)
		return node.queueSnapshotOrPanic(m.PeerId, s)
	}
	if s.RoundNumber == cache.Number+1 {
		round, _, err := node.startNewRound(s, cache, false)
		if err != nil {
			logger.Verbosef("ERROR verifyExternalSnapshot %s %d %s %s\n", s.NodeId, s.RoundNumber, s.Transaction, err.Error())
			return node.queueSnapshotOrPanic(m.PeerId, s)
		} else if round == nil {
			return nil
		} else {
			final = round
		}
		cache = &CacheRound{
			NodeId:     s.NodeId,
			Number:     s.RoundNumber,
			Timestamp:  s.Timestamp,
			References: s.References,
		}
		err = node.persistStore.StartNewRound(cache.NodeId, cache.Number, cache.References, final.Start)
		if err != nil {
			panic(err)
		}
	}
	node.assignNewGraphRound(final, cache)

	if err := cache.ValidateSnapshot(s, false); err != nil {
		return nil
	}

	node.CosiVerifiers[s.Hash] = v
	return node.Peer.SendSnapshotCommitmentMessage(s.NodeId, s.Hash, v.random.Public().Key(), tx == nil)
}

func (node *Node) cosiHandleCommitment(m *CosiAction) error {
	logger.Verbosef("CosiLoop cosiHandleAction cosiHandleCommitment %v\n", m)
	cn := node.ConsensusNodes[m.PeerId]
	if cn == nil {
		return nil
	}

	ann := node.CosiAggregators.Get(m.SnapshotHash)
	if ann == nil || ann.Snapshot.Hash != m.SnapshotHash {
		return nil
	}
	if ann.committed[m.PeerId] {
		return nil
	}
	if !node.CheckCatchUpWithPeers() && !node.checkInitialAcceptSnapshotWeak(ann.Snapshot) {
		logger.Verbosef("CosiLoop cosiHandleAction cosiHandleCommitment CheckCatchUpWithPeers\n")
		return nil
	}
	if cn.Timestamp+uint64(config.KernelNodeAcceptPeriodMinimum) >= ann.Snapshot.Timestamp && !node.genesisNodesMap[cn.IdForNetwork(node.networkId)] {
		return nil
	}
	ann.committed[m.PeerId] = true

	base := node.ConsensusThreshold(ann.Snapshot.Timestamp)
	if len(ann.Commitments) >= base {
		return nil
	}
	for i, id := range node.SortedConsensusNodes {
		if id == m.PeerId {
			ann.Commitments[i] = m.Commitment
			ann.WantTxs[m.PeerId] = m.WantTx
			break
		}
	}
	if len(ann.Commitments) < base {
		return nil
	}

	tx, finalized, err := node.checkCacheSnapshotTransaction(ann.Snapshot)
	if err != nil || finalized || tx == nil {
		return nil
	}

	cosi, err := crypto.CosiAggregateCommitments(ann.Commitments)
	if err != nil {
		return err
	}
	ann.Snapshot.Signature = cosi
	v := node.CosiVerifiers[m.SnapshotHash]
	priv := node.Signer.PrivateSpendKey
	publics := node.ConsensusKeys(ann.Snapshot.Timestamp)
	if node.checkInitialAcceptSnapshot(ann.Snapshot, tx) {
		publics = append(publics, node.ConsensusPledging.Signer.PublicSpendKey)
	}
	challenge, err := cosi.Challenge(publics, m.SnapshotHash[:])
	if err != nil {
		return err
	}

	signature := priv.SignWithChallenge(v.random, m.SnapshotHash[:], challenge)
	if node.checkInitialAcceptSnapshot(ann.Snapshot, tx) {
		cosi.AggregateSignature(len(node.SortedConsensusNodes), signature)
	} else {
		cosi.AggregateSignature(node.ConsensusIndex, signature)
	}
	for id := range node.ConsensusNodes {
		if wantTx, found := ann.WantTxs[id]; !found {
			continue
		} else if wantTx {
			err = node.Peer.SendTransactionChallengeMessage(id, m.SnapshotHash, cosi, tx)
		} else {
			err = node.Peer.SendTransactionChallengeMessage(id, m.SnapshotHash, cosi, nil)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (node *Node) cosiHandleChallenge(m *CosiAction) error {
	logger.Verbosef("CosiLoop cosiHandleAction cosiHandleChallenge %v\n", m)
	if node.ConsensusIndex < 0 || !node.CheckCatchUpWithPeers() {
		logger.Verbosef("CosiLoop cosiHandleAction cosiHandleChallenge CheckCatchUpWithPeers\n")
		return nil
	}
	if node.getPeerConsensusNode(m.PeerId) == nil {
		return nil
	}

	v := node.CosiVerifiers[m.SnapshotHash]
	if v == nil || v.Snapshot.Hash != m.SnapshotHash {
		return nil
	}

	if m.Transaction != nil {
		err := node.CachePutTransaction(m.PeerId, m.Transaction)
		if err != nil {
			return err
		}
	}

	s := v.Snapshot
	threshold := config.SnapshotRoundGap * config.SnapshotReferenceThreshold
	if s.Timestamp > uint64(clock.Now().UnixNano())+threshold {
		return nil
	}
	if s.Timestamp+threshold*2 < node.Graph.GraphTimestamp {
		return nil
	}

	tx, finalized, err := node.checkCacheSnapshotTransaction(s)
	if err != nil || finalized || tx == nil {
		return nil
	}

	pub := node.getPeerConsensusNode(s.NodeId).Signer.PublicSpendKey
	publics := node.ConsensusKeys(s.Timestamp)
	if node.checkInitialAcceptSnapshot(s, tx) {
		publics = append(publics, node.ConsensusPledging.Signer.PublicSpendKey)
	}
	challenge, err := m.Signature.Challenge(publics, m.SnapshotHash[:])
	if err != nil {
		return nil
	}

	if len(m.Signature.Signatures) != 1 {
		return fmt.Errorf("invalid CosiSignature signature size: %d", len(m.Signature.Signatures))
	}

	var sig crypto.Signature
	copy(sig[:], m.Signature.Signatures[0][:])
	sig.WithCommitment(s.Commitment)
	if !pub.VerifyWithChallenge(m.SnapshotHash[:], &sig, challenge) {
		return nil
	}

	response := m.Signature.DumpSignatureResponse(node.Signer.PrivateSpendKey.SignWithChallenge(v.random, m.SnapshotHash[:], challenge))
	return node.Peer.SendSnapshotResponseMessage(m.PeerId, m.SnapshotHash, response[:])
}

func (node *Node) cosiHandleResponse(m *CosiAction) error {
	logger.Verbosef("CosiLoop cosiHandleAction cosiHandleResponse %v\n", m)
	if node.ConsensusNodes[m.PeerId] == nil {
		return nil
	}

	agg := node.CosiAggregators.Get(m.SnapshotHash)
	if agg == nil || agg.Snapshot.Hash != m.SnapshotHash {
		return nil
	}
	if agg.responsed[m.PeerId] {
		return nil
	}
	if !node.CheckCatchUpWithPeers() && !node.checkInitialAcceptSnapshotWeak(agg.Snapshot) {
		logger.Verbosef("CosiLoop cosiHandleAction cosiHandleResponse CheckCatchUpWithPeers\n")
		return nil
	}
	if len(agg.responsed) >= len(agg.Commitments) {
		return nil
	}
	base := node.ConsensusThreshold(agg.Snapshot.Timestamp)
	if len(agg.Commitments) < base {
		return nil
	}

	s := agg.Snapshot
	tx, finalized, err := node.checkCacheSnapshotTransaction(s)
	if err != nil || finalized || tx == nil {
		return nil
	}

	for i, id := range node.SortedConsensusNodes {
		if id == m.PeerId {
			commitment := agg.Commitments[i]
			sig, err := agg.Snapshot.Signature.LoadResponseSignature(commitment, m.Response)
			if err != nil {
				return err
			}
			if err := agg.Snapshot.Signature.AggregateSignature(i, sig); err != nil {
				return err
			}
			break
		}
	}
	agg.responsed[m.PeerId] = true
	if len(agg.responsed) != len(agg.Commitments) {
		return nil
	}

	publics := node.ConsensusKeys(s.Timestamp)
	if node.checkInitialAcceptSnapshot(s, tx) {
		publics = append(publics, node.ConsensusPledging.Signer.PublicSpendKey)
	}
	if !node.CacheVerifyCosi(m.SnapshotHash, s.Signature, publics, base) {
		return nil
	}

	if node.checkInitialAcceptSnapshot(s, tx) {
		err := node.finalizeNodeAcceptSnapshot(s)
		if err != nil {
			return err
		}
		for id := range node.ConsensusNodes {
			err := node.Peer.SendSnapshotFinalizationMessage(id, s)
			if err != nil {
				return err
			}
		}
		return node.reloadConsensusNodesList(s, tx)
	}

	cache := node.Graph.CacheRound[s.NodeId].Copy()
	if s.RoundNumber > cache.Number {
		panic(fmt.Sprintf("should never be here %d %d", cache.Number, s.RoundNumber))
	}
	if s.RoundNumber < cache.Number {
		return node.clearAndQueueSnapshotOrPanic(s)
	}
	if !s.References.Equal(cache.References) {
		return node.clearAndQueueSnapshotOrPanic(s)
	}
	if err := cache.ValidateSnapshot(s, false); err != nil {
		return node.clearAndQueueSnapshotOrPanic(s)
	}

	topo := &common.SnapshotWithTopologicalOrder{
		Snapshot:         *s,
		TopologicalOrder: node.TopoCounter.Next(),
	}
	err = node.persistStore.WriteSnapshot(topo)
	if err != nil {
		panic(err)
	}
	if err := cache.ValidateSnapshot(s, true); err != nil {
		panic("should never be here")
	}
	node.Graph.CacheRound[s.NodeId] = cache

	for id := range node.ConsensusNodes {
		if !agg.responsed[id] {
			err := node.SendTransactionToPeer(id, agg.Snapshot.Transaction)
			if err != nil {
				return err
			}
		}
		err := node.Peer.SendSnapshotFinalizationMessage(id, agg.Snapshot)
		if err != nil {
			return err
		}
	}
	return node.reloadConsensusNodesList(s, tx)
}

func (node *Node) cosiHandleFinalization(m *CosiAction) error {
	logger.Verbosef("CosiLoop cosiHandleAction cosiHandleFinalization %s %v\n", m.PeerId, m.Snapshot)
	s, tx := m.Snapshot, m.Transaction

	if node.checkInitialAcceptSnapshot(s, tx) {
		err := node.finalizeNodeAcceptSnapshot(s)
		if err != nil {
			return err
		}
		return node.reloadConsensusNodesList(s, tx)
	}

	cache := node.Graph.CacheRound[s.NodeId].Copy()
	final := node.Graph.FinalRound[s.NodeId].Copy()

	if s.RoundNumber < cache.Number {
		logger.Verbosef("ERROR cosiHandleFinalization expired round %s %s %d %d\n", m.PeerId, s.Hash, s.RoundNumber, cache.Number)
		return nil
	}
	if s.RoundNumber > cache.Number+1 {
		return node.QueueAppendSnapshot(m.PeerId, s, true)
	}
	if s.RoundNumber == cache.Number && !s.References.Equal(cache.References) {
		if len(cache.Snapshots) != 0 {
			logger.Verbosef("ERROR cosiHandleFinalization malformated head round references not empty %s %v %d\n", m.PeerId, s, len(cache.Snapshots))
			return nil
		}
		if s.References.Self != cache.References.Self {
			logger.Verbosef("ERROR cosiHandleFinalization malformated head round references self diff %s %v %v\n", m.PeerId, s, cache.References)
			return nil
		}
		external, err := node.persistStore.ReadRound(s.References.External)
		if err != nil {
			return err
		}
		if external == nil {
			logger.Verbosef("ERROR cosiHandleFinalization head round references external not ready yet %s %v %v\n", m.PeerId, s, cache.References)
			return node.QueueAppendSnapshot(m.PeerId, s, true)
		}
		err = node.persistStore.UpdateEmptyHeadRound(cache.NodeId, cache.Number, s.References)
		if err != nil {
			panic(err)
		}
		cache.References = s.References
		node.assignNewGraphRound(final, cache)
		return node.QueueAppendSnapshot(m.PeerId, s, true)
	}
	if s.RoundNumber == cache.Number+1 {
		if round, _, err := node.startNewRound(s, cache, false); err != nil {
			return node.QueueAppendSnapshot(m.PeerId, s, true)
		} else if round == nil {
			logger.Verbosef("ERROR cosiHandleFinalization startNewRound empty %s %v\n", m.PeerId, s)
			return nil
		} else {
			final = round
		}
		cache = &CacheRound{
			NodeId:     s.NodeId,
			Number:     s.RoundNumber,
			Timestamp:  s.Timestamp,
			References: s.References,
		}
		err := node.persistStore.StartNewRound(cache.NodeId, cache.Number, cache.References, final.Start)
		if err != nil {
			panic(err)
		}
	}
	node.assignNewGraphRound(final, cache)

	if err := cache.ValidateSnapshot(s, false); err != nil {
		logger.Verbosef("ERROR cosiHandleFinalization ValidateSnapshot %s %v %s\n", m.PeerId, s, err.Error())
		return nil
	}
	topo := &common.SnapshotWithTopologicalOrder{
		Snapshot:         *s,
		TopologicalOrder: node.TopoCounter.Next(),
	}
	err := node.persistStore.WriteSnapshot(topo)
	if err != nil {
		panic(err)
	}
	if err := cache.ValidateSnapshot(s, true); err != nil {
		panic("should never be here")
	}
	node.assignNewGraphRound(final, cache)
	return node.reloadConsensusNodesList(s, tx)
}

func (node *Node) handleFinalization(m *CosiAction) error {
	logger.Debugf("CosiLoop cosiHandleAction handleFinalization %s %v\n", m.PeerId, m.Snapshot)
	s := m.Snapshot
	s.Hash = s.PayloadHash()
	if !node.verifyFinalization(s) {
		logger.Verbosef("ERROR handleFinalization verifyFinalization %s %v %d %t\n", m.PeerId, s, node.ConsensusThreshold(s.Timestamp), node.ConsensusRemovedRecently(s.Timestamp) != nil)
		return nil
	}

	if cache := node.Graph.CacheRound[s.NodeId]; cache != nil {
		if s.RoundNumber < cache.Number {
			logger.Verbosef("ERROR handleFinalization expired round %s %s %d %d\n", m.PeerId, s.Hash, s.RoundNumber, cache.Number)
			return nil
		}
		if s.RoundNumber > cache.Number+1 {
			return node.QueueAppendSnapshot(m.PeerId, s, true)
		}
	}

	dummy, err := node.tryToStartNewRound(s)
	if err != nil {
		logger.Verbosef("ERROR handleFinalization tryToStartNewRound %s %s %d %t %s\n", m.PeerId, s.Hash, node.ConsensusThreshold(s.Timestamp), node.ConsensusRemovedRecently(s.Timestamp) != nil, err.Error())
		return node.QueueAppendSnapshot(m.PeerId, s, true)
	} else if dummy {
		logger.Verbosef("ERROR handleFinalization tryToStartNewRound DUMMY %s %s %d %t\n", m.PeerId, s.Hash, node.ConsensusThreshold(s.Timestamp), node.ConsensusRemovedRecently(s.Timestamp) != nil)
		return node.QueueAppendSnapshot(m.PeerId, s, true)
	}

	tx, err := node.checkFinalSnapshotTransaction(s)
	if err != nil {
		logger.Verbosef("ERROR handleFinalization checkFinalSnapshotTransaction %s %s %d %t %s\n", m.PeerId, s.Hash, node.ConsensusThreshold(s.Timestamp), node.ConsensusRemovedRecently(s.Timestamp) != nil, err.Error())
		return node.QueueAppendSnapshot(m.PeerId, s, true)
	} else if tx == nil {
		logger.Verbosef("ERROR handleFinalization checkFinalSnapshotTransaction %s %s %d %t %s\n", m.PeerId, s.Hash, node.ConsensusThreshold(s.Timestamp), node.ConsensusRemovedRecently(s.Timestamp) != nil, "tx empty")
		return nil
	}
	if s.RoundNumber == 0 && tx.TransactionType() != common.TransactionTypeNodeAccept {
		return fmt.Errorf("invalid initial transaction type %d", tx.TransactionType())
	}

	m.Transaction = tx
	return node.cosiHandleFinalization(m)
}

func (node *Node) CosiQueueExternalAnnouncement(peerId crypto.Hash, s *common.Snapshot, commitment *crypto.Commitment) error {
	if node.getPeerConsensusNode(peerId) == nil {
		return nil
	}

	if s.Version != common.SnapshotVersion {
		return nil
	}
	if s.NodeId == node.IdForNetwork || s.NodeId != peerId {
		return nil
	}
	if s.Signature != nil || s.Timestamp == 0 || commitment == nil {
		return nil
	}
	s.Hash = s.PayloadHash()
	s.Commitment = commitment
	return node.QueueAppendSnapshot(peerId, s, false)
}

func (node *Node) CosiAggregateSelfCommitments(peerId crypto.Hash, snap crypto.Hash, commitment *crypto.Commitment, wantTx bool) error {
	if node.ConsensusNodes[peerId] == nil {
		return nil
	}

	m := &CosiAction{
		PeerId:       peerId,
		Action:       CosiActionSelfCommitment,
		SnapshotHash: snap,
		Commitment:   commitment,
		WantTx:       wantTx,
	}
	node.cosiActionsChan <- m
	return nil
}

func (node *Node) CosiQueueExternalChallenge(peerId crypto.Hash, snap crypto.Hash, cosi *crypto.CosiSignature, ver *common.VersionedTransaction) error {
	if node.getPeerConsensusNode(peerId) == nil {
		return nil
	}

	m := &CosiAction{
		PeerId:       peerId,
		Action:       CosiActionExternalChallenge,
		SnapshotHash: snap,
		Signature:    cosi,
		Transaction:  ver,
	}
	node.cosiActionsChan <- m
	return nil
}

func (node *Node) CosiAggregateSelfResponses(peerId crypto.Hash, snap crypto.Hash, response *crypto.Response) error {
	if node.ConsensusNodes[peerId] == nil {
		return nil
	}

	agg := node.CosiAggregators.Get(snap)
	if agg == nil {
		return nil
	}

	s := agg.Snapshot
	tx, finalized, err := node.checkCacheSnapshotTransaction(s)
	if err != nil || finalized || tx == nil {
		return nil
	}

	index := -1
	for i, id := range node.SortedConsensusNodes {
		if id == peerId {
			index = i
			break
		}
	}
	if index < 0 {
		return nil
	}
	publics := node.ConsensusKeys(s.Timestamp)
	if node.checkInitialAcceptSnapshotWeak(s) {
		publics = append(publics, node.ConsensusPledging.Signer.PublicSpendKey)
	}
	challenge, err := s.Signature.Challenge(publics, snap[:])
	if err != nil {
		return nil
	}

	commitment, ok := agg.Commitments[index]
	if !ok {
		return nil
	}
	sig, err := s.Signature.LoadResponseSignature(commitment, response)
	if err != nil {
		return nil
	}
	if !publics[index].VerifyWithChallenge(snap[:], sig, challenge) {
		return nil
	}

	m := &CosiAction{
		PeerId:       peerId,
		Action:       CosiActionSelfResponse,
		SnapshotHash: snap,
		Response:     response,
	}
	node.cosiActionsChan <- m
	return nil
}

func (node *Node) VerifyAndQueueAppendSnapshotFinalization(peerId crypto.Hash, s *common.Snapshot) error {
	s.Hash = s.PayloadHash()
	logger.Debugf("VerifyAndQueueAppendSnapshotFinalization(%s, %s)\n", peerId, s.Hash)
	if node.custom.Node.ConsensusOnly && node.getPeerConsensusNode(peerId) == nil {
		logger.Verbosef("VerifyAndQueueAppendSnapshotFinalization(%s, %s) invalid consensus peer\n", peerId, s.Hash)
		return nil
	}

	node.Peer.ConfirmSnapshotForPeer(peerId, s.Hash)
	err := node.Peer.SendSnapshotConfirmMessage(peerId, s.Hash)
	if err != nil {
		return err
	}
	inNode, err := node.persistStore.CheckTransactionInNode(s.NodeId, s.Transaction)
	if err != nil || inNode {
		logger.Verbosef("VerifyAndQueueAppendSnapshotFinalization(%s, %s) already finalized %t %v\n", peerId, s.Hash, inNode, err)
		return err
	}

	if s.Version == 0 {
		return node.legacyAppendFinalization(peerId, s)
	}
	if !node.verifyFinalization(s) {
		logger.Verbosef("ERROR VerifyAndQueueAppendSnapshotFinalization %s %v %d %t\n", peerId, s, node.ConsensusThreshold(s.Timestamp), node.ConsensusRemovedRecently(s.Timestamp) != nil)
		return nil
	}

	return node.QueueAppendSnapshot(peerId, s, true)
}

func (node *Node) getPeerConsensusNode(peerId crypto.Hash) *common.Node {
	if n := node.ConsensusPledging; n != nil && n.IdForNetwork(node.networkId) == peerId {
		return n
	}
	return node.ConsensusNodes[peerId]
}

type aggregatorMap struct {
	mutex *sync.RWMutex
	m     map[crypto.Hash]*CosiAggregator
}

func (s *aggregatorMap) Set(k crypto.Hash, p *CosiAggregator) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.m[k] = p
}

func (s *aggregatorMap) Get(k crypto.Hash) *CosiAggregator {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.m[k]
}

func (s *aggregatorMap) Delete(k crypto.Hash) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.m, k)
}
