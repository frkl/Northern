// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Copyright (c) 2018 The Northern developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"

#include "random.h"
#include "util.h"
#include "utilstrencodings.h"
#include <assert.h>

#include <boost/assign/list_of.hpp>

using namespace std;
using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

/**
 * Main network
 */

//! Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress>& vSeedsOut, const SeedSpec6* data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7 * 24 * 60 * 60;
    for (unsigned int i = 0; i < count; i++) {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}
//   What makes a good checkpoint block?
// + Is surrounded by blocks with reasonable timestamps
//   (no blocks before with a timestamp after, none after with
//    timestamp before)
// + Contains no strange transactions

static Checkpoints::MapCheckpoints mapCheckpoints =
    boost::assign::map_list_of
        (0, uint256("0x00000e68c6ddd656c615022da9cda3dc1e548288f683a7d496aacc9a77c55b17"));

static const Checkpoints::CCheckpointData data = {
    &mapCheckpoints,
    1518556170, // * UNIX timestamp of last checkpoint block
    0,    	// * total number of transactions between genesis and last checkpoint
                //   (the tx=... number in the SetBestChain debug.log lines)
    2000        // * estimated number of transactions per day after checkpoint
};

static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
    boost::assign::map_list_of(0, uint256("0x00000967e4707b2baf2ba18f811b9b2a7b4baca8f3bae5f1fc8cd18468128781"));
static const Checkpoints::CCheckpointData dataTestnet = {
    &mapCheckpointsTestnet,
    1518558575,
    0,
    100};
static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
    boost::assign::map_list_of(0, uint256("0x001"));
static const Checkpoints::CCheckpointData dataRegtest = {
    &mapCheckpointsRegtest,
    1454124731,
    0,
    100};
class CMainParams : public CChainParams
{
public:
    CMainParams()
    {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";
        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
	pchMessageStart[0] = 0x02;
	pchMessageStart[1] = 0x06;
	pchMessageStart[2] = 0xd2;
	pchMessageStart[3] = 0x04;

	vAlertPubKey = ParseHex("04657d53a6ab79c364955f04c4e8ea299a4ce972d7ce5ef20c782b570105c77ed64c483dc20af25eddfa3f85b95d00f33a6e35dc3ea7655310a3dc2a0c46e6135a");
	nDefaultPort = 60151;
	bnProofOfWorkLimit = ~uint256(0) >> 20; // Northern starting difficulty is 1 / 2^12
	nMaxReorganizationDepth = 100;
	nMinerThreads = 0;
	nTargetTimespan = 1 * 60; // Northern: 60s
	nTargetSpacing = 1 * 60; // Northern: 60s
	nLastPOWBlock = 518400; // Northern: 360 Days.
	nMaturity = 100; // 100 Minutes
	nMasternodeCountDrift = 4;
	nModifierUpdateBlock = 1;
	nMaxMoneyOut = 6466162 * COIN;
	
	nEnforceBlockUpgradeMajority = 750;
	nRejectBlockOutdatedMajority = 950;
	nToCheckBlockUpgradeMajority = 1000;

	const char* pszTimestamp = "Chloe Kim dominates in snowboard halfpipe to win Olympic gold. NBC 12/02/2018";
	CMutableTransaction txNew;
	txNew.vin.resize(1);
	txNew.vout.resize(1);
	txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
	txNew.vout[0].nValue = 10 * COIN;
	txNew.vout[0].scriptPubKey = CScript() << ParseHex("37346373796a6961314f4e2f30467637376d42346d6a43334653426d512b687142626c37413d3d0a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d0a") << OP_CHECKSIG;
	genesis.vtx.push_back(txNew);
	genesis.hashPrevBlock = 0;
	genesis.hashMerkleRoot = genesis.BuildMerkleTree();
	genesis.nVersion = 1;
	genesis.nTime = 1518556170;
	genesis.nBits = bnProofOfWorkLimit.GetCompact();;
	genesis.nNonce = 756830;

	hashGenesisBlock = genesis.GetHash();
	assert(hashGenesisBlock == uint256("0x00000e68c6ddd656c615022da9cda3dc1e548288f683a7d496aacc9a77c55b17"));
	assert(genesis.hashMerkleRoot == uint256("0xcd2552728eb8937b197aed49471d95cdb9b1a74e97e204cfdb1bd8c103461cf7"));

	vSeeds.push_back(CDNSSeedData("thesnoot.space", "northern.thesnoot.space"));
	vSeeds.push_back(CDNSSeedData("nort.network", "northern.nort.network"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 112); // Northern pubkey address starts with 'n'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 8); // Northern P2SH address starts with '4'
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 196); // Northern Private address starts with '2'
	
	// Extended Pubkey starts with 'xpub'
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
	// Extended Pubkey starts with 'xprv'
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
        //  BIP44 coin type is '5'
	base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0x05).convert_to_container<std::vector<unsigned char> >();
        
	convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));
        
	fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = false;
        fHeadersFirstSyncingActive = false;
        
	nPoolMaxTransactions = 3;
        strSporkKey = "04e3f9e69877d61b84510c28464bcbf41f102f8aeefb6182829b0cf2a92bb72cc4ba208f303fd707b1f1206a737eeeb0db12082d77bd463fece95de3eac29c5907";
        strObfuscationPoolDummyAddress = "NTcz4yxx67MHjMcyTDET4qXv3drpqYCRhd";
        nStartMasternodePayments = 1518512400; // Tuesday, February 13, 2018 9:00:00 AM (GMT)
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return data;
    }
};
static CMainParams mainParams;
/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams
{
public:
    CTestNetParams()
    {
        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";
        pchMessageStart[0] = 0xb3;
        pchMessageStart[1] = 0xc5;
        pchMessageStart[2] = 0xf3;
        pchMessageStart[3] = 0xb0;

	    vAlertPubKey = ParseHex("0418ee48636371ae4300eed0f10434a827ed373e76c415f11fcebd4ee2366e617b195a14c3d62009c516e1d901d04d48e21ddc328881127e0948a0023372f2ed2b");
        nDefaultPort = 50151;
        nMinerThreads = 0;
        nTargetTimespan = 1 * 60; // 60 Seconds
        nTargetSpacing = 1 * 60;  // 60 Seconds
        nLastPOWBlock = 1000;
        nMaturity = 15;
	bnProofOfWorkLimit = ~uint256(0) >> 18;
	nMaxMoneyOut = 100000000 * COIN;
        nEnforceBlockUpgradeMajority = 51;
        nRejectBlockOutdatedMajority = 75;
        nToCheckBlockUpgradeMajority = 100;

        genesis.nVersion = 1;
        genesis.nTime = 1518558575;
        genesis.nBits = bnProofOfWorkLimit.GetCompact();;
        genesis.nNonce = 62025;

	hashGenesisBlock = genesis.GetHash();
	assert(hashGenesisBlock == uint256("0x00000967e4707b2baf2ba18f811b9b2a7b4baca8f3bae5f1fc8cd18468128781"));
	assert(genesis.hashMerkleRoot == uint256("0xcd2552728eb8937b197aed49471d95cdb9b1a74e97e204cfdb1bd8c103461cf7"));
    	vFixedSeeds.clear();
    	vSeeds.clear();

	vSeeds.push_back(CDNSSeedData("thesnoot.space", "northerntestnet.thesnoot.space"));
	vSeeds.push_back(CDNSSeedData("nort.network", "northerntestnet.nort.network"));

	// Using Bitcoin defaults for Testnet
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
        // Testnet northern BIP44 coin type is '1' (All coin's testnet default)
        base58Prefixes[EXT_COIN_TYPE]  = boost::assign::list_of(0x80)(0x00)(0x00)(0x01).convert_to_container<std::vector<unsigned char> >();
        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));
        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;
        nPoolMaxTransactions = 2;
        strSporkKey = "0438b5c0e49036745799085e40aa03aa13f2b39799c1f7a58a9c5b70247f9f226019ae5ceb24896a75137b3b81a7260319705e674e0b9eed2231c6baa9c0faf39a";
        strObfuscationPoolDummyAddress = "TUQ57Fbh1crybrDhV6X9SDH95H4oSq4v6p";
        nStartMasternodePayments = 1518498005; //Tuesday, February 13, 2018 9:00:00 AM (GMT)
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataTestnet;
    }
};
static CTestNetParams testNetParams;
/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams
{
public:
    CRegTestParams()
    {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";
        strNetworkID = "regtest";
        pchMessageStart[0] = 0xa1;
        pchMessageStart[1] = 0xcf;
        pchMessageStart[2] = 0x7e;
        pchMessageStart[3] = 0xac;
        nMinerThreads = 1;
        nTargetTimespan = 24 * 60 * 60; // Northern: 1 day
        nTargetSpacing = 1 * 60;        // Northern: 1 minutes
        bnProofOfWorkLimit = ~uint256(0) >> 1;
        genesis.nTime = 1454124731;
        genesis.nBits = 0x207fffff;
        genesis.nNonce = 12345;
        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 51476;
//        assert(hashGenesisBlock == uint256("0"));
        vFixedSeeds.clear(); //! Testnet mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Testnet mode doesn't have any DNS seeds.
        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataRegtest;
    }
};
static CRegTestParams regTestParams;
/**
 * Unit test
 */
class CUnitTestParams : public CMainParams, public CModifiableParams
{
public:
    CUnitTestParams()
    {
        networkID = CBaseChainParams::UNITTEST;
        strNetworkID = "unittest";
        nDefaultPort = 51478;
        vFixedSeeds.clear(); //! Unit test mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Unit test mode doesn't have any DNS seeds.
        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fAllowMinDifficultyBlocks = false;
        fMineBlocksOnDemand = true;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        // UnitTest share the same checkpoints as MAIN
        return data;
    }
    //! Published setters to allow changing values in unit test cases
    virtual void setDefaultConsistencyChecks(bool afDefaultConsistencyChecks) { fDefaultConsistencyChecks = afDefaultConsistencyChecks; }
    virtual void setAllowMinDifficultyBlocks(bool afAllowMinDifficultyBlocks) { fAllowMinDifficultyBlocks = afAllowMinDifficultyBlocks; }
    virtual void setSkipProofOfWorkCheck(bool afSkipProofOfWorkCheck) { fSkipProofOfWorkCheck = afSkipProofOfWorkCheck; }
    virtual void setEnforceBlockUpgradeMajority(int anEnforceBlockUpgradeMajority) { nEnforceBlockUpgradeMajority = anEnforceBlockUpgradeMajority; }
    virtual void setRejectBlockOutdatedMajority(int anRejectBlockOutdatedMajority) { nRejectBlockOutdatedMajority = anRejectBlockOutdatedMajority; }
    virtual void setToCheckBlockUpgradeMajority(int anToCheckBlockUpgradeMajority) { nToCheckBlockUpgradeMajority = anToCheckBlockUpgradeMajority; }

};
static CUnitTestParams unitTestParams;
static CChainParams* pCurrentParams = 0;
CModifiableParams* ModifiableParams()
{
    assert(pCurrentParams);
    assert(pCurrentParams == &unitTestParams);
    return (CModifiableParams*)&unitTestParams;
}
const CChainParams& Params()
{
    assert(pCurrentParams);
    return *pCurrentParams;
}
CChainParams& Params(CBaseChainParams::Network network)
{
    switch (network) {
    case CBaseChainParams::MAIN:
        return mainParams;
    case CBaseChainParams::TESTNET:
        return testNetParams;
    case CBaseChainParams::REGTEST:
        return regTestParams;
    case CBaseChainParams::UNITTEST:
        return unitTestParams;
    default:
        assert(false && "Unimplemented network");
        return mainParams;
    }
}
void SelectParams(CBaseChainParams::Network network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}
bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;
    SelectParams(network);
    return true;
}
