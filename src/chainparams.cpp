// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2021 The Raven Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"
#include "arith_uint256.h"

#include <assert.h>
#include "chainparamsseeds.h"

#include <iostream>


// TODO: Take these out (kept from upstream)
extern double algoHashTotal[16];
extern int algoHashHits[16];

// ---------------------------------------------------------------------
// TODO (Ravencore): Fill these with your mined genesis values
// After updating these, you may also uncomment the asserts below.
static const uint32_t GEN_MAIN_TIME  = 1756389662;
static const uint32_t GEN_MAIN_NONCE = 2040671;

static const uint32_t GEN_TEST_TIME  = 1756389679;
static const uint32_t GEN_TEST_NONCE = 4567163;

static const uint32_t GEN_REG_TIME   = 1756389697;
static const uint32_t GEN_REG_NONCE  = 1075313;
// ---------------------------------------------------------------------

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << CScriptNum(0) << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    // UNIQUE to Ravencore so your merkle root is unique:
    const char* pszTimestamp = "Ravencore genesis - 2025-08-28 fair launch";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

void CChainParams::TurnOffSegwit() {
    consensus.nSegwitEnabled = false;
}

void CChainParams::TurnOffCSV() {
    consensus.nCSVEnabled = false;
}

void CChainParams::TurnOffBIP34() {
    consensus.nBIP34Enabled = false;
}

void CChainParams::TurnOffBIP65() {
    consensus.nBIP65Enabled = false;
}

void CChainParams::TurnOffBIP66() {
    consensus.nBIP66Enabled = false;
}

bool CChainParams::BIP34() {
    return consensus.nBIP34Enabled;
}

bool CChainParams::BIP65() {
    return consensus.nBIP65Enabled;
}

bool CChainParams::BIP66() {
    return consensus.nBIP66Enabled;
}

bool CChainParams::CSVEnabled() const{
    return consensus.nCSVEnabled;
}

/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 2100000;  //~ 4 yrs at 1 min block time
        consensus.nBIP34Enabled = true;
        consensus.nBIP65Enabled = true;
        consensus.nBIP66Enabled = true;
        consensus.nSegwitEnabled = true;
        consensus.nCSVEnabled = true;

        consensus.powLimit    = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.kawpowLimit = uint256S("0000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // Estimated starting diff for first 180 kawpow blocks
        consensus.nPowTargetTimespan = 2016 * 60; // 1.4 days
        consensus.nPowTargetSpacing  = 1 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting  = false;
        consensus.nRuleChangeActivationThreshold = 1613; // ~80% of 2016
        consensus.nMinerConfirmationWindow       = 2016;

        // Version bits (kept from upstream)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout   = 1230767999;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nOverrideRuleChangeActivationThreshold = 1814;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nOverrideMinerConfirmationWindow = 2016;

        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].bit = 6;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nStartTime = 1540944000;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nTimeout   = 1572480000;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nOverrideRuleChangeActivationThreshold = 1814;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nOverrideMinerConfirmationWindow = 2016;

        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].bit = 7;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nStartTime = 1578920400;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nTimeout   = 1610542800;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nOverrideRuleChangeActivationThreshold = 1714;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nOverrideMinerConfirmationWindow = 2016;

        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].bit = 8;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nStartTime = 1588788000;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nTimeout   = 1620324000;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nOverrideRuleChangeActivationThreshold = 1714;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nOverrideMinerConfirmationWindow = 2016;

        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].bit = 9;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nStartTime = 1593453600;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nTimeout   = 1624989600;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nOverrideRuleChangeActivationThreshold = 1411;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nOverrideMinerConfirmationWindow = 2016;

        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].bit = 10;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nStartTime = 1597341600;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nTimeout   = 1628877600;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nOverrideRuleChangeActivationThreshold = 1411;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nOverrideMinerConfirmationWindow = 2016;

        // New network identity (Ravencore MAINNET)
        pchMessageStart[0] = 0xA3;
        pchMessageStart[1] = 0xC1;
        pchMessageStart[2] = 0xB5;
        pchMessageStart[3] = 0xD7;
        nDefaultPort = 28770;
        nPruneAfterHeight = 100000;


        // ---- Ravencore mainnet genesis ----
        genesis = CreateGenesisBlock(
            /* nTime    */ GEN_MAIN_TIME,
            /* nNonce   */ GEN_MAIN_NONCE,
            /* nBits    */ 0x1e0ffff0,   // if your helper printed a different BITS, put it here
            /* nVersion */ 1,
            /* reward   */ 5000 * COIN
        );
        // Standard header hash for genesis (NOT X16R)
        consensus.hashGenesisBlock = genesis.GetHash();

//*************
//	std::cout << "MAINNET GENESIS nTime=" << genesis.nTime
//          << " nNonce=" << genesis.nNonce
//          << " nBits=0x" << strprintf("%08x", genesis.nBits)
 //         << " header=" << consensus.hashGenesisBlock.GetHex()
 //         << " merkle=" << genesis.hashMerkleRoot.GetHex()
 //         << std::endl;



//************ 6b17d77afde82d4b32b5b72a1fb79a90f5e719b13deb90b90487c5c6e11e9791
//orig hash 00000d57e20b023606f48665f66b9e6bb90091e38ea292092b1968deecdc457d
//orig merkel 638f060e3bf88a9abfe6a07e6ab3f801fd3ad6a6cec861ee5b832645d8e3252a
        assert(consensus.hashGenesisBlock == uint256S("0x6b17d77afde82d4b32b5b72a1fb79a90f5e719b13deb90b90487c5c6e11e9791"));
        assert(genesis.hashMerkleRoot   == uint256S("0x697a81aab7cf71cb4e6a2f7ae16420fcc34ce7965c54c463152e9ae5e0987f27"));

        // No seeds or checkpoints for a brand new chain
        vSeeds.clear();
        vFixedSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,60);   // 'R...' style
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,122);
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        // BIP44 cointype (RVN uses 175). Keep or change later if desired.
        nExtCoinType = 175;

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fMiningRequiresPeers = true;

        checkpointData = (CCheckpointData){{}};
        chainTxData = ChainTxData{0, 0, 0};

        // Reset work/assumeValid for a new chain
        consensus.nMinimumChainWork = uint256S("0x00");
        consensus.defaultAssumeValid = uint256S("0x00");

        /** RVN (assets/burns) retained; adjust later if desired **/
        nIssueAssetBurnAmount = 500 * COIN;
        nReissueAssetBurnAmount = 100 * COIN;
        nIssueSubAssetBurnAmount = 100 * COIN;
        nIssueUniqueAssetBurnAmount = 5 * COIN;
        nIssueMsgChannelAssetBurnAmount = 100 * COIN;
        nIssueQualifierAssetBurnAmount = 1000 * COIN;
        nIssueSubQualifierAssetBurnAmount = 100 * COIN;
        nIssueRestrictedAssetBurnAmount = 1500 * COIN;
        nAddNullQualifierTagBurnAmount = .1 * COIN;

        strIssueAssetBurnAddress        = "RXissueAssetXXXXXXXXXXXXXXXXXhhZGt";
        strReissueAssetBurnAddress      = "RXReissueAssetXXXXXXXXXXXXXXVEFAWu";
        strIssueSubAssetBurnAddress     = "RXissueSubAssetXXXXXXXXXXXXXWcwhwL";
        strIssueUniqueAssetBurnAddress  = "RXissueUniqueAssetXXXXXXXXXXWEAe58";
        strIssueMsgChannelAssetBurnAddress = "RXissueMsgChanneLAssetXXXXXXSjHvAY";
        strIssueQualifierAssetBurnAddress  = "RXissueQuaLifierXXXXXXXXXXXXUgEDbC";
        strIssueSubQualifierAssetBurnAddress = "RXissueSubQuaLifierXXXXXXXXXVTzvv5";
        strIssueRestrictedAssetBurnAddress  = "RXissueRestrictedXXXXXXXXXXXXzJZ1q";
        strAddNullQualifierTagBurnAddress   = "RXaddTagBurnXXXXXXXXXXXXXXXXZQm5ya";
        strGlobalBurnAddress               = "RXBurnXXXXXXXXXXXXXXXXXXXXXXWUo9FV";

        nDGWActivationBlock = 338778;
        nMaxReorganizationDepth = 60;
        nMinReorganizationPeers = 4;
        nMinReorganizationAge = 60 * 60 * 12;

        nAssetActivationHeight    = 435456;
        nMessagingActivationBlock = 1092672;
        nRestrictedActivationBlock= 1092672;
        
        // Put KAWPOW after genesis so block 0 uses X16R
	nKAAAWWWPOWActivationTime = GEN_TEST_TIME + 1;   // 1756389680
	nKAWPOWActivationTime     = nKAAAWWWPOWActivationTime;

       // nKAAAWWWPOWActivationTime = 1588788000;
       // nKAWPOWActivationTime     = nKAAAWWWPOWActivationTime;
    }
};

/**
 * Testnet
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 2100000;  //~ 4 yrs at 1 min block time
        consensus.nBIP34Enabled = true;
        consensus.nBIP65Enabled = true;
        consensus.nBIP66Enabled = true;
        consensus.nSegwitEnabled = true;
        consensus.nCSVEnabled = true;

        consensus.powLimit    = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.kawpowLimit = uint256S("000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 2016 * 60; // 1.4 days
        consensus.nPowTargetSpacing  = 1 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting  = false;
        consensus.nRuleChangeActivationThreshold = 1310; // ~65%
        consensus.nMinerConfirmationWindow       = 2016;

        // Version bits (kept)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout   = 1230767999;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nOverrideRuleChangeActivationThreshold = 1310;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nOverrideMinerConfirmationWindow = 2016;

        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].bit = 5;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nStartTime = 1533924000;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nTimeout   = 1577257200;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nOverrideRuleChangeActivationThreshold = 1310;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nOverrideMinerConfirmationWindow = 2016;

        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].bit = 6;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nStartTime = 1570428000;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nTimeout   = 1577257200;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nOverrideRuleChangeActivationThreshold = 1310;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nOverrideMinerConfirmationWindow = 2016;

        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].bit = 8;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nStartTime = 1586973600;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nTimeout   = 1618509600;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nOverrideRuleChangeActivationThreshold = 1310;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nOverrideMinerConfirmationWindow = 2016;

        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].bit = 9;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nStartTime = 1593453600;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nTimeout   = 1624989600;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nOverrideRuleChangeActivationThreshold = 1411;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nOverrideMinerConfirmationWindow = 2016;

        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].bit = 10;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nStartTime = 1597341600;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nTimeout   = 1628877600;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nOverrideRuleChangeActivationThreshold = 1411;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nOverrideMinerConfirmationWindow = 2016;

        // New network identity (Ravencore TESTNET)
        pchMessageStart[0] = 0xB4;
        pchMessageStart[1] = 0xA1;
        pchMessageStart[2] = 0x97;
        pchMessageStart[3] = 0x22;
        nDefaultPort = 38770;
        nPruneAfterHeight = 1000;

        // ---- Ravencore testnet genesis ----
        genesis = CreateGenesisBlock(
            /* nTime    */ GEN_TEST_TIME,
            /* nNonce   */ GEN_TEST_NONCE,
            /* nBits    */ 0x1e0ffff0,   // if helper printed different BITS for testnet, put it here
            /* nVersion */ 1,
            /* reward   */ 5000 * COIN
        ); 
      
       // 0x5658847386ed3314fa1b2585089560ab5d8ff9a4b450473f0cf7d71786a16b35
        consensus.hashGenesisBlock = genesis.GetHash();
        //************************
      //  std::cout << "TESTNET GENESIS nTime=" << genesis.nTime
      //    << " nNonce=" << genesis.nNonce
      //    << " nBits=0x" << strprintf("%08x", genesis.nBits)
      //    << " header=" << genesis.GetHash().GetHex()
      //    << " merkle=" << genesis.hashMerkleRoot.GetHex()
      //    << std::endl;

        
        //********************
//std::cout << "DEBUG Testnet consensus.hashGenesisBlock = " << consensus.hashGenesisBlock.GetHex() << std::endl;

        assert(consensus.hashGenesisBlock == uint256S("0x5658847386ed3314fa1b2585089560ab5d8ff9a4b450473f0cf7d71786a16b35"));
	assert(genesis.hashMerkleRoot == uint256S("0x697a81aab7cf71cb4e6a2f7ae16420fcc34ce7965c54c463152e9ae5e0987f27"));


        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        nExtCoinType = 1;

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fMiningRequiresPeers = true;

        checkpointData = (CCheckpointData){{}};
        chainTxData = ChainTxData{0, 0, 0};

        // Reset work/assumeValid for a new testnet
        consensus.nMinimumChainWork = uint256S("0x00");
        consensus.defaultAssumeValid = uint256S("0x00");

        /** RVN asset params retained **/
        nIssueAssetBurnAmount = 500 * COIN;
        nReissueAssetBurnAmount = 100 * COIN;
        nIssueSubAssetBurnAmount = 100 * COIN;
        nIssueUniqueAssetBurnAmount = 5 * COIN;
        nIssueMsgChannelAssetBurnAmount = 100 * COIN;
        nIssueQualifierAssetBurnAmount = 1000 * COIN;
        nIssueSubQualifierAssetBurnAmount = 100 * COIN;
        nIssueRestrictedAssetBurnAmount = 1500 * COIN;
        nAddNullQualifierTagBurnAmount = .1 * COIN;

        strIssueAssetBurnAddress = "n1issueAssetXXXXXXXXXXXXXXXXWdnemQ";
        strReissueAssetBurnAddress = "n1ReissueAssetXXXXXXXXXXXXXXWG9NLd";
        strIssueSubAssetBurnAddress = "n1issueSubAssetXXXXXXXXXXXXXbNiH6v";
        strIssueUniqueAssetBurnAddress = "n1issueUniqueAssetXXXXXXXXXXS4695i";
        strIssueMsgChannelAssetBurnAddress = "n1issueMsgChanneLAssetXXXXXXT2PBdD";
        strIssueQualifierAssetBurnAddress = "n1issueQuaLifierXXXXXXXXXXXXUysLTj";
        strIssueSubQualifierAssetBurnAddress = "n1issueSubQuaLifierXXXXXXXXXYffPLh";
        strIssueRestrictedAssetBurnAddress = "n1issueRestrictedXXXXXXXXXXXXZVT9V";
        strAddNullQualifierTagBurnAddress = "n1addTagBurnXXXXXXXXXXXXXXXXX5oLMH";

        strGlobalBurnAddress = "n1BurnXXXXXXXXXXXXXXXXXXXXXXU1qejP";

        nDGWActivationBlock = 1;
        nMaxReorganizationDepth = 60;
        nMinReorganizationPeers = 4;
        nMinReorganizationAge = 60 * 60 * 12;

        nAssetActivationHeight    = 6048;
        nMessagingActivationBlock = 10080;
        nRestrictedActivationBlock= 10080;
        
        // Put KAWPOW after genesis so block 0 uses X16R
	nKAAAWWWPOWActivationTime = GEN_TEST_TIME + 1;   // 1756389680
	nKAWPOWActivationTime     = nKAAAWWWPOWActivationTime;


        //nKAAAWWWPOWActivationTime = 1588788000; // 
        //nKAWPOWActivationTime     = nKAAAWWWPOWActivationTime;
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nBIP34Enabled = true;
        consensus.nBIP65Enabled = true;
        consensus.nBIP66Enabled = true;
        consensus.nSegwitEnabled = true;
        consensus.nCSVEnabled = true;
        consensus.nSubsidyHalvingInterval = 150;
        consensus.powLimit    = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.kawpowLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 2016 * 60;
        consensus.nPowTargetSpacing  = 1 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting  = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75%
        consensus.nMinerConfirmationWindow       = 144;

        // New network identity (Ravencore REGTEST)
        pchMessageStart[0] = 0xC7;
        pchMessageStart[1] = 0xD2;
        pchMessageStart[2] = 0x81;
        pchMessageStart[3] = 0x5F;
        nDefaultPort = 48770;
        nPruneAfterHeight = 1000;
//
// --- TEMP: mine regtest genesis with X16R ---
// Use the same nBits you want to keep for regtest:
//uint32_t bits = 0x1e0ffff0;
//arith_uint256 target; {
//    bool neg=false, overflow=false;
//    target.SetCompact(bits, &neg, &overflow);
//}

//uint32_t bestNonce = 0;
//uint256 bestHash = //uint256S("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

//for (uint32_t n = 0; n < 500000000; ++n) {
 //   CBlock tryBlock = CreateGenesisBlock(GEN_REG_TIME, n, bits, 1, 5000 * COIN);
 //   uint256 h = tryBlock.GetX16RHash(); // IMPORTANT: X16R pow hash
 //   if (UintToArith256(h) < UintToArith256(bestHash)) {
 //       bestHash = h;
 //       bestNonce = n;
 //       printf("candidate X16R hash=%s nonce=%u\n", bestHash.GetHex().c_str(), bestNonce);
 //   }
 //   if (UintToArith256(h) <= target) {
 //       printf("\nFOUND!\n");
 //       printf("[REG] GENESIS_TIME=%u\n", GEN_REG_TIME);
 //       printf("[REG] GENESIS_NONCE=%u\n", n);
 //       printf("[REG] MERKLE_ROOT=%s\n", tryBlock.hashMerkleRoot.GetHex().c_str());
 //       printf("[REG] GENESIS_HASH=%s\n", h.GetHex().c_str());
 //       printf("[REG] BITS=0x%08x\n", bits);
 //       abort(); // stop here; copy values; then remove this TEMP code
 //   }
//}
// If we got here, didn’t find one in range
//abort();

//
//
        // ---- Ravencore regtest genesis ----
        genesis = CreateGenesisBlock(
            /* nTime    */ GEN_REG_TIME,
            /* nNonce   */ GEN_REG_NONCE,
            /* nBits    */ 0x1e0ffff0, // match helper's BITS for regtest; change if you mined with 0x207fffff
            /* nVersion */ 1,
            /* reward   */ 5000 * COIN
        );
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0xd5e4e4d884c42887a680b728482448179f7b72184798ebca836eb3763345007b"));
        assert(genesis.hashMerkleRoot   == uint256S("0x697a81aab7cf71cb4e6a2f7ae16420fcc34ce7965c54c463152e9ae5e0987f27"));

        vFixedSeeds.clear();
        vSeeds.clear();

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = (CCheckpointData){{}};
        chainTxData = ChainTxData{0, 0, 0};

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        nExtCoinType = 1;

        /** RVN assets config retained **/
        nIssueAssetBurnAmount = 500 * COIN;
        nReissueAssetBurnAmount = 100 * COIN;
        nIssueSubAssetBurnAmount = 100 * COIN;
        nIssueUniqueAssetBurnAmount = 5 * COIN;
        nIssueMsgChannelAssetBurnAmount = 100 * COIN;
        nIssueQualifierAssetBurnAmount = 1000 * COIN;
        nIssueSubQualifierAssetBurnAmount = 100 * COIN;
        nIssueRestrictedAssetBurnAmount = 1500 * COIN;
        nAddNullQualifierTagBurnAmount = .1 * COIN;

        strIssueAssetBurnAddress = "n1issueAssetXXXXXXXXXXXXXXXXWdnemQ";
        strReissueAssetBurnAddress = "n1ReissueAssetXXXXXXXXXXXXXXWG9NLd";
        strIssueSubAssetBurnAddress = "n1issueSubAssetXXXXXXXXXXXXXbNiH6v";
        strIssueUniqueAssetBurnAddress = "n1issueUniqueAssetXXXXXXXXXXS4695i";
        strIssueMsgChannelAssetBurnAddress = "n1issueMsgChanneLAssetXXXXXXT2PBdD";
        strIssueQualifierAssetBurnAddress = "n1issueQuaLifierXXXXXXXXXXXXUysLTj";
        strIssueSubQualifierAssetBurnAddress = "n1issueSubQuaLifierXXXXXXXXXYffPLh";
        strIssueRestrictedAssetBurnAddress = "n1issueRestrictedXXXXXXXXXXXXZVT9V";
        strAddNullQualifierTagBurnAddress = "n1addTagBurnXXXXXXXXXXXXXXXXX5oLMH";

        strGlobalBurnAddress = "n1BurnXXXXXXXXXXXXXXXXXXXXXXU1qejP";

        nDGWActivationBlock = 200;
        nMaxReorganizationDepth = 60;
        nMinReorganizationPeers = 4;
        nMinReorganizationAge = 60 * 60 * 12;

        nAssetActivationHeight    = 0;
        nMessagingActivationBlock = 0;
        nRestrictedActivationBlock= 0;

        // Leave KAWPOW activation future for regtest unless you need to test it specifically
        nKAAAWWWPOWActivationTime = 1588788000;
        nKAWPOWActivationTime     = nKAAAWWWPOWActivationTime;

        // Reset work/assumeValid for a fresh regtest
        consensus.nMinimumChainWork = uint256S("0x00");
        consensus.defaultAssumeValid = uint256S("0x00");
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &GetParams() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network, bool fForceBlockNetwork)
{
    SelectBaseParams(network);
    if (fForceBlockNetwork) {
        bNetwork.SetNetwork(network);
    }
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}

void TurnOffSegwit(){
    globalChainParams->TurnOffSegwit();
}

void TurnOffCSV() {
    globalChainParams->TurnOffCSV();
}

void TurnOffBIP34() {
    globalChainParams->TurnOffBIP34();
}

void TurnOffBIP65() {
    globalChainParams->TurnOffBIP65();
}

void TurnOffBIP66() {
    globalChainParams->TurnOffBIP66();
}

