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

// TODO: Take these out (kept from upstream)
extern double algoHashTotal[16];
extern int algoHashHits[16];

// ---------------------------------------------------------------------
// TODO (Ravencore): Fill these with your mined genesis values
// After updating these, you may also uncomment the asserts below.
static const uint32_t GEN_MAIN_TIME  = 1756384384; // e.g., 1756339200
static const uint32_t GEN_MAIN_NONCE = 41035; // e.g., 1234567

static const uint32_t GEN_TEST_TIME  = 1756384408;
static const uint32_t GEN_TEST_NONCE = 1492244;

static const uint32_t GEN_REG_TIME   = 1756384427;
static const uint32_t GEN_REG_NONCE  = 427747;
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
    const char* pszTimestamp = "Ravencore genesis — 2025-08-28 fair launch";
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
    // FIX: previously returned nBIP34Enabled
    return consensus.nBIP65Enabled;
}

bool CChainParams::BIP66() {
    // FIX: previously returned nBIP34Enabled
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
            /* nBits    */ 0x1e0ffff0,
            /* nVersion */ 1,
            /* reward   */ 5000 * COIN
        );
        // Standard header hash for genesis (NOT X16R)
        consensus.hashGenesisBlock = genesis.GetHash();

        // Uncomment after you paste real values:
        assert(consensus.hashGenesisBlock == uint256S("0x0000020b54fa247ccc99a0e3e6f4913c203226d623a0a288de4a64ac0c4e2953"));
        assert(genesis.hashMerkleRoot   == uint256S("0x1ed27e5951fc873c4110e25cdc17ddf506c0e98fe48839215aa6e14ca0f8d1e"));

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

        nKAAAWWWPOWActivationTime = 1588788000;
        nKAWPOWActivationTime     = nKAAAWWWPOWActivationTime;
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
            /* nBits    */ 0x1e0ffff0,
            /* nVersion */ 1,
            /* reward   */ 5000 * COIN
        );
        consensus.hashGenesisBlock = genesis.GetHash();

        // Uncomment after you paste real values:
         assert(consensus.hashGenesisBlock == uint256S("0x000002f4a036f1f22a138356450208123940cd1080cf0dc8d384b4be1d781e09"));
        assert(genesis.hashMerkleRoot   == uint256S("0x1ed27e5951fc873c4110e25cdc17ddf506c0e98fe48839215aa6e14ca0f8d1e"));

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

        nKAAAWWWPOWActivationTime = 1585159200; // 2020-03-25 18:00:00 UTC
        nKAWPOWActivationTime     = nKAAAWWWPOWActivationTime;
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

        // ---- Ravencore regtest genesis ----
        genesis = CreateGenesisBlock(
            /* nTime    */ GEN_REG_TIME,
            /* nNonce   */ GEN_REG_NONCE,
            /* nBits    */ 0x207fffff, // super easy target for regtest
            /* nVersion */ 1,
            /* reward   */ 5000 * COIN
        );
        consensus.hashGenesisBlock = genesis.GetHash();

        // Uncomment after you paste real values:
      assert(consensus.hashGenesisBlock == uint256S("0x<00000b20377766df7e1b220953515a182ca447eecd643b8540d0dbcbbfbb81d4"));
      assert(genesis.hashMerkleRoot   == uint256S("0x1ed27e5951fc873c4110e25cdc17ddf506c0e98fe48839215aa6e14ca0f8d1e"));

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
        nKAAAWWWPOWActivationTime = 3582830167;
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

