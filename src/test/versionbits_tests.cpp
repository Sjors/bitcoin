// Copyright (c) 2014-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <script/script.h>
#include <test/util/random.h>
#include <test/util/common.h>
#include <test/util/setup_common.h>
#include <test/util/versionbits.h>
#include <util/chaintype.h>
#include <versionbits.h>
#include <versionbits_impl.h>

#include <boost/test/unit_test.hpp>

/* Define a virtual block time, one block per 10 minutes after Nov 14 2014, 0:55:36am */
static int32_t TestTime(int nHeight) { return 1415926536 + 600 * nHeight; }

class TestConditionChecker final : public VersionBitsConditionChecker
{
private:
    mutable ThresholdConditionCache cache;

public:
    // constructor is implicit to allow for easier initialization of vector<TestConditionChecker>
    explicit(false) TestConditionChecker(const Consensus::BIP9Deployment& dep) : VersionBitsConditionChecker{dep} { }
    ~TestConditionChecker() override = default;

    ThresholdState StateFor(const CBlockIndex* pindexPrev) const { return AbstractThresholdConditionChecker::GetStateFor(pindexPrev, cache); }
    int StateSinceHeightFor(const CBlockIndex* pindexPrev) const { return AbstractThresholdConditionChecker::GetStateSinceHeightFor(pindexPrev, cache); }
    void clear() { cache.clear(); }
};

namespace {
struct Deployments
{
    const Consensus::BIP9Deployment normal{
        .bit = 8,
        .nStartTime = TestTime(10000),
        .nTimeout = TestTime(20000),
        .min_activation_height = 0,
        .period = 1000,
        .threshold = 900,
    };
    Consensus::BIP9Deployment always, never, delayed;
    Deployments()
    {
        delayed = normal; delayed.min_activation_height = 15000;
        always = normal; always.nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        never = normal; never.nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
    }
};

/** Deployments that use OP_RETURN signalling instead of per-deployment version bits */
struct OPReturnDeployments
{
    const Consensus::BIP9Deployment normal{
        .bit = Consensus::MIN_OP_RETURN_SIGNAL,
        .nStartTime = TestTime(10000),
        .nTimeout = TestTime(20000),
        .signal_tag = "BIP-9999",
        .min_activation_height = 0,
        .period = 1000,
        .threshold = 900,
    };
    Consensus::BIP9Deployment always, never, delayed;
    OPReturnDeployments()
    {
        delayed = normal; delayed.min_activation_height = 15000;
        always = normal; always.nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        never = normal; never.nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
    }
};
}

#define CHECKERS 6

using DeploymentSignals = Consensus::DeploymentSignals;

template<typename DeploymentSet = Deployments>
class VersionBitsTester
{
    FastRandomContext& m_rng;
    // A fake blockchain
    std::vector<CBlockIndex*> vpblock;

    // Used to automatically set the top bits for manual calls to Mine()
    const int32_t nVersionBase{0};

    // Setup BIP9Deployment structs for the checkers
    const DeploymentSet test_deployments;

    // 6 independent checkers for the same bit.
    // The first one performs all checks, the second only 50%, the third only 25%, etc...
    // This is to test whether lack of cached information leads to the same results.
    std::vector<TestConditionChecker> checker{CHECKERS, {test_deployments.normal}};
    // Another 6 that assume delayed activation
    std::vector<TestConditionChecker> checker_delayed{CHECKERS, {test_deployments.delayed}};
    // Another 6 that assume always active activation
    std::vector<TestConditionChecker> checker_always{CHECKERS, {test_deployments.always}};
    // Another 6 that assume never active activation
    std::vector<TestConditionChecker> checker_never{CHECKERS, {test_deployments.never}};

    // Test counter (to identify failures)
    int num{1000};

public:
    explicit VersionBitsTester(FastRandomContext& rng, int32_t nVersionBase=0) : m_rng{rng}, nVersionBase{nVersionBase} { }

    VersionBitsTester& Reset() {
        // Have each group of tests be counted by the 1000s part, starting at 1000
        num = num - (num % 1000) + 1000;

        for (unsigned int i = 0; i < vpblock.size(); i++) {
            delete vpblock[i];
        }
        for (unsigned int  i = 0; i < CHECKERS; i++) {
            checker[i].clear();
            checker_delayed[i].clear();
            checker_always[i].clear();
            checker_never[i].clear();
        }
        vpblock.clear();
        return *this;
    }

    ~VersionBitsTester() {
         Reset();
    }

    VersionBitsTester& Mine(unsigned int height, int32_t nTime, int32_t nVersion, DeploymentSignals deployment_signals = {})
    {
        while (vpblock.size() < height) {
            CBlockIndex* pindex = new CBlockIndex();
            pindex->nHeight = vpblock.size();
            pindex->pprev = Tip();
            pindex->nTime = nTime;
            pindex->nVersion = (nVersionBase | nVersion);
            if ((pindex->nVersion & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS) {
                // Manually populate m_deployment_signals because normal block
                // connection is bypassed.
                for (std::size_t bit = 0; bit < static_cast<std::size_t>(Consensus::MIN_OP_RETURN_SIGNAL); ++bit) {
                    if ((pindex->nVersion & (uint32_t{1} << bit)) != 0) {
                        pindex->m_deployment_signals.set(bit);
                    }
                }
                if ((pindex->nVersion & VERSIONBITS_DEPLOYMENT_OPRETURN_FLAG) != 0) {
                    pindex->m_deployment_signals |= deployment_signals;
                }
            }
            pindex->BuildSkip();
            vpblock.push_back(pindex);
        }
        return *this;
    }

    VersionBitsTester& TestStateSinceHeight(int height)
    {
        return TestStateSinceHeight(height, height);
    }

    VersionBitsTester& TestStateSinceHeight(int height, int height_delayed)
    {
        const CBlockIndex* tip = Tip();
        for (int i = 0; i < CHECKERS; i++) {
            if (m_rng.randbits(i) == 0) {
                BOOST_CHECK_MESSAGE(checker[i].StateSinceHeightFor(tip) == height, strprintf("Test %i for StateSinceHeight", num));
                BOOST_CHECK_MESSAGE(checker_delayed[i].StateSinceHeightFor(tip) == height_delayed, strprintf("Test %i for StateSinceHeight (delayed)", num));
                BOOST_CHECK_MESSAGE(checker_always[i].StateSinceHeightFor(tip) == 0, strprintf("Test %i for StateSinceHeight (always active)", num));
                BOOST_CHECK_MESSAGE(checker_never[i].StateSinceHeightFor(tip) == 0, strprintf("Test %i for StateSinceHeight (never active)", num));
            }
        }
        num++;
        return *this;
    }

    VersionBitsTester& TestState(ThresholdState exp)
    {
        return TestState(exp, exp);
    }

    VersionBitsTester& TestState(ThresholdState exp, ThresholdState exp_delayed)
    {
        if (exp != exp_delayed) {
            // only expected differences are that delayed stays in locked_in longer
            BOOST_CHECK_EQUAL(exp, ThresholdState::ACTIVE);
            BOOST_CHECK_EQUAL(exp_delayed, ThresholdState::LOCKED_IN);
        }

        const CBlockIndex* pindex = Tip();
        for (int i = 0; i < CHECKERS; i++) {
            if (m_rng.randbits(i) == 0) {
                ThresholdState got = checker[i].StateFor(pindex);
                ThresholdState got_delayed = checker_delayed[i].StateFor(pindex);
                ThresholdState got_always = checker_always[i].StateFor(pindex);
                ThresholdState got_never = checker_never[i].StateFor(pindex);
                // nHeight of the next block. If vpblock is empty, the next (ie first)
                // block should be the genesis block with nHeight == 0.
                int height = pindex == nullptr ? 0 : pindex->nHeight + 1;
                BOOST_CHECK_MESSAGE(got == exp, strprintf("Test %i for %s height %d (got %s)", num, StateName(exp), height, StateName(got)));
                BOOST_CHECK_MESSAGE(got_delayed == exp_delayed, strprintf("Test %i for %s height %d (got %s; delayed case)", num, StateName(exp_delayed), height, StateName(got_delayed)));
                BOOST_CHECK_MESSAGE(got_always == ThresholdState::ACTIVE, strprintf("Test %i for ACTIVE height %d (got %s; always active case)", num, height, StateName(got_always)));
                BOOST_CHECK_MESSAGE(got_never == ThresholdState::FAILED, strprintf("Test %i for FAILED height %d (got %s; never active case)", num, height, StateName(got_never)));
            }
        }
        num++;
        return *this;
    }

    VersionBitsTester& TestDefined() { return TestState(ThresholdState::DEFINED); }
    VersionBitsTester& TestStarted() { return TestState(ThresholdState::STARTED); }
    VersionBitsTester& TestLockedIn() { return TestState(ThresholdState::LOCKED_IN); }
    VersionBitsTester& TestActive() { return TestState(ThresholdState::ACTIVE); }
    VersionBitsTester& TestFailed() { return TestState(ThresholdState::FAILED); }

    // non-delayed should be active; delayed should still be locked in
    VersionBitsTester& TestActiveDelayed() { return TestState(ThresholdState::ACTIVE, ThresholdState::LOCKED_IN); }

    CBlockIndex* Tip() { return vpblock.empty() ? nullptr : vpblock.back(); }
};

BOOST_FIXTURE_TEST_SUITE(versionbits_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(versionbits_test)
{
    for (int i = 0; i < 64; i++) {
        // DEFINED -> STARTED after timeout reached -> FAILED
        VersionBitsTester(m_rng, VERSIONBITS_TOP_BITS).TestDefined().TestStateSinceHeight(0)
                           .Mine(1, TestTime(1), 0x100).TestDefined().TestStateSinceHeight(0)
                           .Mine(11, TestTime(11), 0x100).TestDefined().TestStateSinceHeight(0)
                           .Mine(989, TestTime(989), 0x100).TestDefined().TestStateSinceHeight(0)
                           .Mine(999, TestTime(20000), 0x100).TestDefined().TestStateSinceHeight(0) // Timeout and start time reached simultaneously
                           .Mine(1000, TestTime(20000), 0).TestStarted().TestStateSinceHeight(1000) // Hit started, stop signalling
                           .Mine(1999, TestTime(30001), 0).TestStarted().TestStateSinceHeight(1000)
                           .Mine(2000, TestTime(30002), 0x100).TestFailed().TestStateSinceHeight(2000) // Hit failed, start signalling again
                           .Mine(2001, TestTime(30003), 0x100).TestFailed().TestStateSinceHeight(2000)
                           .Mine(2999, TestTime(30004), 0x100).TestFailed().TestStateSinceHeight(2000)
                           .Mine(3000, TestTime(30005), 0x100).TestFailed().TestStateSinceHeight(2000)
                           .Mine(4000, TestTime(30006), 0x100).TestFailed().TestStateSinceHeight(2000)

        // DEFINED -> STARTED -> FAILED
                           .Reset().TestDefined().TestStateSinceHeight(0)
                           .Mine(1, TestTime(1), 0).TestDefined().TestStateSinceHeight(0)
                           .Mine(1000, TestTime(10000) - 1, 0x100).TestDefined().TestStateSinceHeight(0) // One second more and it would be defined
                           .Mine(2000, TestTime(10000), 0x100).TestStarted().TestStateSinceHeight(2000) // So that's what happens the next period
                           .Mine(2051, TestTime(10010), 0).TestStarted().TestStateSinceHeight(2000) // 51 old blocks
                           .Mine(2950, TestTime(10020), 0x100).TestStarted().TestStateSinceHeight(2000) // 899 new blocks
                           .Mine(3000, TestTime(20000), 0).TestFailed().TestStateSinceHeight(3000) // 50 old blocks (so 899 out of the past 1000)
                           .Mine(4000, TestTime(20010), 0x100).TestFailed().TestStateSinceHeight(3000)

        // DEFINED -> STARTED -> LOCKEDIN after timeout reached -> ACTIVE
                           .Reset().TestDefined().TestStateSinceHeight(0)
                           .Mine(1, TestTime(1), 0).TestDefined().TestStateSinceHeight(0)
                           .Mine(1000, TestTime(10000) - 1, 0x101).TestDefined().TestStateSinceHeight(0) // One second more and it would be defined
                           .Mine(2000, TestTime(10000), 0x101).TestStarted().TestStateSinceHeight(2000) // So that's what happens the next period
                           .Mine(2999, TestTime(30000), 0x100).TestStarted().TestStateSinceHeight(2000) // 999 new blocks
                           .Mine(3000, TestTime(30000), 0x100).TestLockedIn().TestStateSinceHeight(3000) // 1 new block (so 1000 out of the past 1000 are new)
                           .Mine(3999, TestTime(30001), 0).TestLockedIn().TestStateSinceHeight(3000)
                           .Mine(4000, TestTime(30002), 0).TestActiveDelayed().TestStateSinceHeight(4000, 3000)
                           .Mine(14333, TestTime(30003), 0).TestActiveDelayed().TestStateSinceHeight(4000, 3000)
                           .Mine(24000, TestTime(40000), 0).TestActive().TestStateSinceHeight(4000, 15000)

        // DEFINED -> STARTED -> LOCKEDIN before timeout -> ACTIVE
                           .Reset().TestDefined()
                           .Mine(1, TestTime(1), 0).TestDefined().TestStateSinceHeight(0)
                           .Mine(1000, TestTime(10000) - 1, 0x101).TestDefined().TestStateSinceHeight(0) // One second more and it would be defined
                           .Mine(2000, TestTime(10000), 0x101).TestStarted().TestStateSinceHeight(2000) // So that's what happens the next period
                           .Mine(2050, TestTime(10010), 0x200).TestStarted().TestStateSinceHeight(2000) // 50 old blocks
                           .Mine(2950, TestTime(10020), 0x100).TestStarted().TestStateSinceHeight(2000) // 900 new blocks
                           .Mine(2999, TestTime(19999), 0x200).TestStarted().TestStateSinceHeight(2000) // 49 old blocks
                           .Mine(3000, TestTime(29999), 0x200).TestLockedIn().TestStateSinceHeight(3000) // 1 old block (so 900 out of the past 1000)
                           .Mine(3999, TestTime(30001), 0).TestLockedIn().TestStateSinceHeight(3000)
                           .Mine(4000, TestTime(30002), 0).TestActiveDelayed().TestStateSinceHeight(4000, 3000) // delayed will not become active until height=15000
                           .Mine(14333, TestTime(30003), 0).TestActiveDelayed().TestStateSinceHeight(4000, 3000)
                           .Mine(15000, TestTime(40000), 0).TestActive().TestStateSinceHeight(4000, 15000)
                           .Mine(24000, TestTime(40000), 0).TestActive().TestStateSinceHeight(4000, 15000)

        // DEFINED multiple periods -> STARTED multiple periods -> FAILED
                           .Reset().TestDefined().TestStateSinceHeight(0)
                           .Mine(999, TestTime(999), 0).TestDefined().TestStateSinceHeight(0)
                           .Mine(1000, TestTime(1000), 0).TestDefined().TestStateSinceHeight(0)
                           .Mine(2000, TestTime(2000), 0).TestDefined().TestStateSinceHeight(0)
                           .Mine(3000, TestTime(10000), 0).TestStarted().TestStateSinceHeight(3000)
                           .Mine(4000, TestTime(10000), 0).TestStarted().TestStateSinceHeight(3000)
                           .Mine(5000, TestTime(10000), 0).TestStarted().TestStateSinceHeight(3000)
                           .Mine(5999, TestTime(20000), 0).TestStarted().TestStateSinceHeight(3000)
                           .Mine(6000, TestTime(20000), 0).TestFailed().TestStateSinceHeight(6000)
                           .Mine(7000, TestTime(20000), 0x100).TestFailed().TestStateSinceHeight(6000)
                           .Mine(24000, TestTime(20000), 0x100).TestFailed().TestStateSinceHeight(6000) // stay in FAILED no matter how much we signal
        ;
    }
}

struct BlockVersionTest : BasicTestingSetup {
/** Check that ComputeBlockVersion will set the appropriate bit correctly
 * Also checks IsActiveAfter() behaviour */
void check_computeblockversion(VersionBitsCache& versionbitscache, const Consensus::Params& params, Consensus::DeploymentPos dep)
{
    // Clear the cache every time
    versionbitscache.Clear();

    int64_t bit = params.vDeployments[dep].bit;
    int64_t nStartTime = params.vDeployments[dep].nStartTime;
    int64_t nTimeout = params.vDeployments[dep].nTimeout;
    int min_activation_height = params.vDeployments[dep].min_activation_height;
    uint32_t period = params.vDeployments[dep].period;
    uint32_t threshold = params.vDeployments[dep].threshold;

    BOOST_REQUIRE(period > 0); // no division by zero, thankyou
    BOOST_REQUIRE(0 < threshold); // must be able to have a window that doesn't activate
    BOOST_REQUIRE(threshold < period); // must be able to have a window that does activate

    // should not be any signalling for first block
    BOOST_CHECK_EQUAL(versionbitscache.ComputeBlockVersion(nullptr, params), VERSIONBITS_TOP_BITS);

    // always/never active deployments shouldn't need to be tested further
    if (nStartTime == Consensus::BIP9Deployment::ALWAYS_ACTIVE ||
        nStartTime == Consensus::BIP9Deployment::NEVER_ACTIVE)
    {
        if (nStartTime == Consensus::BIP9Deployment::ALWAYS_ACTIVE) {
            BOOST_CHECK(versionbitscache.IsActiveAfter(nullptr, params, dep));
        } else {
            BOOST_CHECK(!versionbitscache.IsActiveAfter(nullptr, params, dep));
        }
        BOOST_CHECK_EQUAL(min_activation_height, 0);
        BOOST_CHECK_EQUAL(nTimeout, Consensus::BIP9Deployment::NO_TIMEOUT);
        return;
    }

    BOOST_REQUIRE(nStartTime < nTimeout);
    BOOST_REQUIRE(nStartTime >= 0);
    BOOST_REQUIRE(nTimeout <= std::numeric_limits<uint32_t>::max() || nTimeout == Consensus::BIP9Deployment::NO_TIMEOUT);
    BOOST_REQUIRE(0 <= bit && bit < 32);
    // Make sure that no deployment tries to set an invalid bit.
    BOOST_REQUIRE(((1 << bit) & VERSIONBITS_TOP_MASK) == 0);
    BOOST_REQUIRE(min_activation_height >= 0);
    // Check min_activation_height is on a retarget boundary
    BOOST_REQUIRE_EQUAL(min_activation_height % period, 0U);

    // In the first chain, test that the bit is set by CBV until it has failed.
    // In the second chain, test the bit is set by CBV while STARTED and
    // LOCKED-IN, and then no longer set while ACTIVE.
    VersionBitsTester firstChain{m_rng}, secondChain{m_rng};

    int64_t nTime = nStartTime;

    const CBlockIndex *lastBlock = nullptr;

    // Before MedianTimePast of the chain has crossed nStartTime, the bit
    // should not be set.
    if (nTime == 0) {
        // since CBlockIndex::nTime is uint32_t we can't represent any
        // earlier time, so will transition from DEFINED to STARTED at the
        // end of the first period by mining blocks at nTime == 0
        lastBlock = firstChain.Mine(period - 1, nTime, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();
        BOOST_CHECK_EQUAL(versionbitscache.ComputeBlockVersion(lastBlock, params) & (1 << bit), 0);
        BOOST_CHECK(!versionbitscache.IsActiveAfter(lastBlock, params, dep));
        lastBlock = firstChain.Mine(period, nTime, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();
        BOOST_CHECK((versionbitscache.ComputeBlockVersion(lastBlock, params) & (1 << bit)) != 0);
        BOOST_CHECK(!versionbitscache.IsActiveAfter(lastBlock, params, dep));
        // then we'll keep mining at nStartTime...
    } else {
        // use a time 1s earlier than start time to check we stay DEFINED
        --nTime;

        // Start generating blocks before nStartTime
        lastBlock = firstChain.Mine(period, nTime, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();
        BOOST_CHECK_EQUAL(versionbitscache.ComputeBlockVersion(lastBlock, params) & (1 << bit), 0);
        BOOST_CHECK(!versionbitscache.IsActiveAfter(lastBlock, params, dep));

        // Mine more blocks (4 less than the adjustment period) at the old time, and check that CBV isn't setting the bit yet.
        for (uint32_t i = 1; i < period - 4; i++) {
            lastBlock = firstChain.Mine(period + i, nTime, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();
            BOOST_CHECK_EQUAL(versionbitscache.ComputeBlockVersion(lastBlock, params) & (1 << bit), 0);
            BOOST_CHECK(!versionbitscache.IsActiveAfter(lastBlock, params, dep));
        }
        // Now mine 5 more blocks at the start time -- MTP should not have passed yet, so
        // CBV should still not yet set the bit.
        nTime = nStartTime;
        for (uint32_t i = period - 4; i <= period; i++) {
            lastBlock = firstChain.Mine(period + i, nTime, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();
            BOOST_CHECK_EQUAL(versionbitscache.ComputeBlockVersion(lastBlock, params) & (1 << bit), 0);
            BOOST_CHECK(!versionbitscache.IsActiveAfter(lastBlock, params, dep));
        }
        // Next we will advance to the next period and transition to STARTED,
    }

    lastBlock = firstChain.Mine(period * 3, nTime, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();
    // so ComputeBlockVersion should now set the bit,
    BOOST_CHECK((versionbitscache.ComputeBlockVersion(lastBlock, params) & (1 << bit)) != 0);
    // and should also be using the VERSIONBITS_TOP_BITS.
    BOOST_CHECK_EQUAL(versionbitscache.ComputeBlockVersion(lastBlock, params) & VERSIONBITS_TOP_MASK, VERSIONBITS_TOP_BITS);
    BOOST_CHECK(!versionbitscache.IsActiveAfter(lastBlock, params, dep));

    // Check that ComputeBlockVersion will set the bit until nTimeout
    nTime += 600;
    uint32_t blocksToMine = period * 2; // test blocks for up to 2 time periods
    uint32_t nHeight = period * 3;
    // These blocks are all before nTimeout is reached.
    while (nTime < nTimeout && blocksToMine > 0) {
        lastBlock = firstChain.Mine(nHeight+1, nTime, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();
        BOOST_CHECK((versionbitscache.ComputeBlockVersion(lastBlock, params) & (1 << bit)) != 0);
        BOOST_CHECK_EQUAL(versionbitscache.ComputeBlockVersion(lastBlock, params) & VERSIONBITS_TOP_MASK, VERSIONBITS_TOP_BITS);
        BOOST_CHECK(!versionbitscache.IsActiveAfter(lastBlock, params, dep));
        blocksToMine--;
        nTime += 600;
        nHeight += 1;
    }

    if (nTimeout != Consensus::BIP9Deployment::NO_TIMEOUT) {
        // can reach any nTimeout other than NO_TIMEOUT due to earlier BOOST_REQUIRE

        nTime = nTimeout;

        // finish the last period before we start timing out
        while (nHeight % period != 0) {
            lastBlock = firstChain.Mine(nHeight+1, nTime - 1, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();
            BOOST_CHECK((versionbitscache.ComputeBlockVersion(lastBlock, params) & (1 << bit)) != 0);
            BOOST_CHECK(!versionbitscache.IsActiveAfter(lastBlock, params, dep));
            nHeight += 1;
        }

        // FAILED is only triggered at the end of a period, so CBV should be setting
        // the bit until the period transition.
        for (uint32_t i = 0; i < period - 1; i++) {
            lastBlock = firstChain.Mine(nHeight+1, nTime, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();
            BOOST_CHECK((versionbitscache.ComputeBlockVersion(lastBlock, params) & (1 << bit)) != 0);
            BOOST_CHECK(!versionbitscache.IsActiveAfter(lastBlock, params, dep));
            nHeight += 1;
        }
        // The next block should trigger no longer setting the bit.
        lastBlock = firstChain.Mine(nHeight+1, nTime, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();
        BOOST_CHECK_EQUAL(versionbitscache.ComputeBlockVersion(lastBlock, params) & (1 << bit), 0);
        BOOST_CHECK(!versionbitscache.IsActiveAfter(lastBlock, params, dep));
    }

    // On a new chain:
    // verify that the bit will be set after lock-in, and then stop being set
    // after activation.
    nTime = nStartTime;

    // Mine one period worth of blocks, and check that the bit will be on for the
    // next period.
    lastBlock = secondChain.Mine(period, nTime, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();
    BOOST_CHECK((versionbitscache.ComputeBlockVersion(lastBlock, params) & (1 << bit)) != 0);
    BOOST_CHECK(!versionbitscache.IsActiveAfter(lastBlock, params, dep));

    // Mine another period worth of blocks, signaling the new bit.
    lastBlock = secondChain.Mine(period * 2, nTime, VERSIONBITS_TOP_BITS | (1<<bit)).Tip();
    // After one period of setting the bit on each block, it should have locked in.
    // We keep setting the bit for one more period though, until activation.
    BOOST_CHECK((versionbitscache.ComputeBlockVersion(lastBlock, params) & (1 << bit)) != 0);
    BOOST_CHECK(!versionbitscache.IsActiveAfter(lastBlock, params, dep));

    // Now check that we keep mining the block until the end of this period, and
    // then stop at the beginning of the next period.
    lastBlock = secondChain.Mine((period * 3) - 1, nTime, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();
    BOOST_CHECK((versionbitscache.ComputeBlockVersion(lastBlock, params) & (1 << bit)) != 0);
    BOOST_CHECK(!versionbitscache.IsActiveAfter(lastBlock, params, dep));
    lastBlock = secondChain.Mine(period * 3, nTime, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();

    if (lastBlock->nHeight + 1 < min_activation_height) {
        // check signalling continues while min_activation_height is not reached
        lastBlock = secondChain.Mine(min_activation_height - 1, nTime, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();
        BOOST_CHECK((versionbitscache.ComputeBlockVersion(lastBlock, params) & (1 << bit)) != 0);
        BOOST_CHECK(!versionbitscache.IsActiveAfter(lastBlock, params, dep));
        // then reach min_activation_height, which was already REQUIRE'd to start a new period
        lastBlock = secondChain.Mine(min_activation_height, nTime, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();
    }

    // Check that we don't signal after activation
    BOOST_CHECK_EQUAL(versionbitscache.ComputeBlockVersion(lastBlock, params) & (1 << bit), 0);
    BOOST_CHECK(versionbitscache.IsActiveAfter(lastBlock, params, dep));
}
}; // struct BlockVersionTest

/** Test OP_RETURN signalling: version bit 0 as flag, signal in m_deployment_signals.
 *  Mirrors the structure of the existing versionbits_test above, substituting
 *  the signalling mechanism. */
BOOST_AUTO_TEST_CASE(versionbits_opreturn_signal)
{
    DeploymentSignals SIG;
    SIG.set(Consensus::MIN_OP_RETURN_SIGNAL);
    // Version for signalling blocks: top bits + bit 0 flag
    // (nVersionBase is already set to VERSIONBITS_TOP_BITS)
    const int32_t V_SIG = 0x01;  // bit 0 set
    const int32_t V_NONE = 0;    // no signal bits

    for (int i = 0; i < 64; i++) {
        // DEFINED -> STARTED after timeout reached -> FAILED
        VersionBitsTester<OPReturnDeployments>(m_rng, VERSIONBITS_TOP_BITS).TestDefined().TestStateSinceHeight(0)
                           .Mine(1, TestTime(1), V_SIG, SIG).TestDefined().TestStateSinceHeight(0)
                           .Mine(11, TestTime(11), V_SIG, SIG).TestDefined().TestStateSinceHeight(0)
                           .Mine(989, TestTime(989), V_SIG, SIG).TestDefined().TestStateSinceHeight(0)
                           .Mine(999, TestTime(20000), V_SIG, SIG).TestDefined().TestStateSinceHeight(0)
                           .Mine(1000, TestTime(20000), V_NONE).TestStarted().TestStateSinceHeight(1000) // Hit started, stop signalling
                           .Mine(1999, TestTime(30001), V_NONE).TestStarted().TestStateSinceHeight(1000)
                           .Mine(2000, TestTime(30002), V_SIG, SIG).TestFailed().TestStateSinceHeight(2000) // Timed out
                           .Mine(2001, TestTime(30003), V_SIG, SIG).TestFailed().TestStateSinceHeight(2000)
                           .Mine(2999, TestTime(30004), V_SIG, SIG).TestFailed().TestStateSinceHeight(2000)
                           .Mine(3000, TestTime(30005), V_SIG, SIG).TestFailed().TestStateSinceHeight(2000)
                           .Mine(4000, TestTime(30006), V_SIG, SIG).TestFailed().TestStateSinceHeight(2000)

        // DEFINED -> STARTED -> FAILED (insufficient signals)
                           .Reset().TestDefined().TestStateSinceHeight(0)
                           .Mine(1, TestTime(1), V_NONE).TestDefined().TestStateSinceHeight(0)
                           .Mine(1000, TestTime(10000) - 1, V_SIG, SIG).TestDefined().TestStateSinceHeight(0)
                           .Mine(2000, TestTime(10000), V_SIG, SIG).TestStarted().TestStateSinceHeight(2000)
                           .Mine(2051, TestTime(10010), V_NONE).TestStarted().TestStateSinceHeight(2000) // 51 old blocks
                           .Mine(2950, TestTime(10020), V_SIG, SIG).TestStarted().TestStateSinceHeight(2000) // 899 new blocks
                           .Mine(3000, TestTime(20000), V_NONE).TestFailed().TestStateSinceHeight(3000)
                           .Mine(4000, TestTime(20010), V_SIG, SIG).TestFailed().TestStateSinceHeight(3000)

        // DEFINED -> STARTED -> LOCKEDIN after timeout reached -> ACTIVE
                           .Reset().TestDefined().TestStateSinceHeight(0)
                           .Mine(1, TestTime(1), V_NONE).TestDefined().TestStateSinceHeight(0)
                           .Mine(1000, TestTime(10000) - 1, V_SIG, SIG).TestDefined().TestStateSinceHeight(0)
                           .Mine(2000, TestTime(10000), V_SIG, SIG).TestStarted().TestStateSinceHeight(2000)
                           .Mine(2999, TestTime(30000), V_SIG, SIG).TestStarted().TestStateSinceHeight(2000) // 999 new blocks
                           .Mine(3000, TestTime(30000), V_SIG, SIG).TestLockedIn().TestStateSinceHeight(3000) // 1000 signalling
                           .Mine(3999, TestTime(30001), V_NONE).TestLockedIn().TestStateSinceHeight(3000)
                           .Mine(4000, TestTime(30002), V_NONE).TestActiveDelayed().TestStateSinceHeight(4000, 3000)
                           .Mine(14333, TestTime(30003), V_NONE).TestActiveDelayed().TestStateSinceHeight(4000, 3000)
                           .Mine(24000, TestTime(40000), V_NONE).TestActive().TestStateSinceHeight(4000, 15000)

        // Test that wrong signal types don't count:
        //  - version bit 0 without OP_RETURN signal -> no signal
        //  - BIP9 version bit 8 (0x100) without OP_RETURN -> no signal
        //  - OP_RETURN signal without version bit 0 -> no signal
                           .Reset().TestDefined().TestStateSinceHeight(0)
                           .Mine(1, TestTime(1), V_NONE).TestDefined().TestStateSinceHeight(0)
                           .Mine(1000, TestTime(10000) - 1, V_NONE).TestDefined().TestStateSinceHeight(0)
                           .Mine(2000, TestTime(10000), V_NONE).TestStarted().TestStateSinceHeight(2000)
                           // Version bit 0 set but no OP_RETURN signal -> doesn't count
                           .Mine(3000, TestTime(10010), V_SIG, {}).TestStarted().TestStateSinceHeight(2000)
                           // BIP9 version bit 8 set, no OP_RETURN -> doesn't count
                           .Mine(4000, TestTime(10020), 0x100, {}).TestStarted().TestStateSinceHeight(2000)
                           // OP_RETURN signal set but no version bit 0 -> doesn't count
                           .Mine(5000, TestTime(10030), V_NONE, SIG).TestStarted().TestStateSinceHeight(2000)
                           // Finally, both version bit 0 AND OP_RETURN -> signals!
                           .Mine(6000, TestTime(10040), V_SIG, SIG).TestLockedIn().TestStateSinceHeight(6000)
        ;
    }
}

BOOST_AUTO_TEST_CASE(versionbits_opreturn_signal_parsing)
{
    Consensus::Params params;
    params.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY2] = {
        .bit = Consensus::MIN_OP_RETURN_SIGNAL,
        .signal_tag = "BIP-9999",
    };
    DeploymentSignals SIG;
    SIG.set(Consensus::MIN_OP_RETURN_SIGNAL);

    CMutableTransaction coinbase;
    coinbase.vout.emplace_back(0, CScript{} << OP_RETURN << std::vector<uint8_t>{'B', 'I', 'P', '-', '9', '9', '9', '9'});
    coinbase.vout.emplace_back(0, CScript{} << OP_RETURN << std::vector<uint8_t>{'B', 'I', 'P', '-', '0', '0', '0', '1'});
    coinbase.vout.emplace_back(0, CScript{} << OP_TRUE);

    CBlock block;
    block.nVersion = VERSIONBITS_TOP_BITS | VERSIONBITS_DEPLOYMENT_OPRETURN_FLAG;
    block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));

    BOOST_CHECK(GetDeploymentSignals(block, params) == SIG);

    CMutableTransaction non_signalling_coinbase;
    non_signalling_coinbase.vout.emplace_back(0, CScript{} << OP_RETURN << std::vector<uint8_t>{'B', 'I', 'P', '-', '0', '0', '0', '1'});

    CBlock non_signalling_block;
    non_signalling_block.nVersion = VERSIONBITS_TOP_BITS;
    non_signalling_block.vtx.push_back(MakeTransactionRef(std::move(non_signalling_coinbase)));

    BOOST_CHECK(GetDeploymentSignals(non_signalling_block, params).none());
}

BOOST_AUTO_TEST_CASE(versionbits_opreturn_computeblockversion)
{
    VersionBitsCache versionbitscache;
    DeploymentSignals SIG;
    SIG.set(Consensus::MIN_OP_RETURN_SIGNAL);

    ArgsManager args;
    args.ForceSetArg("-vbparams", "testdummy2:1199145601:1230767999"); // January 1, 2008 - December 31, 2008
    const auto chain_params = CreateChainParams(args, ChainType::REGTEST);
    auto params = chain_params->GetConsensus();
    params.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
    params.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY2].period = 1000;
    params.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY2].threshold = 900;

    VersionBitsTester<OPReturnDeployments> chain(m_rng, VERSIONBITS_TOP_BITS);
    CBlockIndex* last_block = chain.Mine(1000, TestTime(10000), 0).Tip();
    BOOST_CHECK_EQUAL(versionbitscache.ComputeBlockVersion(last_block, params), VERSIONBITS_TOP_BITS | VERSIONBITS_DEPLOYMENT_OPRETURN_FLAG);

    last_block = chain.Mine(2000, TestTime(10000), VERSIONBITS_DEPLOYMENT_OPRETURN_FLAG, SIG).Tip();
    BOOST_CHECK_EQUAL(versionbitscache.ComputeBlockVersion(last_block, params), VERSIONBITS_TOP_BITS | VERSIONBITS_DEPLOYMENT_OPRETURN_FLAG);

    last_block = chain.Mine(3000, TestTime(10000), 0).Tip();
    BOOST_CHECK_EQUAL(versionbitscache.ComputeBlockVersion(last_block, params) & VERSIONBITS_DEPLOYMENT_OPRETURN_FLAG, 0);
    BOOST_CHECK(versionbitscache.IsActiveAfter(last_block, params, Consensus::DEPLOYMENT_TESTDUMMY2));
}

BOOST_FIXTURE_TEST_CASE(versionbits_computeblockversion, BlockVersionTest)
{
    VersionBitsCache vbcache;

    // check that any deployment on any chain can conceivably reach both
    // ACTIVE and FAILED states in roughly the way we expect
    for (const auto& chain_type: {ChainType::MAIN, ChainType::TESTNET, ChainType::TESTNET4, ChainType::SIGNET, ChainType::REGTEST}) {
        const auto chainParams = CreateChainParams(*m_node.args, chain_type);
        uint32_t chain_all_vbits{0};
        for (int i = 0; i < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++i) {
            const auto dep = static_cast<Consensus::DeploymentPos>(i);
            // Check that no bits are reused (within the same chain). This is
            // disallowed because the transition to FAILED (on timeout) does
            // not take precedence over STARTED/LOCKED_IN. So all softforks on
            // the same bit might overlap, even when non-overlapping start-end
            // times are picked.
            const auto& dep_info = chainParams->GetConsensus().vDeployments[dep];
            const uint32_t dep_mask{uint32_t{1} << dep_info.bit};
            BOOST_CHECK(!(chain_all_vbits & dep_mask));
            chain_all_vbits |= dep_mask;
            BOOST_CHECK(0 <= dep_info.bit);
            if (chain_type != ChainType::REGTEST) {
                if (dep == Consensus::DEPLOYMENT_TESTDUMMY ||
                    dep == Consensus::DEPLOYMENT_TESTDUMMY2) {
                    BOOST_CHECK_EQUAL(dep_info.nStartTime, Consensus::BIP9Deployment::NEVER_ACTIVE);
                    BOOST_CHECK_EQUAL(dep_info.nTimeout, Consensus::BIP9Deployment::NO_TIMEOUT);
                } else if (dep_info.signal_tag.empty()) {
                    BOOST_CHECK(dep_info.bit < VERSIONBITS_NUM_BITS);
                }
            }
            if (dep_info.signal_tag.empty()) {
                BOOST_CHECK(dep_info.bit < VERSIONBITS_MAX_NUM_BITS);
                check_computeblockversion(vbcache, chainParams->GetConsensus(), dep);
            } else {
                BOOST_CHECK_EQUAL(dep_info.bit, Consensus::MIN_OP_RETURN_SIGNAL);
            }
        }
    }

    {
        // Use regtest/testdummy to ensure we always exercise some
        // deployment that's not always/never active
        ArgsManager args;
        args.ForceSetArg("-vbparams", "testdummy:1199145601:1230767999"); // January 1, 2008 - December 31, 2008
        const auto chainParams = CreateChainParams(args, ChainType::REGTEST);
        check_computeblockversion(vbcache, chainParams->GetConsensus(), Consensus::DEPLOYMENT_TESTDUMMY);
    }

    {
        // Use regtest/testdummy to ensure we always exercise the
        // min_activation_height test, even if we're not using that in a
        // live deployment
        ArgsManager args;
        args.ForceSetArg("-vbparams", "testdummy:1199145601:1230767999:403200"); // January 1, 2008 - December 31, 2008, min act height 403200
        const auto chainParams = CreateChainParams(args, ChainType::REGTEST);
        check_computeblockversion(vbcache, chainParams->GetConsensus(), Consensus::DEPLOYMENT_TESTDUMMY);
    }

    {
        ArgsManager args;
        args.ForceSetArg("-vbparams", "testdummy2:1199145601:1230767999"); // January 1, 2008 - December 31, 2008
        const auto chainParams = CreateChainParams(args, ChainType::REGTEST);
        BOOST_CHECK_EQUAL(chainParams->GetConsensus().vDeployments[Consensus::DEPLOYMENT_TESTDUMMY2].bit, Consensus::MIN_OP_RETURN_SIGNAL);
        BOOST_CHECK_EQUAL(chainParams->GetConsensus().vDeployments[Consensus::DEPLOYMENT_TESTDUMMY2].signal_tag, "BIP-9999");
    }
}

BOOST_AUTO_TEST_SUITE_END()
