// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

interface IFlowerswapReferralRegistry {
    function quoteRebateSplit(address referrer)
        external
        view
        returns (address[3] memory payees, uint256[3] memory shares);
}

/**
 * @title FlowerswapRouter (v3 — multi-tier referral edition)
 * @notice Thin relay that sits in front of a whitelisted DEX aggregator
 *         (KyberSwap, 1inch, OpenOcean, ...). Takes a configurable fee
 *         on the input asset, splits it between the treasury and an
 *         optional 3-tier referral chain (resolved via the external
 *         `FlowerswapReferralRegistry`), then forwards the rest to the
 *         aggregator using user-supplied calldata.
 *
 *         The output token is sent directly to the user by the aggregator
 *         (the `recipient` field inside the aggregator calldata MUST be the
 *         end user), so this contract never custodies tokenOut.
 *
 * @dev    Referral split is computed by `registry.quoteRebateSplit(referrer)`
 *         which returns up to 3 (payee, sharesBps) pairs (T0, T1, T2). The
 *         router accrues each payee's portion to the pull-payment ledger;
 *         the rest goes to `feeRecipient`.
 *
 *         Self-protection: if any payee equals `msg.sender` (the swapper),
 *         that payee's share is redirected to the treasury — prevents a
 *         T0/T1 from earning a kickback on their own swap by passing one
 *         of their downstream agents as the referrer.
 *
 *         Other guardrails:
 *         - aggregator must be explicitly whitelisted (owner-controlled)
 *         - fee hard-capped at MAX_FEE_BPS (1%)
 *         - nonReentrant on swap and claim
 *         - rescue() can NEVER touch funds owed to referrers
 *         - approve to aggregator is reset to 0 after each call
 */
contract FlowerswapRouter is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    address public constant NATIVE = address(0);
    uint256 public constant FEE_DENOMINATOR = 10_000;
    /// @notice Absolute cap on `feeBps`. Cannot be raised even by owner.
    uint256 public constant MAX_FEE_BPS = 100; // 1%

    /// @notice Current fee in basis points (e.g. 10 = 0.10%).
    uint256 public feeBps;
    /// @notice Treasury that receives the non-referrer portion of the fee.
    address public feeRecipient;

    /// @notice External registry that resolves a referrer into up to 3
    ///         (payee, bps share) pairs. May be set to address(0) to fully
    ///         disable referrals — every fee then goes to the treasury.
    IFlowerswapReferralRegistry public registry;

    /// @notice Aggregator routers the relay is allowed to call.
    mapping(address => bool) public allowedAggregators;

    // -- Referral rebate ledger (pull-payment) --
    /// @notice payee => token => amount accrued and not yet claimed.
    mapping(address => mapping(address => uint256)) public unclaimedRebates;
    /// @notice payee => token => lifetime amount earned (for stats).
    mapping(address => mapping(address => uint256)) public lifetimeEarned;
    /// @notice payee => # of accruals across all tiers.
    mapping(address => uint256) public referralCount;
    /// @notice token => total currently unclaimed across all payees.
    ///         Used by rescue() to keep referrer funds safe.
    mapping(address => uint256) public totalUnclaimed;

    // -- Events --
    event Swap(
        address indexed user,
        address indexed aggregator,
        address tokenIn,
        uint256 amountIn,
        uint256 feeAmount,
        address indexed referrer,
        uint256 totalReferrerAmount
    );
    event RebateAccrued(
        address indexed payee,
        address indexed token,
        address indexed user,
        uint256 amount
    );
    event RebateClaimed(
        address indexed payee,
        address indexed token,
        uint256 amount
    );
    event FeeBpsUpdated(uint256 oldBps, uint256 newBps);
    event RegistryUpdated(address oldRegistry, address newRegistry);
    event FeeRecipientUpdated(address oldRecipient, address newRecipient);
    event AggregatorSet(address indexed aggregator, bool allowed);
    event Rescue(address indexed token, address indexed to, uint256 amount);

    // -- Errors --
    error AggregatorNotAllowed(address aggregator);
    error ZeroAddress();
    error ZeroAmount();
    error BadMsgValue();
    error FeeTooHigh(uint256 feeBps);
    error AggregatorCallFailed(bytes returnData);
    error NothingToClaim();
    error InsufficientFreeBalance(uint256 requested, uint256 free);

    constructor(
        address initialOwner,
        address _feeRecipient,
        uint256 _feeBps,
        address _registry,
        address[] memory initialAggregators
    ) Ownable(initialOwner) {
        if (_feeRecipient == address(0)) revert ZeroAddress();
        if (_feeBps > MAX_FEE_BPS) revert FeeTooHigh(_feeBps);

        feeRecipient = _feeRecipient;
        feeBps = _feeBps;
        registry = IFlowerswapReferralRegistry(_registry);
        emit RegistryUpdated(address(0), _registry);

        for (uint256 i = 0; i < initialAggregators.length; i++) {
            address a = initialAggregators[i];
            if (a == address(0)) revert ZeroAddress();
            allowedAggregators[a] = true;
            emit AggregatorSet(a, true);
        }
    }

    // ---------------------------------------------------------------------
    // Quotation helpers
    // ---------------------------------------------------------------------

    /**
     * @notice Preview how the fee on `amountIn` would be split for a swap
     *         routed through `referrer`. Mirrors the math in `swap()`.
     *
     *         Self-on-chain protection is applied as if `caller` were the
     *         swapper, so a UI can show the user-facing breakdown.
     */
    function previewFee(uint256 amountIn, address referrer, address caller)
        external
        view
        returns (
            uint256 totalFee,
            uint256 treasuryAmount,
            address[3] memory payees,
            uint256[3] memory amounts
        )
    {
        totalFee = (amountIn * feeBps) / FEE_DENOMINATOR;
        if (address(registry) != address(0) && referrer != address(0)) {
            uint256[3] memory shares;
            (payees, shares) = registry.quoteRebateSplit(referrer);
            uint256 totalReferral;
            for (uint256 i; i < 3; ++i) {
                if (shares[i] == 0 || payees[i] == address(0)) continue;
                if (payees[i] == caller) continue;
                amounts[i] = (totalFee * shares[i]) / FEE_DENOMINATOR;
                totalReferral += amounts[i];
            }
            treasuryAmount = totalFee - totalReferral;
        } else {
            treasuryAmount = totalFee;
        }
    }

    // ---------------------------------------------------------------------
    // Core
    // ---------------------------------------------------------------------

    /**
     * @notice Execute a fee-skimmed swap through `aggregator`, optionally
     *         crediting the referral chain attached to `referrer`.
     *
     * @param aggregator Whitelisted aggregator router.
     * @param tokenIn    Address(0) for native (BNB), otherwise the ERC20.
     * @param amountIn   Total tokens the user wants to spend (fee included).
     * @param data       Aggregator calldata. `sender` MUST be this contract;
     *                   `recipient` MUST be the end user.
     * @param referrer   Optional referrer address. Resolved via the
     *                   registry into up to 3 (payee, bps) pairs.
     */
    function swap(
        address aggregator,
        address tokenIn,
        uint256 amountIn,
        bytes calldata data,
        address referrer
    ) external payable nonReentrant {
        if (!allowedAggregators[aggregator]) revert AggregatorNotAllowed(aggregator);
        if (amountIn == 0) revert ZeroAmount();

        uint256 totalFee = (amountIn * feeBps) / FEE_DENOMINATOR;

        // Resolve the rebate plan. We compute amounts up-front so the
        // accrual + treasury split is settled before the (untrusted)
        // aggregator call runs.
        address[3] memory payees;
        uint256[3] memory amounts;
        uint256 totalReferral;

        if (address(registry) != address(0) && referrer != address(0)) {
            uint256[3] memory shares;
            (payees, shares) = registry.quoteRebateSplit(referrer);
            for (uint256 i; i < 3; ++i) {
                if (shares[i] == 0 || payees[i] == address(0)) continue;
                // Strict self-protection: a swapper sitting anywhere on
                // their own referral chain shouldn't earn a rebate. Their
                // tier's share goes to the treasury instead.
                if (payees[i] == msg.sender) continue;
                uint256 a = (totalFee * shares[i]) / FEE_DENOMINATOR;
                amounts[i] = a;
                totalReferral += a;
            }
        }

        uint256 treasuryAmount = totalFee - totalReferral;
        uint256 amountAfterFee = amountIn - totalFee;

        if (tokenIn == NATIVE) {
            if (msg.value != amountIn) revert BadMsgValue();

            if (treasuryAmount > 0) {
                _sendNative(feeRecipient, treasuryAmount);
            }
            // Referrer's native rebate stays escrowed in this contract.

            (bool ok, bytes memory ret) = aggregator.call{value: amountAfterFee}(data);
            if (!ok) revert AggregatorCallFailed(ret);
        } else {
            if (msg.value != 0) revert BadMsgValue();

            IERC20 token = IERC20(tokenIn);
            token.safeTransferFrom(msg.sender, address(this), amountIn);

            if (treasuryAmount > 0) {
                token.safeTransfer(feeRecipient, treasuryAmount);
            }
            // Referrer's ERC20 rebate stays escrowed in this contract.

            token.forceApprove(aggregator, amountAfterFee);
            (bool ok, bytes memory ret) = aggregator.call(data);
            if (!ok) {
                token.forceApprove(aggregator, 0);
                revert AggregatorCallFailed(ret);
            }
            token.forceApprove(aggregator, 0);
        }

        // Accrue per-tier rebates and emit one `RebateAccrued` per non-zero
        // payee. Done after the aggregator call so reverts inside it roll
        // everything back atomically.
        for (uint256 i; i < 3; ++i) {
            if (amounts[i] == 0) continue;
            unclaimedRebates[payees[i]][tokenIn] += amounts[i];
            lifetimeEarned[payees[i]][tokenIn] += amounts[i];
            totalUnclaimed[tokenIn] += amounts[i];
            referralCount[payees[i]] += 1;
            emit RebateAccrued(payees[i], tokenIn, msg.sender, amounts[i]);
        }

        emit Swap(
            msg.sender,
            aggregator,
            tokenIn,
            amountIn,
            totalFee,
            referrer,
            totalReferral
        );
    }

    /**
     * @notice Pull-payment claim across one or more tokens. Use
     *         `address(0)` for native (BNB).
     */
    function claim(address[] calldata tokens) external nonReentrant {
        uint256 totalClaimedAmount;
        for (uint256 i = 0; i < tokens.length; i++) {
            address tok = tokens[i];
            uint256 amount = unclaimedRebates[msg.sender][tok];
            if (amount == 0) continue;

            unclaimedRebates[msg.sender][tok] = 0;
            totalUnclaimed[tok] -= amount;
            totalClaimedAmount += amount;

            if (tok == NATIVE) {
                _sendNative(msg.sender, amount);
            } else {
                IERC20(tok).safeTransfer(msg.sender, amount);
            }
            emit RebateClaimed(msg.sender, tok, amount);
        }
        if (totalClaimedAmount == 0) revert NothingToClaim();
    }

    // ---------------------------------------------------------------------
    // Admin
    // ---------------------------------------------------------------------

    function setFeeBps(uint256 _feeBps) external onlyOwner {
        if (_feeBps > MAX_FEE_BPS) revert FeeTooHigh(_feeBps);
        emit FeeBpsUpdated(feeBps, _feeBps);
        feeBps = _feeBps;
    }

    function setRegistry(address _registry) external onlyOwner {
        emit RegistryUpdated(address(registry), _registry);
        registry = IFlowerswapReferralRegistry(_registry);
    }

    function setFeeRecipient(address _feeRecipient) external onlyOwner {
        if (_feeRecipient == address(0)) revert ZeroAddress();
        emit FeeRecipientUpdated(feeRecipient, _feeRecipient);
        feeRecipient = _feeRecipient;
    }

    function setAggregator(address aggregator, bool allowed) external onlyOwner {
        if (aggregator == address(0)) revert ZeroAddress();
        allowedAggregators[aggregator] = allowed;
        emit AggregatorSet(aggregator, allowed);
    }

    /// @notice Sweep dust balances. Cannot touch funds owed to referrers.
    function rescue(address token, address to, uint256 amount) external onlyOwner {
        if (to == address(0)) revert ZeroAddress();

        uint256 bal = token == NATIVE
            ? address(this).balance
            : IERC20(token).balanceOf(address(this));
        uint256 reserved = totalUnclaimed[token];
        uint256 free = bal > reserved ? bal - reserved : 0;
        if (amount > free) revert InsufficientFreeBalance(amount, free);

        if (token == NATIVE) {
            _sendNative(to, amount);
        } else {
            IERC20(token).safeTransfer(to, amount);
        }
        emit Rescue(token, to, amount);
    }

    // ---------------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------------

    function _sendNative(address to, uint256 amount) private {
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "native transfer failed");
    }

    /// @notice Accept refunds from aggregators (e.g. unused native dust).
    receive() external payable {}
}
