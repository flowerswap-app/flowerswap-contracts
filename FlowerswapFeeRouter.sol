// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title FlowerswapFeeRouter (v2 — referral edition)
 * @notice Thin relay that sits in front of a whitelisted DEX aggregator
 *         (KyberSwap, 1inch, OpenOcean, ...). Takes a configurable fee
 *         on the input asset, splits it between the treasury and an
 *         optional referrer, then forwards the rest to the aggregator
 *         using user-supplied calldata.
 *
 *         The output token is sent directly to the user by the aggregator
 *         (the `recipient` field inside the aggregator calldata MUST be the
 *         end user), so this contract never custodies tokenOut.
 *
 * @dev    Fee model: input-side, fixed bps.
 *
 *         Referral rebates use a pull-payment ledger:
 *           - swap() records `referrerAmount` to `unclaimedRebates[ref][tok]`
 *           - referrer pulls their balance via claim(tokens[])
 *         This avoids untrusted external sends during swap (defense against
 *         broken/malicious referrer contracts, fee-on-transfer tokens, etc.)
 *
 *         Security guardrails:
 *         - aggregator must be explicitly whitelisted (owner-controlled)
 *         - fee hard-capped at MAX_FEE_BPS (1%)
 *         - referrerShareBps capped at FEE_DENOMINATOR (100% of fee)
 *         - nonReentrant on swap and claim
 *         - rescue() can NEVER touch funds owed to referrers
 *         - approve to aggregator is reset to 0 after each call
 */
contract FlowerswapFeeRouter is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    address public constant NATIVE = address(0);
    uint256 public constant FEE_DENOMINATOR = 10_000;
    /// @notice Absolute cap on `feeBps`. Cannot be raised even by owner.
    uint256 public constant MAX_FEE_BPS = 100; // 1%

    /// @notice Current fee in basis points (e.g. 10 = 0.10%).
    uint256 public feeBps;
    /// @notice Share of the fee allocated to the referrer (bps of FEE_DENOMINATOR).
    ///         e.g. 5000 = 50% of `feeBps` goes to the referrer when present.
    uint256 public referrerShareBps;
    /// @notice Treasury that receives the non-referrer portion of the fee.
    address public feeRecipient;

    /// @notice Aggregator routers the relay is allowed to call.
    mapping(address => bool) public allowedAggregators;

    // -- Referral rebate ledger (pull-payment) --
    /// @notice referrer => token => amount accrued and not yet claimed.
    mapping(address => mapping(address => uint256)) public unclaimedRebates;
    /// @notice referrer => token => lifetime amount earned (for stats).
    mapping(address => mapping(address => uint256)) public lifetimeEarned;
    /// @notice referrer => # of swaps that credited them.
    mapping(address => uint256) public referralCount;
    /// @notice token => total currently unclaimed across all referrers.
    ///         Used by rescue() to guarantee referrer funds stay safe.
    mapping(address => uint256) public totalUnclaimed;

    // -- Events --
    event Swap(
        address indexed user,
        address indexed aggregator,
        address tokenIn,
        uint256 amountIn,
        uint256 feeAmount,
        address indexed referrer,
        uint256 referrerAmount
    );
    event RebateAccrued(
        address indexed referrer,
        address indexed token,
        address indexed user,
        uint256 amount
    );
    event RebateClaimed(
        address indexed referrer,
        address indexed token,
        uint256 amount
    );
    event FeeBpsUpdated(uint256 oldBps, uint256 newBps);
    event ReferrerShareBpsUpdated(uint256 oldBps, uint256 newBps);
    event FeeRecipientUpdated(address oldRecipient, address newRecipient);
    event AggregatorSet(address indexed aggregator, bool allowed);
    event Rescue(address indexed token, address indexed to, uint256 amount);

    // -- Errors --
    error AggregatorNotAllowed(address aggregator);
    error ZeroAddress();
    error ZeroAmount();
    error BadMsgValue();
    error FeeTooHigh(uint256 feeBps);
    error InvalidShareBps(uint256 bps);
    error AggregatorCallFailed(bytes returnData);
    error NothingToClaim();
    error InsufficientFreeBalance(uint256 requested, uint256 free);

    constructor(
        address initialOwner,
        address _feeRecipient,
        uint256 _feeBps,
        uint256 _referrerShareBps,
        address[] memory initialAggregators
    ) Ownable(initialOwner) {
        if (_feeRecipient == address(0)) revert ZeroAddress();
        if (_feeBps > MAX_FEE_BPS) revert FeeTooHigh(_feeBps);
        if (_referrerShareBps > FEE_DENOMINATOR) {
            revert InvalidShareBps(_referrerShareBps);
        }

        feeRecipient = _feeRecipient;
        feeBps = _feeBps;
        referrerShareBps = _referrerShareBps;

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
     * @notice Preview how the fee on `amountIn` would be split for the
     *         given `referrer`. Mirrors the math used by swap().
     */
    function previewFee(uint256 amountIn, address referrer)
        external
        view
        returns (
            uint256 totalFee,
            uint256 treasuryAmount,
            uint256 referrerAmount,
            uint256 amountAfter
        )
    {
        totalFee = (amountIn * feeBps) / FEE_DENOMINATOR;
        if (
            referrer != address(0) &&
            referrer != msg.sender &&
            referrerShareBps > 0
        ) {
            referrerAmount = (totalFee * referrerShareBps) / FEE_DENOMINATOR;
        }
        treasuryAmount = totalFee - referrerAmount;
        amountAfter = amountIn - totalFee;
    }

    // ---------------------------------------------------------------------
    // Core
    // ---------------------------------------------------------------------

    /**
     * @notice Execute a fee-skimmed swap through `aggregator`, optionally
     *         crediting `referrer` with a share of the fee.
     *
     * @param aggregator Whitelisted aggregator router.
     * @param tokenIn    Address(0) for native (BNB), otherwise the ERC20.
     * @param amountIn   Total tokens the user wants to spend (fee included).
     * @param data       Aggregator calldata. `sender` MUST be this contract;
     *                   `recipient` MUST be the end user.
     * @param referrer   Optional referrer address. address(0) or self =
     *                   no referral, full fee goes to treasury.
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
        bool referralValid =
            referrer != address(0) &&
            referrer != msg.sender &&
            referrerShareBps > 0;

        uint256 referrerAmount = referralValid
            ? (totalFee * referrerShareBps) / FEE_DENOMINATOR
            : 0;
        uint256 treasuryAmount = totalFee - referrerAmount;
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

        if (referralValid && referrerAmount > 0) {
            unclaimedRebates[referrer][tokenIn] += referrerAmount;
            lifetimeEarned[referrer][tokenIn] += referrerAmount;
            totalUnclaimed[tokenIn] += referrerAmount;
            referralCount[referrer] += 1;
            emit RebateAccrued(referrer, tokenIn, msg.sender, referrerAmount);
        }

        emit Swap(
            msg.sender,
            aggregator,
            tokenIn,
            amountIn,
            totalFee,
            referrer,
            referrerAmount
        );
    }

    /**
     * @notice Claim accrued rebates across one or more tokens. Use
     *         `address(0)` for native (BNB).
     *
     *         Pull-payment: only the referrer itself can withdraw their
     *         own balance.
     */
    function claim(address[] calldata tokens) external nonReentrant {
        uint256 totalClaimedCount;
        for (uint256 i = 0; i < tokens.length; i++) {
            address tok = tokens[i];
            uint256 amount = unclaimedRebates[msg.sender][tok];
            if (amount == 0) continue;

            unclaimedRebates[msg.sender][tok] = 0;
            totalUnclaimed[tok] -= amount;
            totalClaimedCount += amount;

            if (tok == NATIVE) {
                _sendNative(msg.sender, amount);
            } else {
                IERC20(tok).safeTransfer(msg.sender, amount);
            }
            emit RebateClaimed(msg.sender, tok, amount);
        }
        if (totalClaimedCount == 0) revert NothingToClaim();
    }

    // ---------------------------------------------------------------------
    // Admin
    // ---------------------------------------------------------------------

    function setFeeBps(uint256 _feeBps) external onlyOwner {
        if (_feeBps > MAX_FEE_BPS) revert FeeTooHigh(_feeBps);
        emit FeeBpsUpdated(feeBps, _feeBps);
        feeBps = _feeBps;
    }

    function setReferrerShareBps(uint256 _bps) external onlyOwner {
        if (_bps > FEE_DENOMINATOR) revert InvalidShareBps(_bps);
        emit ReferrerShareBpsUpdated(referrerShareBps, _bps);
        referrerShareBps = _bps;
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

    /**
     * @notice Sweep dust balances the contract should never hold (e.g. a
     *         failed inner call, fee-on-transfer rounding). Strictly cannot
     *         touch funds owed to referrers — the call reverts if it would
     *         leave less than `totalUnclaimed[token]` in the contract.
     */
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
