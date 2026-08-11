// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IMobileCoinVerifier, VerifiedReturn} from "./IMobileCoinVerifier.sol";

/// TEST ONLY. Never deploy.
///
/// These exist so the escrow's accounting, replay set, freeze path and
/// beneficiary handling can be tested independently of the MobileCoin
/// cryptography. Keeping them in a file named TestMocks makes it obvious in a
/// diff when one is reachable from production code.

/// A USDC-shaped ERC20: 6 decimals, returns bool, no fee-on-transfer.
contract MockERC20 {
    string public name = "USD Coin";
    string public symbol = "USDC";
    uint8 public decimals = 6;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount)
        external
        returns (bool)
    {
        require(balanceOf[from] >= amount, "balance");
        uint256 a = allowance[from][msg.sender];
        require(a >= amount, "allowance");
        if (a != type(uint256).max) allowance[from][msg.sender] = a - amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// A verifier that trusts its input. TEST ONLY.
///
/// It decodes a VerifiedReturn straight out of the proof bytes, which is
/// exactly the thing the real verifier must never do. Using it in the escrow
/// tests isolates the escrow's own logic; the real verifier is tested against
/// MobileCoin fixtures separately.
contract MockVerifier is IMobileCoinVerifier {
    bool public shouldRevert;

    function setShouldRevert(bool v) external {
        shouldRevert = v;
    }

    function verifyReturn(bytes calldata proof)
        external
        view
        returns (VerifiedReturn memory)
    {
        require(!shouldRevert, "MockVerifier: forced failure");
        return abi.decode(proof, (VerifiedReturn));
    }
}

/// An ERC20 that re-enters the escrow on transfer. TEST ONLY.
contract ReentrantToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    address public target;
    bytes public payload;
    bool public armed;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function arm(address _target, bytes calldata _payload) external {
        target = _target;
        payload = _payload;
        armed = true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        if (armed) {
            armed = false;
            (bool ok,) = target.call(payload);
            require(ok, "reentry call failed");
        }
        return true;
    }

    function transferFrom(address from, address to, uint256 amount)
        external
        returns (bool)
    {
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        if (armed) {
            armed = false;
            (bool ok,) = target.call(payload);
            require(ok, "reentry call failed");
        }
        return true;
    }
}
