// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// Little-endian byte packing.
///
/// Every wire format this repo speaks — Merlin/STROBE framing, Digestible
/// field encoding, the Blake2b F precompile — is little-endian, and the EVM is
/// big-endian. Three files had each grown their own copy of this conversion;
/// an endianness bug in any one of them produces a plausible digest that
/// matches nothing, which is the least debuggable failure this codebase can
/// have. One implementation, used everywhere, tested once.
library LE {
    function le32(uint32 x) internal pure returns (bytes memory b) {
        b = new bytes(4);
        unchecked {
            for (uint256 i = 0; i < 4; i++) b[i] = bytes1(uint8(x >> (8 * i)));
        }
    }

    function le64(uint64 x) internal pure returns (bytes memory b) {
        b = new bytes(8);
        unchecked {
            for (uint256 i = 0; i < 8; i++) b[i] = bytes1(uint8(x >> (8 * i)));
        }
    }

    /// Write `v` little-endian into `b` at `off`; returns the next offset so
    /// serializers can thread it.
    function put64(bytes memory b, uint256 off, uint64 v)
        internal
        pure
        returns (uint256)
    {
        unchecked {
            for (uint256 i = 0; i < 8; i++) {
                b[off + i] = bytes1(uint8(v >> (8 * i)));
            }
            return off + 8;
        }
    }

    function get64(bytes memory b, uint256 off)
        internal
        pure
        returns (uint64 v)
    {
        unchecked {
            for (uint256 i = 0; i < 8; i++) {
                v |= uint64(uint8(b[off + i])) << (8 * i);
            }
        }
    }
}
