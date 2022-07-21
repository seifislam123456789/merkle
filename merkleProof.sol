// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

library Merkleprooff {

    function verify(
        bytes32[] memory prooff,
        bytes32 roott,
        bytes32 leaff
    ) internal pure returns (bool) {
        return processprooff(prooff, leaff) == roott;
    }


    function processprooff(bytes32[] memory prooff, bytes32 leaff) internal pure returns (bytes32) {
        bytes32 computedHash = leaff;
        for (uint256 i = 0; i < prooff.length; i++) {
            computedHash = _hashPair(computedHash, prooff[i]);
        }
        return computedHash;
    }

    function processprooffCalldata(bytes32[] calldata prooff, bytes32 leaff) internal pure returns (bytes32) {
        bytes32 computedHash = leaff;
        for (uint256 i = 0; i < prooff.length; i++) {
            computedHash = _hashPair(computedHash, prooff[i]);
        }
        return computedHash;
    }


    function multiprooffVerify(
        bytes32[] memory prooff,
        bool[] memory prooffFlags,
        bytes32 roott,
        bytes32[] memory leaves
    ) internal pure returns (bool) {
        return processMultiprooff(prooff, prooffFlags, leaves) == roott;
    }

    function multiprooffVerifyCalldata(
        bytes32[] calldata prooff,
        bool[] calldata prooffFlags,
        bytes32 roott,
        bytes32[] memory leaves
    ) internal pure returns (bool) {
        return processMultiprooffCalldata(prooff, prooffFlags, leaves) == roott;
    }


    function processMultiprooff(
        bytes32[] memory prooff,
        bool[] memory prooffFlags,
        bytes32[] memory leaves
    ) internal pure returns (bytes32 merkleroott) {
 
        uint256 leavesLen = leaves.length;
        uint256 totalHashes = prooffFlags.length;

        require(leavesLen + prooff.length - 1 == totalHashes, "Merkleprooff: invalid multiprooff");

    
        bytes32[] memory hashes = new bytes32[](totalHashes);
        uint256 leaffPos = 0;
        uint256 hashPos = 0;
        uint256 prooffPos = 0;

        for (uint256 i = 0; i < totalHashes; i++) {
            bytes32 a = leaffPos < leavesLen ? leaves[leaffPos++] : hashes[hashPos++];
            bytes32 b = prooffFlags[i] ? leaffPos < leavesLen ? leaves[leaffPos++] : hashes[hashPos++] : prooff[prooffPos++];
            hashes[i] = _hashPair(a, b);
        }

        if (totalHashes > 0) {
            return hashes[totalHashes - 1];
        } else if (leavesLen > 0) {
            return leaves[0];
        } else {
            return prooff[0];
        }
    }


    function processMultiprooffCalldata(
        bytes32[] calldata prooff,
        bool[] calldata prooffFlags,
        bytes32[] memory leaves
    ) internal pure returns (bytes32 merkleroott) {

        uint256 leavesLen = leaves.length;
        uint256 totalHashes = prooffFlags.length;

        require(leavesLen + prooff.length - 1 == totalHashes, "Merkleprooff: invalid multiprooff");


        bytes32[] memory hashes = new bytes32[](totalHashes);
        uint256 leaffPos = 0;
        uint256 hashPos = 0;
        uint256 prooffPos = 0;

        for (uint256 i = 0; i < totalHashes; i++) {
            bytes32 a = leaffPos < leavesLen ? leaves[leaffPos++] : hashes[hashPos++];
            bytes32 b = prooffFlags[i] ? leaffPos < leavesLen ? leaves[leaffPos++] : hashes[hashPos++] : prooff[prooffPos++];
            hashes[i] = _hashPair(a, b);
        }

        if (totalHashes > 0) {
            return hashes[totalHashes - 1];
        } else if (leavesLen > 0) {
            return leaves[0];
        } else {
            return prooff[0];
        }
    }

    function _hashPair(bytes32 a, bytes32 b) private pure returns (bytes32) {
        return a < b ? _efficientHash(a, b) : _efficientHash(b, a);
    }

    function _efficientHash(bytes32 a, bytes32 b) private pure returns (bytes32 value) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, a)
            mstore(0x20, b)
            value := keccak256(0x00, 0x40)
        }
    }
}
