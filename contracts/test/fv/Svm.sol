// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// Minimal Halmos symbolic-VM cheatcode interface (halmos-cheatcodes/SVM.sol).
interface SVM {
    function createUint(uint256 bitSize, string memory name) external pure returns (uint256);
    function createUint256(string memory name) external pure returns (uint256);
    function createBytes(uint256 byteSize, string memory name) external pure returns (bytes memory);
    function createBytes32(string memory name) external pure returns (bytes32);
    function createAddress(string memory name) external pure returns (address);
    function createBool(string memory name) external pure returns (bool);
    function enableSymbolicStorage(address target) external;
}

abstract contract SymTest {
    SVM internal constant svm = SVM(0xF3993A62377BCd56AE39D773740A5390411E8BC9);
}
