// SPDX-License-Identifier: MIT
pragma solidity >=0.4.21;
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/draft-EIP712.sol";

contract SignatureDemo is Ownable {
    using SafeMath for uint256;
    using ECDSA for bytes32;
    uint256 storedData;
    address serverSigner;
    uint256 chainId = 1337;  // for Goerli test net. Change it to suit your network.
    address verifierContract;

    struct Unit {
        string actionType;
        uint256 timestamp;
        string authorizer;
    }
    /* if chainId is not a constant and instead dynamically initialized,
     * the hash calculation seems to be off and ecrecover() returns an unexpected signing address
    // uint256 internal chainId;
    // constructor(uint256 _chainId) public{
    //     chainId = _chainId;
    // }
    */

    // EIP-712 boilerplate begins
    event SignatureExtracted(address indexed signer, string action);

    string private constant EIP712_DOMAIN  = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
    string private constant UNIT_TYPE = "Unit(string actionType,uint256 timestamp,string authorizer)";

    // type hashes. Hash of the following strings:
    // 1. EIP712 Domain separator.
    // 2. string describing identity type
    // 3. string describing message type (enclosed identity type description included in the string)

    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(abi.encodePacked(EIP712_DOMAIN));
    bytes32 private constant UNIT_TYPEHASH = keccak256(abi.encodePacked(UNIT_TYPE));

  
    event ServerAddressChanged(address oldSigner, address newSigner);
    event ConfirmationSigRecieved(string testData, address signer);
    event ConfirmationResult(string confirmed);
    event verifierContractChanged(address oldverifierContract, address verifierContract);

    function setServerAddress(address serverAddress) public onlyOwner {
        address oldSigner = serverSigner;
        serverSigner = serverAddress;
        emit ServerAddressChanged(oldSigner, serverSigner);
    }

    function getServerAddress() public view returns (address) {
        return serverSigner;
    }

     function setverifierContract(address newVerifierContract) public onlyOwner {
        address oldverifierContract = verifierContract;
        verifierContract = newVerifierContract;
        emit verifierContractChanged(oldverifierContract, verifierContract);
    }

    function getverifierContract() public view returns (address) {
        return verifierContract;
    }

    function splitSignature(bytes memory sig)
        internal
        pure
        returns (
            uint8,
            bytes32,
            bytes32
        )
    {
        require(sig.length == 65);

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            // first 32 bytes, after the length prefix
            r := mload(add(sig, 32))
            // second 32 bytes
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }

        return (v, r, s);
    }
  
     // functions to generate hash representation of the struct objects

    function hashUnit(Unit memory unitobj) private view returns (bytes32) {
        bytes32 DOMAIN_SEPARATOR = keccak256(abi.encode(
        EIP712_DOMAIN_TYPEHASH,
        keccak256("VerifierApp101"),  // string name
        keccak256("1"),  // string version
        chainId,  // uint256 chainId
        verifierContract  // address verifyingContract
    ));

        return keccak256(abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(
                    UNIT_TYPEHASH,
                    keccak256(bytes(unitobj.actionType)),
                    unitobj.timestamp,
                    keccak256(bytes(unitobj.authorizer))
                ))
            ));
    }

    function submitProof(string memory actionType, uint256 timestamp, string memory authorizer, bytes memory sig) public {
        uint8 v;
        bytes32 r;
        bytes32 s;
        Unit memory _msg = Unit({
           actionType: actionType,
           timestamp: timestamp,
           authorizer: authorizer
        });
        (v, r, s) = splitSignature(sig);
        address recovered_signer = ecrecover(hashUnit(_msg), v, r, s);
        emit SignatureExtracted(recovered_signer, _msg.actionType);
        if( recovered_signer == serverSigner){
          emit ConfirmationResult("true");
          //proceed to call token procedures for example
        }
        else {
          emit ConfirmationResult("false");
        }
    }
}
