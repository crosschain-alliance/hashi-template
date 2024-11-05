// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity <0.9.0 >=0.5.10 ^0.8.0 ^0.8.20 ^0.8.8;

// node_modules/@eth-optimism/contracts-bedrock/src/libraries/Bytes.sol

/// @title Bytes
/// @notice Bytes is a library for manipulating byte arrays.
library Bytes {
    /// @custom:attribution https://github.com/GNSPS/solidity-bytes-utils
    /// @notice Slices a byte array with a given starting index and length. Returns a new byte array
    ///         as opposed to a pointer to the original array. Will throw if trying to slice more
    ///         bytes than exist in the array.
    /// @param _bytes Byte array to slice.
    /// @param _start Starting index of the slice.
    /// @param _length Length of the slice.
    /// @return Slice of the input byte array.
    function slice(bytes memory _bytes, uint256 _start, uint256 _length) internal pure returns (bytes memory) {
        unchecked {
            require(_length + 31 >= _length, "slice_overflow");
            require(_start + _length >= _start, "slice_overflow");
            require(_bytes.length >= _start + _length, "slice_outOfBounds");
        }

        bytes memory tempBytes;

        assembly {
            switch iszero(_length)
            case 0 {
                // Get a location of some free memory and store it in tempBytes as
                // Solidity does for memory variables.
                tempBytes := mload(0x40)

                // The first word of the slice result is potentially a partial
                // word read from the original array. To read it, we calculate
                // the length of that partial word and start copying that many
                // bytes into the array. The first word we copy will start with
                // data we don't care about, but the last `lengthmod` bytes will
                // land at the beginning of the contents of the new array. When
                // we're done copying, we overwrite the full first word with
                // the actual length of the slice.
                let lengthmod := and(_length, 31)

                // The multiplication in the next line is necessary
                // because when slicing multiples of 32 bytes (lengthmod == 0)
                // the following copy loop was copying the origin's length
                // and then ending prematurely not copying everything it should.
                let mc := add(add(tempBytes, lengthmod), mul(0x20, iszero(lengthmod)))
                let end := add(mc, _length)

                for {
                    // The multiplication in the next line has the same exact purpose
                    // as the one above.
                    let cc := add(add(add(_bytes, lengthmod), mul(0x20, iszero(lengthmod))), _start)
                } lt(mc, end) {
                    mc := add(mc, 0x20)
                    cc := add(cc, 0x20)
                } { mstore(mc, mload(cc)) }

                mstore(tempBytes, _length)

                //update free-memory pointer
                //allocating the array padded to 32 bytes like the compiler does now
                mstore(0x40, and(add(mc, 31), not(31)))
            }
            //if we want a zero-length slice let's just return a zero-length array
            default {
                tempBytes := mload(0x40)

                //zero out the 32 bytes slice we are about to return
                //we need to do it because Solidity does not garbage collect
                mstore(tempBytes, 0)

                mstore(0x40, add(tempBytes, 0x20))
            }
        }

        return tempBytes;
    }

    /// @notice Slices a byte array with a given starting index up to the end of the original byte
    ///         array. Returns a new array rathern than a pointer to the original.
    /// @param _bytes Byte array to slice.
    /// @param _start Starting index of the slice.
    /// @return Slice of the input byte array.
    function slice(bytes memory _bytes, uint256 _start) internal pure returns (bytes memory) {
        if (_start >= _bytes.length) {
            return bytes("");
        }
        return slice(_bytes, _start, _bytes.length - _start);
    }

    /// @notice Converts a byte array into a nibble array by splitting each byte into two nibbles.
    ///         Resulting nibble array will be exactly twice as long as the input byte array.
    /// @param _bytes Input byte array to convert.
    /// @return Resulting nibble array.
    function toNibbles(bytes memory _bytes) internal pure returns (bytes memory) {
        bytes memory _nibbles;
        assembly {
            // Grab a free memory offset for the new array
            _nibbles := mload(0x40)

            // Load the length of the passed bytes array from memory
            let bytesLength := mload(_bytes)

            // Calculate the length of the new nibble array
            // This is the length of the input array times 2
            let nibblesLength := shl(0x01, bytesLength)

            // Update the free memory pointer to allocate memory for the new array.
            // To do this, we add the length of the new array + 32 bytes for the array length
            // rounded up to the nearest 32 byte boundary to the current free memory pointer.
            mstore(0x40, add(_nibbles, and(not(0x1F), add(nibblesLength, 0x3F))))

            // Store the length of the new array in memory
            mstore(_nibbles, nibblesLength)

            // Store the memory offset of the _bytes array's contents on the stack
            let bytesStart := add(_bytes, 0x20)

            // Store the memory offset of the nibbles array's contents on the stack
            let nibblesStart := add(_nibbles, 0x20)

            // Loop through each byte in the input array
            for { let i := 0x00 } lt(i, bytesLength) { i := add(i, 0x01) } {
                // Get the starting offset of the next 2 bytes in the nibbles array
                let offset := add(nibblesStart, shl(0x01, i))
                // Load the byte at the current index within the `_bytes` array
                let b := byte(0x00, mload(add(bytesStart, i)))

                // Pull out the first nibble and store it in the new array
                mstore8(offset, shr(0x04, b))
                // Pull out the second nibble and store it in the new array
                mstore8(add(offset, 0x01), and(b, 0x0F))
            }
        }
        return _nibbles;
    }

    /// @notice Compares two byte arrays by comparing their keccak256 hashes.
    /// @param _bytes First byte array to compare.
    /// @param _other Second byte array to compare.
    /// @return True if the two byte arrays are equal, false otherwise.
    function equal(bytes memory _bytes, bytes memory _other) internal pure returns (bool) {
        return keccak256(_bytes) == keccak256(_other);
    }
}

// node_modules/@eth-optimism/contracts-bedrock/src/libraries/rlp/RLPErrors.sol

/// @notice The length of an RLP item must be greater than zero to be decodable
error EmptyItem();

/// @notice The decoded item type for list is not a list item
error UnexpectedString();

/// @notice The RLP item has an invalid data remainder
error InvalidDataRemainder();

/// @notice Decoded item type for bytes is not a string item
error UnexpectedList();

/// @notice The length of the content must be greater than the RLP item length
error ContentLengthMismatch();

/// @notice Invalid RLP header for RLP item
error InvalidHeader();

// node_modules/solidity-rlp/contracts/RLPReader.sol

/*
 * @author Hamdi Allam hamdi.allam97@gmail.com
 * Please reach out with any questions or concerns
 */

library RLPReader_0 {
    uint8 constant STRING_SHORT_START = 0x80;
    uint8 constant STRING_LONG_START = 0xb8;
    uint8 constant LIST_SHORT_START = 0xc0;
    uint8 constant LIST_LONG_START = 0xf8;
    uint8 constant WORD_SIZE = 32;

    struct RLPItem {
        uint256 len;
        uint256 memPtr;
    }

    struct Iterator {
        RLPItem item; // Item that's being iterated over.
        uint256 nextPtr; // Position of the next item in the list.
    }

    /*
     * @dev Returns the next element in the iteration. Reverts if it has not next element.
     * @param self The iterator.
     * @return The next element in the iteration.
     */
    function next(Iterator memory self) internal pure returns (RLPItem memory) {
        require(hasNext(self));

        uint256 ptr = self.nextPtr;
        uint256 itemLength = _itemLength(ptr);
        self.nextPtr = ptr + itemLength;

        return RLPItem(itemLength, ptr);
    }

    /*
     * @dev Returns true if the iteration has more elements.
     * @param self The iterator.
     * @return true if the iteration has more elements.
     */
    function hasNext(Iterator memory self) internal pure returns (bool) {
        RLPItem memory item = self.item;
        return self.nextPtr < item.memPtr + item.len;
    }

    /*
     * @param item RLP encoded bytes
     */
    function toRlpItem(bytes memory item) internal pure returns (RLPItem memory) {
        uint256 memPtr;
        assembly {
            memPtr := add(item, 0x20)
        }

        return RLPItem(item.length, memPtr);
    }

    /*
     * @dev Create an iterator. Reverts if item is not a list.
     * @param self The RLP item.
     * @return An 'Iterator' over the item.
     */
    function iterator(RLPItem memory self) internal pure returns (Iterator memory) {
        require(isList(self));

        uint256 ptr = self.memPtr + _payloadOffset(self.memPtr);
        return Iterator(self, ptr);
    }

    /*
     * @param the RLP item.
     */
    function rlpLen(RLPItem memory item) internal pure returns (uint256) {
        return item.len;
    }

    /*
     * @param the RLP item.
     * @return (memPtr, len) pair: location of the item's payload in memory.
     */
    function payloadLocation(RLPItem memory item) internal pure returns (uint256, uint256) {
        uint256 offset = _payloadOffset(item.memPtr);
        uint256 memPtr = item.memPtr + offset;
        uint256 len = item.len - offset; // data length
        return (memPtr, len);
    }

    /*
     * @param the RLP item.
     */
    function payloadLen(RLPItem memory item) internal pure returns (uint256) {
        (, uint256 len) = payloadLocation(item);
        return len;
    }

    /*
     * @param the RLP item containing the encoded list.
     */
    function toList(RLPItem memory item) internal pure returns (RLPItem[] memory) {
        require(isList(item));

        uint256 items = numItems(item);
        RLPItem[] memory result = new RLPItem[](items);

        uint256 memPtr = item.memPtr + _payloadOffset(item.memPtr);
        uint256 dataLen;
        for (uint256 i = 0; i < items; i++) {
            dataLen = _itemLength(memPtr);
            result[i] = RLPItem(dataLen, memPtr);
            memPtr = memPtr + dataLen;
        }

        return result;
    }

    // @return indicator whether encoded payload is a list. negate this function call for isData.
    function isList(RLPItem memory item) internal pure returns (bool) {
        if (item.len == 0) return false;

        uint8 byte0;
        uint256 memPtr = item.memPtr;
        assembly {
            byte0 := byte(0, mload(memPtr))
        }

        if (byte0 < LIST_SHORT_START) return false;
        return true;
    }

    /*
     * @dev A cheaper version of keccak256(toRlpBytes(item)) that avoids copying memory.
     * @return keccak256 hash of RLP encoded bytes.
     */
    function rlpBytesKeccak256(RLPItem memory item) internal pure returns (bytes32) {
        uint256 ptr = item.memPtr;
        uint256 len = item.len;
        bytes32 result;
        assembly {
            result := keccak256(ptr, len)
        }
        return result;
    }

    /*
     * @dev A cheaper version of keccak256(toBytes(item)) that avoids copying memory.
     * @return keccak256 hash of the item payload.
     */
    function payloadKeccak256(RLPItem memory item) internal pure returns (bytes32) {
        (uint256 memPtr, uint256 len) = payloadLocation(item);
        bytes32 result;
        assembly {
            result := keccak256(memPtr, len)
        }
        return result;
    }

    /** RLPItem conversions into data types **/

    // @returns raw rlp encoding in bytes
    function toRlpBytes(RLPItem memory item) internal pure returns (bytes memory) {
        bytes memory result = new bytes(item.len);
        if (result.length == 0) return result;

        uint256 ptr;
        assembly {
            ptr := add(0x20, result)
        }

        copy(item.memPtr, ptr, item.len);
        return result;
    }

    // any non-zero byte except "0x80" is considered true
    function toBoolean(RLPItem memory item) internal pure returns (bool) {
        require(item.len == 1);
        uint256 result;
        uint256 memPtr = item.memPtr;
        assembly {
            result := byte(0, mload(memPtr))
        }

        // SEE Github Issue #5.
        // Summary: Most commonly used RLP libraries (i.e Geth) will encode
        // "0" as "0x80" instead of as "0". We handle this edge case explicitly
        // here.
        if (result == 0 || result == STRING_SHORT_START) {
            return false;
        } else {
            return true;
        }
    }

    function toAddress(RLPItem memory item) internal pure returns (address) {
        // 1 byte for the length prefix
        require(item.len == 21);

        return address(uint160(toUint(item)));
    }

    function toUint(RLPItem memory item) internal pure returns (uint256) {
        require(item.len > 0 && item.len <= 33);

        (uint256 memPtr, uint256 len) = payloadLocation(item);

        uint256 result;
        assembly {
            result := mload(memPtr)

            // shift to the correct location if neccesary
            if lt(len, 32) {
                result := div(result, exp(256, sub(32, len)))
            }
        }

        return result;
    }

    // enforces 32 byte length
    function toUintStrict(RLPItem memory item) internal pure returns (uint256) {
        // one byte prefix
        require(item.len == 33);

        uint256 result;
        uint256 memPtr = item.memPtr + 1;
        assembly {
            result := mload(memPtr)
        }

        return result;
    }

    function toBytes(RLPItem memory item) internal pure returns (bytes memory) {
        require(item.len > 0);

        (uint256 memPtr, uint256 len) = payloadLocation(item);
        bytes memory result = new bytes(len);

        uint256 destPtr;
        assembly {
            destPtr := add(0x20, result)
        }

        copy(memPtr, destPtr, len);
        return result;
    }

    /*
     * Private Helpers
     */

    // @return number of payload items inside an encoded list.
    function numItems(RLPItem memory item) private pure returns (uint256) {
        if (item.len == 0) return 0;

        uint256 count = 0;
        uint256 currPtr = item.memPtr + _payloadOffset(item.memPtr);
        uint256 endPtr = item.memPtr + item.len;
        while (currPtr < endPtr) {
            currPtr = currPtr + _itemLength(currPtr); // skip over an item
            count++;
        }

        return count;
    }

    // @return entire rlp item byte length
    function _itemLength(uint256 memPtr) private pure returns (uint256) {
        uint256 itemLen;
        uint256 byte0;
        assembly {
            byte0 := byte(0, mload(memPtr))
        }

        if (byte0 < STRING_SHORT_START) {
            itemLen = 1;
        } else if (byte0 < STRING_LONG_START) {
            itemLen = byte0 - STRING_SHORT_START + 1;
        } else if (byte0 < LIST_SHORT_START) {
            assembly {
                let byteLen := sub(byte0, 0xb7) // # of bytes the actual length is
                memPtr := add(memPtr, 1) // skip over the first byte

                /* 32 byte word size */
                let dataLen := div(mload(memPtr), exp(256, sub(32, byteLen))) // right shifting to get the len
                itemLen := add(dataLen, add(byteLen, 1))
            }
        } else if (byte0 < LIST_LONG_START) {
            itemLen = byte0 - LIST_SHORT_START + 1;
        } else {
            assembly {
                let byteLen := sub(byte0, 0xf7)
                memPtr := add(memPtr, 1)

                let dataLen := div(mload(memPtr), exp(256, sub(32, byteLen))) // right shifting to the correct length
                itemLen := add(dataLen, add(byteLen, 1))
            }
        }

        return itemLen;
    }

    // @return number of bytes until the data
    function _payloadOffset(uint256 memPtr) private pure returns (uint256) {
        uint256 byte0;
        assembly {
            byte0 := byte(0, mload(memPtr))
        }

        if (byte0 < STRING_SHORT_START) {
            return 0;
        } else if (byte0 < STRING_LONG_START || (byte0 >= LIST_SHORT_START && byte0 < LIST_LONG_START)) {
            return 1;
        } else if (byte0 < LIST_SHORT_START) {
            // being explicit
            return byte0 - (STRING_LONG_START - 1) + 1;
        } else {
            return byte0 - (LIST_LONG_START - 1) + 1;
        }
    }

    /*
     * @param src Pointer to source
     * @param dest Pointer to destination
     * @param len Amount of memory to copy from the source
     */
    function copy(uint256 src, uint256 dest, uint256 len) private pure {
        if (len == 0) return;

        // copy as many word sizes as possible
        for (; len >= WORD_SIZE; len -= WORD_SIZE) {
            assembly {
                mstore(dest, mload(src))
            }

            src += WORD_SIZE;
            dest += WORD_SIZE;
        }

        if (len > 0) {
            // left over bytes. Mask is used to remove unwanted bytes from the word
            uint256 mask = 256**(WORD_SIZE - len) - 1;
            assembly {
                let srcpart := and(mload(src), not(mask)) // zero out src
                let destpart := and(mload(dest), mask) // retrieve the bytes
                mstore(dest, or(destpart, srcpart))
            }
        }
    }
}

// packages/evm/contracts/interfaces/IAdapter.sol

/**
 * @title IAdapter
 */
interface IAdapter {
    error ConflictingBlockHeader(uint256 blockNumber, bytes32 blockHash, bytes32 storedBlockHash);
    error InvalidBlockHeaderRLP();

    /**
     * @dev Emitted when a hash is stored.
     * @param id - The ID of the stored hash.
     * @param hash - The stored hash as bytes32 values.
     */
    event HashStored(uint256 indexed id, bytes32 indexed hash);

    /**
     * @dev Returns the hash for a given ID.
     * @param domain - Identifier for the domain to query.
     * @param id - Identifier for the ID to query.
     * @return hash Bytes32 hash for the given ID on the given domain.
     * @notice MUST return bytes32(0) if the hash is not present.
     */
    function getHash(uint256 domain, uint256 id) external view returns (bytes32 hash);
}

// packages/evm/contracts/interfaces/IHashiProver.sol

/**
 * @title IHashiProver
 */
interface IHashiProver {
    struct AccountAndStorageProof {
        uint256 chainId;
        uint256 blockNumber;
        bytes blockHeader;
        uint256 ancestralBlockNumber;
        bytes[] ancestralBlockHeaders;
        address account;
        bytes[] accountProof;
        bytes32 storageHash;
        bytes32[] storageKeys;
        bytes[][] storageProof;
    }

    struct ReceiptProof {
        uint256 chainId;
        uint256 blockNumber;
        bytes blockHeader;
        uint256 ancestralBlockNumber;
        bytes[] ancestralBlockHeaders;
        bytes[] receiptProof;
        bytes transactionIndex;
        uint256 logIndex;
    }

    error AncestralBlockHeadersLengthReached();
    error BlockHeaderNotFound();
    error ConflictingBlockHeader(uint256 blockNumber, bytes32 ancestralBlockHeaderHash, bytes32 blockHeaderHash);
    error InvalidAccount();
    error InvalidBlockHeader();
    error InvalidBlockHeaderLength();
    error InvalidLogIndex();
    error InvalidReceipt();
    error InvalidReceiptProof();
    error InvalidStorageHash();
    error InvalidStorageProofParams();
    error UnsupportedTxType();
}

// node_modules/@eth-optimism/contracts-bedrock/src/libraries/rlp/RLPReader.sol

/// @custom:attribution https://github.com/hamdiallam/Solidity-RLP
/// @title RLPReader
/// @notice RLPReader is a library for parsing RLP-encoded byte arrays into Solidity types. Adapted
///         from Solidity-RLP (https://github.com/hamdiallam/Solidity-RLP) by Hamdi Allam with
///         various tweaks to improve readability.
library RLPReader_1 {
    /// @notice Custom pointer type to avoid confusion between pointers and uint256s.
    type MemoryPointer is uint256;

    /// @notice RLP item types.
    /// @custom:value DATA_ITEM Represents an RLP data item (NOT a list).
    /// @custom:value LIST_ITEM Represents an RLP list item.
    enum RLPItemType {
        DATA_ITEM,
        LIST_ITEM
    }

    /// @notice Struct representing an RLP item.
    /// @custom:field length Length of the RLP item.
    /// @custom:field ptr    Pointer to the RLP item in memory.
    struct RLPItem {
        uint256 length;
        MemoryPointer ptr;
    }

    /// @notice Max list length that this library will accept.
    uint256 internal constant MAX_LIST_LENGTH = 32;

    /// @notice Converts bytes to a reference to memory position and length.
    /// @param _in Input bytes to convert.
    /// @return out_ Output memory reference.
    function toRLPItem(bytes memory _in) internal pure returns (RLPItem memory out_) {
        // Empty arrays are not RLP items.
        if (_in.length == 0) revert EmptyItem();

        MemoryPointer ptr;
        assembly {
            ptr := add(_in, 32)
        }

        out_ = RLPItem({ length: _in.length, ptr: ptr });
    }

    /// @notice Reads an RLP list value into a list of RLP items.
    /// @param _in RLP list value.
    /// @return out_ Decoded RLP list items.
    function readList(RLPItem memory _in) internal pure returns (RLPItem[] memory out_) {
        (uint256 listOffset, uint256 listLength, RLPItemType itemType) = _decodeLength(_in);

        if (itemType != RLPItemType.LIST_ITEM) revert UnexpectedString();

        if (listOffset + listLength != _in.length) revert InvalidDataRemainder();

        // Solidity in-memory arrays can't be increased in size, but *can* be decreased in size by
        // writing to the length. Since we can't know the number of RLP items without looping over
        // the entire input, we'd have to loop twice to accurately size this array. It's easier to
        // simply set a reasonable maximum list length and decrease the size before we finish.
        out_ = new RLPItem[](MAX_LIST_LENGTH);

        uint256 itemCount = 0;
        uint256 offset = listOffset;
        while (offset < _in.length) {
            (uint256 itemOffset, uint256 itemLength,) = _decodeLength(
                RLPItem({ length: _in.length - offset, ptr: MemoryPointer.wrap(MemoryPointer.unwrap(_in.ptr) + offset) })
            );

            // We don't need to check itemCount < out.length explicitly because Solidity already
            // handles this check on our behalf, we'd just be wasting gas.
            out_[itemCount] = RLPItem({
                length: itemLength + itemOffset,
                ptr: MemoryPointer.wrap(MemoryPointer.unwrap(_in.ptr) + offset)
            });

            itemCount += 1;
            offset += itemOffset + itemLength;
        }

        // Decrease the array size to match the actual item count.
        assembly {
            mstore(out_, itemCount)
        }
    }

    /// @notice Reads an RLP list value into a list of RLP items.
    /// @param _in RLP list value.
    /// @return out_ Decoded RLP list items.
    function readList(bytes memory _in) internal pure returns (RLPItem[] memory out_) {
        out_ = readList(toRLPItem(_in));
    }

    /// @notice Reads an RLP bytes value into bytes.
    /// @param _in RLP bytes value.
    /// @return out_ Decoded bytes.
    function readBytes(RLPItem memory _in) internal pure returns (bytes memory out_) {
        (uint256 itemOffset, uint256 itemLength, RLPItemType itemType) = _decodeLength(_in);

        if (itemType != RLPItemType.DATA_ITEM) revert UnexpectedList();

        if (_in.length != itemOffset + itemLength) revert InvalidDataRemainder();

        out_ = _copy(_in.ptr, itemOffset, itemLength);
    }

    /// @notice Reads an RLP bytes value into bytes.
    /// @param _in RLP bytes value.
    /// @return out_ Decoded bytes.
    function readBytes(bytes memory _in) internal pure returns (bytes memory out_) {
        out_ = readBytes(toRLPItem(_in));
    }

    /// @notice Reads the raw bytes of an RLP item.
    /// @param _in RLP item to read.
    /// @return out_ Raw RLP bytes.
    function readRawBytes(RLPItem memory _in) internal pure returns (bytes memory out_) {
        out_ = _copy(_in.ptr, 0, _in.length);
    }

    /// @notice Decodes the length of an RLP item.
    /// @param _in RLP item to decode.
    /// @return offset_ Offset of the encoded data.
    /// @return length_ Length of the encoded data.
    /// @return type_ RLP item type (LIST_ITEM or DATA_ITEM).
    function _decodeLength(RLPItem memory _in)
        private
        pure
        returns (uint256 offset_, uint256 length_, RLPItemType type_)
    {
        // Short-circuit if there's nothing to decode, note that we perform this check when
        // the user creates an RLP item via toRLPItem, but it's always possible for them to bypass
        // that function and create an RLP item directly. So we need to check this anyway.
        if (_in.length == 0) revert EmptyItem();

        MemoryPointer ptr = _in.ptr;
        uint256 prefix;
        assembly {
            prefix := byte(0, mload(ptr))
        }

        if (prefix <= 0x7f) {
            // Single byte.
            return (0, 1, RLPItemType.DATA_ITEM);
        } else if (prefix <= 0xb7) {
            // Short string.

            // slither-disable-next-line variable-scope
            uint256 strLen = prefix - 0x80;

            if (_in.length <= strLen) revert ContentLengthMismatch();

            bytes1 firstByteOfContent;
            assembly {
                firstByteOfContent := and(mload(add(ptr, 1)), shl(248, 0xff))
            }

            if (strLen == 1 && firstByteOfContent < 0x80) revert InvalidHeader();

            return (1, strLen, RLPItemType.DATA_ITEM);
        } else if (prefix <= 0xbf) {
            // Long string.
            uint256 lenOfStrLen = prefix - 0xb7;

            if (_in.length <= lenOfStrLen) revert ContentLengthMismatch();

            bytes1 firstByteOfContent;
            assembly {
                firstByteOfContent := and(mload(add(ptr, 1)), shl(248, 0xff))
            }

            if (firstByteOfContent == 0x00) revert InvalidHeader();

            uint256 strLen;
            assembly {
                strLen := shr(sub(256, mul(8, lenOfStrLen)), mload(add(ptr, 1)))
            }

            if (strLen <= 55) revert InvalidHeader();

            if (_in.length <= lenOfStrLen + strLen) revert ContentLengthMismatch();

            return (1 + lenOfStrLen, strLen, RLPItemType.DATA_ITEM);
        } else if (prefix <= 0xf7) {
            // Short list.
            // slither-disable-next-line variable-scope
            uint256 listLen = prefix - 0xc0;

            if (_in.length <= listLen) revert ContentLengthMismatch();

            return (1, listLen, RLPItemType.LIST_ITEM);
        } else {
            // Long list.
            uint256 lenOfListLen = prefix - 0xf7;

            if (_in.length <= lenOfListLen) revert ContentLengthMismatch();

            bytes1 firstByteOfContent;
            assembly {
                firstByteOfContent := and(mload(add(ptr, 1)), shl(248, 0xff))
            }

            if (firstByteOfContent == 0x00) revert InvalidHeader();

            uint256 listLen;
            assembly {
                listLen := shr(sub(256, mul(8, lenOfListLen)), mload(add(ptr, 1)))
            }

            if (listLen <= 55) revert InvalidHeader();

            if (_in.length <= lenOfListLen + listLen) revert ContentLengthMismatch();

            return (1 + lenOfListLen, listLen, RLPItemType.LIST_ITEM);
        }
    }

    /// @notice Copies the bytes from a memory location.
    /// @param _src    Pointer to the location to read from.
    /// @param _offset Offset to start reading from.
    /// @param _length Number of bytes to read.
    /// @return out_ Copied bytes.
    function _copy(MemoryPointer _src, uint256 _offset, uint256 _length) private pure returns (bytes memory out_) {
        out_ = new bytes(_length);
        if (_length == 0) {
            return out_;
        }

        // Mostly based on Solidity's copy_memory_to_memory:
        // https://github.com/ethereum/solidity/blob/34dd30d71b4da730488be72ff6af7083cf2a91f6/libsolidity/codegen/YulUtilFunctions.cpp#L102-L114
        uint256 src = MemoryPointer.unwrap(_src) + _offset;
        assembly {
            let dest := add(out_, 32)
            let i := 0
            for { } lt(i, _length) { i := add(i, 32) } { mstore(add(dest, i), mload(add(src, i))) }

            if gt(i, _length) { mstore(add(dest, _length), 0) }
        }
    }
}

// packages/evm/contracts/interfaces/IHashi.sol

/**
 * @title IHashi
 */
interface IHashi {
    error AdaptersDisagree(IAdapter adapterOne, IAdapter adapterTwo);
    error HashNotAvailableInAdapter(IAdapter adapter);
    error InvalidThreshold(uint256 threshold, uint256 maxThreshold);
    error NoAdaptersGiven();

    /**
     * @dev Checks whether the threshold is reached for a message given a set of adapters.
     * @param domain - ID of the domain to query.
     * @param id - ID for which to return hash.
     * @param threshold - Threshold to use.
     * @param adapters - Array of addresses for the adapters to query.
     * @notice If the threshold is 1, it will always return true.
     * @return result A boolean indicating if a threshold for a given message has been reached.
     */
    function checkHashWithThresholdFromAdapters(
        uint256 domain,
        uint256 id,
        uint256 threshold,
        IAdapter[] calldata adapters
    ) external view returns (bool);

    /**
     * @dev Returns the hash stored by a given adapter for a given ID.
     * @param domain - ID of the domain to query.
     * @param id - ID for which to return a hash.
     * @param adapter - Address of the adapter to query.
     * @return hash stored by the given adapter for the given ID.
     */
    function getHashFromAdapter(uint256 domain, uint256 id, IAdapter adapter) external view returns (bytes32);

    /**
     * @dev Returns the hashes for a given ID stored by a given set of adapters.
     * @param domain - The ID of the domain to query.
     * @param id - The ID for which to return hashes.
     * @param adapters - An array of addresses for the adapters to query.
     * @return hashes An array of hashes stored by the given adapters for the specified ID.
     */
    function getHashesFromAdapters(
        uint256 domain,
        uint256 id,
        IAdapter[] calldata adapters
    ) external view returns (bytes32[] memory);

    /**
     * @dev Returns the hash unanimously agreed upon by a given set of adapters.
     * @param domain - The ID of the domain to query.
     * @param id - The ID for which to return a hash.
     * @param adapters - An array of addresses for the adapters to query.
     * @return hash agreed on by the given set of adapters.
     * @notice MUST revert if adapters disagree on the hash or if an adapter does not report.
     */
    function getHash(uint256 domain, uint256 id, IAdapter[] calldata adapters) external view returns (bytes32);
}

// packages/evm/contracts/interfaces/IShuSho.sol

/**
 * @title IShuSho
 */
interface IShuSho {
    struct Domain {
        uint256 threshold;
        uint256 count;
    }

    struct Link {
        IAdapter previous;
        IAdapter next;
    }

    error AdapterNotEnabled(IAdapter adapter);
    error AdapterAlreadyEnabled(IAdapter adapter);
    error CountCannotBeZero();
    error DuplicateHashiAddress(IHashi hashi);
    error DuplicateOrOutOfOrderAdapters(IAdapter adapterOne, IAdapter adapterTwo);
    error DuplicateThreshold(uint256 threshold);
    error InvalidAdapter(IAdapter adapter);
    error InvalidThreshold(uint256 threshold);
    error NoAdaptersEnabled(uint256 domain);
    error NoAdaptersGiven();
    error ThresholdNotMet();

    /**
     * @dev Emitted when adapters are disabled for a specific domain.
     * @param domain - The domain associated with the disabled adapters.
     * @param adapters - An array of disabled adapter addresses associated with this event.
     */
    event AdaptersDisabled(uint256 indexed domain, IAdapter[] adapters);

    /**
     * @dev Emitted when adapters are enabled for a specific domain.
     * @param domain - The domain associated with the enabled adapters.
     * @param adapters - An array of enabled adapter addresses associated with this event.
     */
    event AdaptersEnabled(uint256 indexed domain, IAdapter[] adapters);

    /**
     * @dev Emitted when the address of the IHashi contract is set.
     * @param hashi - The address of the IHashi contract associated with this event.
     */
    event HashiSet(IHashi indexed hashi);

    /**
     * @dev Emitted when initialization occurs with the owner's address and the IHashi contract address.
     * @param owner - The address of the owner associated with this event.
     * @param hashi - The address of the IHashi contract associated with this event.
     */
    event Init(address indexed owner, IHashi indexed hashi);

    /**
     * @dev Emitted when the threshold is set for a specific domain.
     * @param domain - The domain associated with the set threshold.
     * @param threshold - The new threshold value associated with this event.
     */
    event ThresholdSet(uint256 domain, uint256 threshold);

    /**
     * @dev Checks the order and validity of adapters for a given domain.
     * @param domain - The Uint256 identifier for the domain.
     * @param _adapters - An array of adapter instances.
     */
    function checkAdapterOrderAndValidity(uint256 domain, IAdapter[] memory _adapters) external view;

    /**
     * @dev Get the previous and the next adapter given a domain and an adapter.
     * @param domain - Uint256 identifier for the domain.
     * @param adapter - IAdapter value for the adapter.
     * @return link - The Link struct containing the previous and the next adapter.
     */
    function getAdapterLink(uint256 domain, IAdapter adapter) external view returns (Link memory);

    /**
     * @dev Returns an array of enabled adapters for a given domain.
     * @param domain - Uint256 identifier for the domain for which to list adapters.
     * @return adapters - The adapters for a given domain.
     */
    function getAdapters(uint256 domain) external view returns (IAdapter[] memory);

    /**
     * @dev Get the current configuration for a given domain.
     * @param domain - Uint256 identifier for the domain.
     * @return domain - The Domain struct containing the current configuration for a given domain.
     */
    function getDomain(uint256 domain) external view returns (Domain memory);

    /**
     * @dev Returns the threshold and count for a given domain.
     * @param domain - Uint256 identifier for the domain.
     * @return threshold - Uint256 adapters threshold for the given domain.
     * @return count - Uint256 adapters count for the given domain.
     * @notice If the threshold for a domain has not been set, or is explicitly set to 0, this function will return a threshold equal to the adapters count for the given domain.
     */
    function getThresholdAndCount(uint256 domain) external view returns (uint256, uint256);

    /**
     * @dev Returns the address of the specified Hashi.
     * @return hashi - The Hashi address.
     */
    function hashi() external view returns (IHashi);
}

// node_modules/@eth-optimism/contracts-bedrock/src/libraries/trie/MerkleTrie.sol

/// @title MerkleTrie
/// @notice MerkleTrie is a small library for verifying standard Ethereum Merkle-Patricia trie
///         inclusion proofs. By default, this library assumes a hexary trie. One can change the
///         trie radix constant to support other trie radixes.
library MerkleTrie {
    /// @notice Struct representing a node in the trie.
    /// @custom:field encoded The RLP-encoded node.
    /// @custom:field decoded The RLP-decoded node.
    struct TrieNode {
        bytes encoded;
        RLPReader_1.RLPItem[] decoded;
    }

    /// @notice Determines the number of elements per branch node.
    uint256 internal constant TREE_RADIX = 16;

    /// @notice Branch nodes have TREE_RADIX elements and one value element.
    uint256 internal constant BRANCH_NODE_LENGTH = TREE_RADIX + 1;

    /// @notice Leaf nodes and extension nodes have two elements, a `path` and a `value`.
    uint256 internal constant LEAF_OR_EXTENSION_NODE_LENGTH = 2;

    /// @notice Prefix for even-nibbled extension node paths.
    uint8 internal constant PREFIX_EXTENSION_EVEN = 0;

    /// @notice Prefix for odd-nibbled extension node paths.
    uint8 internal constant PREFIX_EXTENSION_ODD = 1;

    /// @notice Prefix for even-nibbled leaf node paths.
    uint8 internal constant PREFIX_LEAF_EVEN = 2;

    /// @notice Prefix for odd-nibbled leaf node paths.
    uint8 internal constant PREFIX_LEAF_ODD = 3;

    /// @notice Verifies a proof that a given key/value pair is present in the trie.
    /// @param _key   Key of the node to search for, as a hex string.
    /// @param _value Value of the node to search for, as a hex string.
    /// @param _proof Merkle trie inclusion proof for the desired node. Unlike traditional Merkle
    ///               trees, this proof is executed top-down and consists of a list of RLP-encoded
    ///               nodes that make a path down to the target node.
    /// @param _root  Known root of the Merkle trie. Used to verify that the included proof is
    ///               correctly constructed.
    /// @return valid_ Whether or not the proof is valid.
    function verifyInclusionProof(
        bytes memory _key,
        bytes memory _value,
        bytes[] memory _proof,
        bytes32 _root
    )
        internal
        pure
        returns (bool valid_)
    {
        valid_ = Bytes.equal(_value, get(_key, _proof, _root));
    }

    /// @notice Retrieves the value associated with a given key.
    /// @param _key   Key to search for, as hex bytes.
    /// @param _proof Merkle trie inclusion proof for the key.
    /// @param _root  Known root of the Merkle trie.
    /// @return value_ Value of the key if it exists.
    function get(bytes memory _key, bytes[] memory _proof, bytes32 _root) internal pure returns (bytes memory value_) {
        require(_key.length > 0, "MerkleTrie: empty key");

        TrieNode[] memory proof = _parseProof(_proof);
        bytes memory key = Bytes.toNibbles(_key);
        bytes memory currentNodeID = abi.encodePacked(_root);
        uint256 currentKeyIndex = 0;

        // Proof is top-down, so we start at the first element (root).
        for (uint256 i = 0; i < proof.length; i++) {
            TrieNode memory currentNode = proof[i];

            // Key index should never exceed total key length or we'll be out of bounds.
            require(currentKeyIndex <= key.length, "MerkleTrie: key index exceeds total key length");

            if (currentKeyIndex == 0) {
                // First proof element is always the root node.
                require(
                    Bytes.equal(abi.encodePacked(keccak256(currentNode.encoded)), currentNodeID),
                    "MerkleTrie: invalid root hash"
                );
            } else if (currentNode.encoded.length >= 32) {
                // Nodes 32 bytes or larger are hashed inside branch nodes.
                require(
                    Bytes.equal(abi.encodePacked(keccak256(currentNode.encoded)), currentNodeID),
                    "MerkleTrie: invalid large internal hash"
                );
            } else {
                // Nodes smaller than 32 bytes aren't hashed.
                require(Bytes.equal(currentNode.encoded, currentNodeID), "MerkleTrie: invalid internal node hash");
            }

            if (currentNode.decoded.length == BRANCH_NODE_LENGTH) {
                if (currentKeyIndex == key.length) {
                    // Value is the last element of the decoded list (for branch nodes). There's
                    // some ambiguity in the Merkle trie specification because bytes(0) is a
                    // valid value to place into the trie, but for branch nodes bytes(0) can exist
                    // even when the value wasn't explicitly placed there. Geth treats a value of
                    // bytes(0) as "key does not exist" and so we do the same.
                    value_ = RLPReader_1.readBytes(currentNode.decoded[TREE_RADIX]);
                    require(value_.length > 0, "MerkleTrie: value length must be greater than zero (branch)");

                    // Extra proof elements are not allowed.
                    require(i == proof.length - 1, "MerkleTrie: value node must be last node in proof (branch)");

                    return value_;
                } else {
                    // We're not at the end of the key yet.
                    // Figure out what the next node ID should be and continue.
                    uint8 branchKey = uint8(key[currentKeyIndex]);
                    RLPReader_1.RLPItem memory nextNode = currentNode.decoded[branchKey];
                    currentNodeID = _getNodeID(nextNode);
                    currentKeyIndex += 1;
                }
            } else if (currentNode.decoded.length == LEAF_OR_EXTENSION_NODE_LENGTH) {
                bytes memory path = _getNodePath(currentNode);
                uint8 prefix = uint8(path[0]);
                uint8 offset = 2 - (prefix % 2);
                bytes memory pathRemainder = Bytes.slice(path, offset);
                bytes memory keyRemainder = Bytes.slice(key, currentKeyIndex);
                uint256 sharedNibbleLength = _getSharedNibbleLength(pathRemainder, keyRemainder);

                // Whether this is a leaf node or an extension node, the path remainder MUST be a
                // prefix of the key remainder (or be equal to the key remainder) or the proof is
                // considered invalid.
                require(
                    pathRemainder.length == sharedNibbleLength,
                    "MerkleTrie: path remainder must share all nibbles with key"
                );

                if (prefix == PREFIX_LEAF_EVEN || prefix == PREFIX_LEAF_ODD) {
                    // Prefix of 2 or 3 means this is a leaf node. For the leaf node to be valid,
                    // the key remainder must be exactly equal to the path remainder. We already
                    // did the necessary byte comparison, so it's more efficient here to check that
                    // the key remainder length equals the shared nibble length, which implies
                    // equality with the path remainder (since we already did the same check with
                    // the path remainder and the shared nibble length).
                    require(
                        keyRemainder.length == sharedNibbleLength,
                        "MerkleTrie: key remainder must be identical to path remainder"
                    );

                    // Our Merkle Trie is designed specifically for the purposes of the Ethereum
                    // state trie. Empty values are not allowed in the state trie, so we can safely
                    // say that if the value is empty, the key should not exist and the proof is
                    // invalid.
                    value_ = RLPReader_1.readBytes(currentNode.decoded[1]);
                    require(value_.length > 0, "MerkleTrie: value length must be greater than zero (leaf)");

                    // Extra proof elements are not allowed.
                    require(i == proof.length - 1, "MerkleTrie: value node must be last node in proof (leaf)");

                    return value_;
                } else if (prefix == PREFIX_EXTENSION_EVEN || prefix == PREFIX_EXTENSION_ODD) {
                    // Prefix of 0 or 1 means this is an extension node. We move onto the next node
                    // in the proof and increment the key index by the length of the path remainder
                    // which is equal to the shared nibble length.
                    currentNodeID = _getNodeID(currentNode.decoded[1]);
                    currentKeyIndex += sharedNibbleLength;
                } else {
                    revert("MerkleTrie: received a node with an unknown prefix");
                }
            } else {
                revert("MerkleTrie: received an unparseable node");
            }
        }

        revert("MerkleTrie: ran out of proof elements");
    }

    /// @notice Parses an array of proof elements into a new array that contains both the original
    ///         encoded element and the RLP-decoded element.
    /// @param _proof Array of proof elements to parse.
    /// @return proof_ Proof parsed into easily accessible structs.
    function _parseProof(bytes[] memory _proof) private pure returns (TrieNode[] memory proof_) {
        uint256 length = _proof.length;
        proof_ = new TrieNode[](length);
        for (uint256 i = 0; i < length;) {
            proof_[i] = TrieNode({ encoded: _proof[i], decoded: RLPReader_1.readList(_proof[i]) });
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Picks out the ID for a node. Node ID is referred to as the "hash" within the
    ///         specification, but nodes < 32 bytes are not actually hashed.
    /// @param _node Node to pull an ID for.
    /// @return id_ ID for the node, depending on the size of its contents.
    function _getNodeID(RLPReader_1.RLPItem memory _node) private pure returns (bytes memory id_) {
        id_ = _node.length < 32 ? RLPReader_1.readRawBytes(_node) : RLPReader_1.readBytes(_node);
    }

    /// @notice Gets the path for a leaf or extension node.
    /// @param _node Node to get a path for.
    /// @return nibbles_ Node path, converted to an array of nibbles.
    function _getNodePath(TrieNode memory _node) private pure returns (bytes memory nibbles_) {
        nibbles_ = Bytes.toNibbles(RLPReader_1.readBytes(_node.decoded[0]));
    }

    /// @notice Utility; determines the number of nibbles shared between two nibble arrays.
    /// @param _a First nibble array.
    /// @param _b Second nibble array.
    /// @return shared_ Number of shared nibbles.
    function _getSharedNibbleLength(bytes memory _a, bytes memory _b) private pure returns (uint256 shared_) {
        uint256 max = (_a.length < _b.length) ? _a.length : _b.length;
        for (; shared_ < max && _a[shared_] == _b[shared_];) {
            unchecked {
                ++shared_;
            }
        }
    }
}

// packages/evm/contracts/interfaces/IShoyuBashi.sol

/**
 * @title IShoyuBashi
 */
interface IShoyuBashi is IShuSho {
    /**
     * @dev Disables the given adapters for a given domain.
     * @param domain - Uint256 identifier for the domain for which to set adapters.
     * @param adapters - Array of adapter addresses.
     * @notice Only callable by the owner of this contract.
     * @notice Reverts if adapters are out of order or contain duplicates.
     */
    function disableAdapters(uint256 domain, IAdapter[] memory adapters) external;

    /**
     * @dev Enables the given adapters for a given domain.
     * @param domain - Uint256 identifier for the domain for which to set adapters.
     * @param adapters - Array of adapter addresses.
     * @param threshold - Uint256 threshold to set for the given domain.
     * @notice Only callable by the owner of this contract.
     * @notice Reverts if adapters are out of order, contain duplicates or if the threshold is not higher than half the count of the adapters
     */
    function enableAdapters(uint256 domain, IAdapter[] memory adapters, uint256 threshold) external;

    /**
     * @dev Returns the hash unanimously agreed upon by ALL of the enabled adapters.
     * @param domain - Uint256 identifier for the domain to query.
     * @param id - Uint256 identifier to query.
     * @return Bytes32 hash agreed upon by the adapters for the given domain.
     * @notice Revert if the adapters do not yet have the hash for the given ID.
     * @notice Reverts if adapters disagree.
     * @notice Reverts if no adapters are set for the given domain.
     */
    function getUnanimousHash(uint256 domain, uint256 id) external view returns (bytes32);

    /**
     * @dev Returns the hash agreed upon by a threshold of the enabled adapters.
     * @param domain - Uint256 identifier for the domain to query.
     * @param id - Uint256 identifier to query.
     * @return Bytes32 hash agreed upon by a threshold of the adapters for the given domain.
     * @notice Reverts if the threshold is not reached.
     * @notice Reverts if no adapters are set for the given domain.
     */
    function getThresholdHash(uint256 domain, uint256 id) external view returns (bytes32);

    /**
     * @dev Returns the hash unanimously agreed upon by all of the given adapters.
     * @param domain - Uint256 identifier for the domain to query.
     * @param adapters - Array of adapter addresses to query.
     * @param id - Uint256 identifier to query.
     * @return Bytes32 hash agreed upon by the adapters for the given domain.
     * @notice adapters must be in numerical order from smallest to largest and contain no duplicates.
     * @notice Reverts if adapters are out of order or contain duplicates.
     * @notice Reverts if adapters disagree.
     * @notice Revert if the adapters do not yet have the hash for the given ID.
     * @notice Reverts if no adapters are set for the given domain.
     */
    function getHash(uint256 domain, uint256 id, IAdapter[] memory adapters) external view returns (bytes32);

    /**
     * @dev Sets the threshold of adapters required for a given domain.
     * @param domain - Uint256 identifier for the domain for which to set the threshold.
     * @param threshold - Uint256 threshold to set for the given domain.
     * @notice Only callable by the owner of this contract.
     * @notice Reverts if the threshold is already set to the given value.
     */
    function setThreshold(uint256 domain, uint256 threshold) external;

    /**
     * @dev Sets the address of the IHashi contract.
     * @param hashi - Address of the hashi contract.
     * @notice Only callable by the owner of this contract.
     */
    function setHashi(IHashi hashi) external;
}

// node_modules/@eth-optimism/contracts-bedrock/src/libraries/trie/SecureMerkleTrie.sol

/// @title SecureMerkleTrie
/// @notice SecureMerkleTrie is a thin wrapper around the MerkleTrie library that hashes the input
///         keys. Ethereum's state trie hashes input keys before storing them.
library SecureMerkleTrie {
    /// @notice Verifies a proof that a given key/value pair is present in the Merkle trie.
    /// @param _key   Key of the node to search for, as a hex string.
    /// @param _value Value of the node to search for, as a hex string.
    /// @param _proof Merkle trie inclusion proof for the desired node. Unlike traditional Merkle
    ///               trees, this proof is executed top-down and consists of a list of RLP-encoded
    ///               nodes that make a path down to the target node.
    /// @param _root  Known root of the Merkle trie. Used to verify that the included proof is
    ///               correctly constructed.
    /// @return valid_ Whether or not the proof is valid.
    function verifyInclusionProof(
        bytes memory _key,
        bytes memory _value,
        bytes[] memory _proof,
        bytes32 _root
    )
        internal
        pure
        returns (bool valid_)
    {
        bytes memory key = _getSecureKey(_key);
        valid_ = MerkleTrie.verifyInclusionProof(key, _value, _proof, _root);
    }

    /// @notice Retrieves the value associated with a given key.
    /// @param _key   Key to search for, as hex bytes.
    /// @param _proof Merkle trie inclusion proof for the key.
    /// @param _root  Known root of the Merkle trie.
    /// @return value_ Value of the key if it exists.
    function get(bytes memory _key, bytes[] memory _proof, bytes32 _root) internal pure returns (bytes memory value_) {
        bytes memory key = _getSecureKey(_key);
        value_ = MerkleTrie.get(key, _proof, _root);
    }

    /// @notice Computes the hashed version of the input key.
    /// @param _key Key to hash.
    /// @return hash_ Hashed version of the key.
    function _getSecureKey(bytes memory _key) private pure returns (bytes memory hash_) {
        hash_ = abi.encodePacked(keccak256(_key));
    }
}

// packages/evm/contracts/prover/HashiProver.sol

contract HashiProver is IHashiProver {
    using RLPReader_0 for RLPReader_0.RLPItem;
    using RLPReader_0 for bytes;

    address public immutable SHOYU_BASHI;

    constructor(address shoyuBashi) {
        SHOYU_BASHI = shoyuBashi;
    }

    /**
     * @dev Verifies and retrieves a specific event from a transaction receipt in a foreign blockchain.
     *
     * @param proof A `ReceiptProof` struct containing proof details:
     * - chainId: The chain ID of the foreign blockchain.
     * - blockNumber: If ancestralBlockNumber is 0, then blockNumber represents the block where the transaction occurred and is available in Hashi.
     * - blockHeader: The header of the specified block.
     * - ancestralBlockNumber: If provided, this is the block number where the transaction took place. In this case, blockNumber is the block whose header is accessible in Hashi.
     * - ancestralBlockHeaders: Array of block headers to prove the ancestry of the specified block.
     * - receiptProof: Proof data for locating the receipt in the Merkle Trie.
     * - transactionIndex: Index of the transaction within the block.
     * - logIndex: The specific log index within the transaction receipt.
     *
     * @return bytes The RLP-encoded event corresponding to the specified `logIndex`.
     */
    function verifyForeignEvent(ReceiptProof calldata proof) public view returns (bytes memory) {
        bytes memory blockHeader = _checkBlockHeaderAgainstHashi(
            proof.chainId,
            proof.blockNumber,
            proof.blockHeader,
            proof.ancestralBlockNumber,
            proof.ancestralBlockHeaders
        );
        RLPReader_0.RLPItem[] memory blockHeaderFields = blockHeader.toRlpItem().toList();
        bytes32 receiptsRoot = bytes32(blockHeaderFields[5].toUint());

        bytes memory value = MerkleTrie.get(proof.transactionIndex, proof.receiptProof, receiptsRoot);
        RLPReader_0.RLPItem[] memory receiptFields = _extractReceiptFields(value);
        if (receiptFields.length != 4) revert InvalidReceipt();

        RLPReader_0.RLPItem[] memory logs = receiptFields[3].toList();
        if (proof.logIndex >= logs.length) revert InvalidLogIndex();
        return logs[proof.logIndex].toRlpBytes();
    }

    /**
     * @dev Verifies foreign storage data for a specified account on a foreign blockchain.
     *
     * @param proof An `AccountAndStorageProof` struct containing proof details:
     * - chainId: The chain ID of the foreign blockchain.
     * - blockNumber: If ancestralBlockNumber is 0, then blockNumber represents the block where the transaction occurred and is available in Hashi.
     * - blockHeader: The header of the specified block.
     * - ancestralBlockNumber: If provided, this is the block number where the transaction took place. In this case, blockNumber is the block whose header is accessible in Hashi.
     * - ancestralBlockHeaders: Array of block headers proving ancestry of the specified block.
     * - account: The account address whose storage is being verified.
     * - accountProof: Proof data for locating the account in the state trie.
     * - storageHash: Expected hash of the storage root for the account.
     * - storageKeys: Array of storage keys for which data is being verified.
     * - storageProof: Proof data for locating the storage values in the storage trie.
     *
     * @return bytes[] An array of storage values corresponding to the specified `storageKeys`.
     */
    function verifyForeignStorage(AccountAndStorageProof calldata proof) public view returns (bytes[] memory) {
        bytes memory blockHeader = _checkBlockHeaderAgainstHashi(
            proof.chainId,
            proof.blockNumber,
            proof.blockHeader,
            proof.ancestralBlockNumber,
            proof.ancestralBlockHeaders
        );
        RLPReader_0.RLPItem[] memory blockHeaderFields = blockHeader.toRlpItem().toList();
        bytes32 stateRoot = bytes32(blockHeaderFields[3].toUint());
        (, , bytes32 expectedStorageHash, ) = _verifyAccountProof(proof.account, stateRoot, proof.accountProof);
        if (proof.storageHash != expectedStorageHash) revert InvalidStorageHash();
        return _verifyStorageProof(proof.storageHash, proof.storageKeys, proof.storageProof);
    }

    function _checkBlockHeaderAgainstHashi(
        uint256 chainId,
        uint256 blockNumber,
        bytes memory blockHeader,
        uint256 ancestralBlockNumber,
        bytes[] memory ancestralBlockHeaders
    ) private view returns (bytes memory) {
        bytes32 blockHeaderHash = keccak256(blockHeader);
        bytes32 currentBlockHeaderHash = IShoyuBashi(SHOYU_BASHI).getThresholdHash(chainId, blockNumber);
        if (currentBlockHeaderHash == blockHeaderHash && ancestralBlockHeaders.length == 0) return blockHeader;

        for (uint256 i = 0; i < ancestralBlockHeaders.length; i++) {
            RLPReader_0.RLPItem memory ancestralBlockHeaderRLP = RLPReader_0.toRlpItem(ancestralBlockHeaders[i]);
            RLPReader_0.RLPItem[] memory ancestralBlockHeaderContent = ancestralBlockHeaderRLP.toList();

            bytes32 blockParentHash = bytes32(ancestralBlockHeaderContent[0].toUint());
            uint256 currentAncestralBlockNumber = uint256(ancestralBlockHeaderContent[8].toUint());

            bytes32 ancestralBlockHeaderHash = keccak256(ancestralBlockHeaders[i]);
            if (ancestralBlockHeaderHash != currentBlockHeaderHash)
                revert ConflictingBlockHeader(
                    currentAncestralBlockNumber,
                    ancestralBlockHeaderHash,
                    currentBlockHeaderHash
                );

            if (ancestralBlockNumber == currentAncestralBlockNumber) {
                return ancestralBlockHeaders[i];
            } else {
                currentBlockHeaderHash = blockParentHash;
            }
        }

        revert BlockHeaderNotFound();
    }

    function _extractReceiptFields(bytes memory value) private pure returns (RLPReader_0.RLPItem[] memory) {
        uint256 offset;
        if (value[0] == 0x01 || value[0] == 0x02 || value[0] == 0x03 || value[0] == 0x7e) {
            offset = 1;
        } else if (value[0] >= 0xc0) {
            offset = 0;
        } else {
            revert UnsupportedTxType();
        }

        uint256 memPtr;
        assembly {
            memPtr := add(value, add(0x20, mul(0x01, offset)))
        }

        return RLPReader_0.RLPItem(value.length - offset, memPtr).toList();
    }

    function _verifyAccountProof(
        address account,
        bytes32 stateRoot,
        bytes[] memory proof
    ) private pure returns (uint256, uint256, bytes32, bytes32) {
        bytes memory accountRlp = SecureMerkleTrie.get(abi.encodePacked(account), proof, stateRoot);

        bytes32 accountStorageRoot = bytes32(accountRlp.toRlpItem().toList()[2].toUint());
        if (accountStorageRoot.length == 0) revert InvalidStorageHash();
        RLPReader_0.RLPItem[] memory accountFields = accountRlp.toRlpItem().toList();
        if (accountFields.length != 4) revert InvalidAccount();
        // [nonce, balance, storageHash, codeHash]
        return (
            accountFields[0].toUint(),
            accountFields[1].toUint(),
            bytes32(accountFields[2].toUint()),
            bytes32(accountFields[3].toUint())
        );
    }

    function _verifyStorageProof(
        bytes32 storageHash,
        bytes32[] memory storageKeys,
        bytes[][] memory proof
    ) private pure returns (bytes[] memory) {
        bytes[] memory results = new bytes[](proof.length);
        if (storageKeys.length == 0 || proof.length == 0 || storageKeys.length != proof.length)
            revert InvalidStorageProofParams();
        for (uint256 i = 0; i < proof.length; ) {
            RLPReader_0.RLPItem memory item = RLPReader_0.toRlpItem(
                SecureMerkleTrie.get(abi.encode(storageKeys[i]), proof[i], storageHash)
            );
            results[i] = item.toBytes();
            unchecked {
                ++i;
            }
        }
        return results;
    }
}
