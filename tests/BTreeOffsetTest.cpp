#include "ApfsLib/ApfsContainer.h"
#include "ApfsLib/BTree.h"
#include <cstring>
#include <cstdlib>
#include <iostream>

static void require(bool ok, const char *message) {
    if (!ok) { std::cerr << message << std::endl; std::exit(1); }
}

int main() {
    ApfsContainer container(nullptr, 0, 0);
    BTree tree(container);
    // Exercise root/non-root and fixed/variable layouts at both block sizes.
    for (size_t size : {size_t(4096), size_t(65536)}) {
        for (bool root : {false, true}) {
            for (bool fixed : {false, true}) {
                std::vector<uint8_t> block(size, 0);
                auto *header = reinterpret_cast<btree_node_phys_t *>(block.data());
                header->btn_flags = (root ? BTNODE_ROOT : 0) | (fixed ? BTNODE_FIXED_KV_SIZE : BTNODE_LEAF);
                header->btn_level = fixed ? 1 : 0;
                header->btn_nkeys = 1;
                const size_t table = fixed ? sizeof(kvoff_t) : sizeof(kvloc_t);
                header->btn_table_space.len = table;
                const size_t key_start = sizeof(btree_node_phys_t) + table;
                const size_t value_start = size - (root ? sizeof(btree_info_t) : 0) - 8;
                if (fixed) {
                    auto *entry = reinterpret_cast<kvoff_t *>(header->btn_data);
                    entry->k = 0; entry->v = 8;
                } else {
                    auto *entry = reinterpret_cast<kvloc_t *>(header->btn_data);
                    entry->k.off = 0; entry->k.len = 8;
                    entry->v.off = 8; entry->v.len = 8;
                }
                const uint64_t key = 1028, value = 79;
                std::memcpy(block.data() + key_start, &key, 8);
                std::memcpy(block.data() + value_start, &value, 8);
                auto node = BTreeNode::CreateNode(tree, block.data(), size, 1, {}, 0);
                BTreeEntry entry;
                require(node->GetEntry(entry, 0), "entry missing");
                require(entry.key == node->block().data() + key_start, "wrong key address");
                // Check pointer before dereferencing: the old uint16_t code fails here.
                require(entry.val == node->block().data() + value_start, "wrong value address (64KiB overflow)");
                uint64_t actual = 0;
                std::memcpy(&actual, entry.val, sizeof(actual));
                require(actual == value, "wrong value content");
                require(!node->GetEntry(entry, 1), "out-of-range entry accepted");
            }
        }
    }
    BTreeIterator it;
    uint64_t key = 2;
    require(!tree.GetIteratorBegin(it), "uninitialized tree accepted");
    require(!tree.GetIterator(it, &key, sizeof(key), CompareStdKey, nullptr), "uninitialized search accepted");
    std::cout << "8 node layouts and empty-tree checks passed" << std::endl;
}
