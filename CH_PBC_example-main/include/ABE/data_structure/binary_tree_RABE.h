#ifndef ABELIB_BINARY_TREE_RABE_H
#define ABELIB_BINARY_TREE_RABE_H

#include "../basis.h"
#include <utils/func.h>
#include <algorithm>

class binary_tree_node_RABE {
    public:
        enum node_type{ INTERNAL, LEAF };
    private:
        binary_tree_node_RABE::node_type type;
        element_t gtheta;  // gtheta
        // leaf node
        element_t id;
        time_t time;

        binary_tree_node_RABE *parent;
        binary_tree_node_RABE *left_child;
        binary_tree_node_RABE *right_child;
    public:
        binary_tree_node_RABE(binary_tree_node_RABE::node_type type, element_t *_G, element_t *_Zn);

        binary_tree_node_RABE::node_type getType();
        void setType(binary_tree_node_RABE::node_type);
        element_t* getGtheta();
        void setGtheta(element_t *gtheta);
        element_t* getId();
        void setId(element_t *id);
        time_t getTime();
        void setTime(time_t time);
       

        binary_tree_node_RABE* getParent();
        void setParent(binary_tree_node_RABE *parent);
        binary_tree_node_RABE* getLeftChild();
        void setLeftChild(binary_tree_node_RABE *left_child);
        binary_tree_node_RABE* getRightChild();
        void setRightChild(binary_tree_node_RABE *right_child);

        bool isEmpty();
};

class binary_tree_RABE {
    private:
        int n;  // number of leaf nodes
        binary_tree_node_RABE *root;

    public:
        binary_tree_RABE(int n, element_t *_G, element_t *_Zn);

        void printTree();

        binary_tree_node_RABE* setLeafNode(element_t *id, time_t time);

        vector<binary_tree_node_RABE *> KUNodes(vector<element_t *> rl_ids, time_t t);
};


#endif //ABELIB_BINARY_TREE_RABE_H
