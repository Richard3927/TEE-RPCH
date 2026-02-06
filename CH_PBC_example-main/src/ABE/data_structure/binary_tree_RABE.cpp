#include <ABE/data_structure/binary_tree_RABE.h>

binary_tree_node_RABE::binary_tree_node_RABE(binary_tree_node_RABE::node_type type, element_t *_G, element_t *_Zn){
    this->type = type;
    element_init_same_as(gtheta, *_G);
    element_init_same_as(id, *_Zn);
    parent = NULL;
    left_child = NULL;
    right_child = NULL;
}

binary_tree_node_RABE* binary_tree_node_RABE::getLeftChild(){
    return left_child;
}

void binary_tree_node_RABE::setLeftChild(binary_tree_node_RABE *left_child){
    this->left_child = left_child;
}

binary_tree_node_RABE* binary_tree_node_RABE::getRightChild(){
    return right_child;
}

void binary_tree_node_RABE::setRightChild(binary_tree_node_RABE *right_child){
    this->right_child = right_child;
}

bool binary_tree_node_RABE::isEmpty(){
    if(type == binary_tree_node_RABE::LEAF){
        if(element_is0(id)){
            return true;
        }else{
            return false;
        }
    }else if(type == binary_tree_node_RABE::INTERNAL){
        if(element_is0(gtheta)){
            return true;
        }else{
            return false;
        }
    }
}

void binary_tree_node_RABE::setParent(binary_tree_node_RABE *parent)
{
    this->parent = parent;
}

binary_tree_node_RABE::node_type binary_tree_node_RABE::getType(){
    return type;
}

void binary_tree_node_RABE::setType(binary_tree_node_RABE::node_type type){
    this->type = type;
}

binary_tree_node_RABE* binary_tree_node_RABE::getParent(){
    return parent;
}

element_t *binary_tree_node_RABE::getGtheta(){
    return &gtheta;
}

void binary_tree_node_RABE::setGtheta(element_t *gtheta)
{
    element_set(this->gtheta, *gtheta);
}
element_t *binary_tree_node_RABE::getId()
{
    return &id;
}

void binary_tree_node_RABE::setId(element_t *id)
{
    element_set(this->id, *id);
}

time_t binary_tree_node_RABE::getTime(){
    return time;
}

void binary_tree_node_RABE::setTime(time_t time)
{
    this->time = time;
}

void ConstructTree(int curDepth, int totalDepth, binary_tree_node_RABE *node, binary_tree_node_RABE *parent_node, element_t *_G, element_t *_Zn){
    if(parent_node != nullptr){
        node->setParent(parent_node);
    }

    if(curDepth == totalDepth){
        // leaf node
        node->setType(binary_tree_node_RABE::LEAF);
        return;
    }
    // internal node
    binary_tree_node_RABE *left = new binary_tree_node_RABE(binary_tree_node_RABE::INTERNAL, _G, _Zn);
    node->setLeftChild(left);
    ConstructTree(curDepth+1, totalDepth, left, node, _G, _Zn);
    binary_tree_node_RABE *right = new binary_tree_node_RABE(binary_tree_node_RABE::INTERNAL, _G, _Zn);
    node->setRightChild(right);
    ConstructTree(curDepth+1, totalDepth, right, node, _G, _Zn);
}

binary_tree_RABE::binary_tree_RABE(int n, element_t *_G, element_t *_Zn){
    // 构造一个有n个叶子节点的二叉树
    if((n & (n-1)) != 0){
        throw invalid_argument("n is not a power of 2");
        return;
    }
    if(n < 2){
        throw invalid_argument("n is less than 2");
        return;
    }
    int totalDepth = log2(n) + 1;
    this->root = new binary_tree_node_RABE(binary_tree_node_RABE::INTERNAL, _G, _Zn);
    ConstructTree(1, totalDepth, this->root, nullptr, _G, _Zn);
}


void PrintTree(binary_tree_node_RABE* node, int depth = 0) {
    if (node == nullptr) {
        return;
    }

    // Print node information
    if (node->getType() == binary_tree_node_RABE::INTERNAL) {
        printf("I");
        // PrintElement("",*node->getGtheta());
    }else if(node->getType() == binary_tree_node_RABE::LEAF){
        printf("L");
    }
    PrintTree(node->getLeftChild(), depth + 1);
    PrintTree(node->getRightChild(), depth + 1);
}

void binary_tree_RABE::printTree(){
    printf("print tree\n");
    PrintTree(this->root);
    printf("\nend of tree\n");
}

binary_tree_node_RABE* binary_tree_RABE::setLeafNode(element_t *id, time_t time){
    // find the first leaf node that is not set
    binary_tree_node_RABE *res = nullptr;
    queue<binary_tree_node_RABE *> q;
    q.push(this->root);
    while(!q.empty()){
        binary_tree_node_RABE *node = q.front();
        if(node->getType() == binary_tree_node_RABE::LEAF && node->isEmpty()){
            res = node;
            break;
        }
        q.pop();
        if(node->getType() == binary_tree_node_RABE::INTERNAL){
            q.push(node->getLeftChild());
            q.push(node->getRightChild());
        }
    }
    if(res != nullptr){
        res->setId(id);
        res->setTime(time);
    }
    return res;
}
vector<binary_tree_node_RABE *> binary_tree_RABE::KUNodes(vector<element_t *> rl_ids, time_t t)
{
    vector<binary_tree_node_RABE *> res;
    vector<binary_tree_node_RABE *> rNodes;  // revoked nodes
    vector<binary_tree_node_RABE *> rNodesWithParents;  // revoked nodes with parents
    queue<binary_tree_node_RABE *> q;
    q.push(this->root);
    while(!q.empty()){
        binary_tree_node_RABE *node = q.front();
        if(node->getType() == binary_tree_node_RABE::LEAF && !node->isEmpty()){
            // check if the node is in rl_ids and the time is less than t
            for(int i = 0;i < rl_ids.size();i++){
                if(element_cmp(*node->getId(), *rl_ids[i]) == 0 && node->getTime() < t){
                    rNodes.push_back(node);
                    break;
                }
            }
        }
        q.pop();
        if(node->getType() == binary_tree_node_RABE::INTERNAL){
            q.push(node->getLeftChild());
            q.push(node->getRightChild());
        }
    }

    // find the parents of revoked nodes
    for(int i = 0;i < rNodes.size();i++){
        rNodesWithParents.push_back(rNodes[i]);
        binary_tree_node_RABE *node = rNodes[i]->getParent();
        while(node != nullptr){
            rNodesWithParents.push_back(node);
            node = node->getParent();
        }
    }

    queue<binary_tree_node_RABE *> p;
    p.push(this->root);
    while(!p.empty()){
        binary_tree_node_RABE *node = p.front();
        p.pop();
        // if node not in rNodesWithParents, add it to res
        if(rNodesWithParents.end() == find(rNodesWithParents.begin(), rNodesWithParents.end(), node)){
            res.push_back(node);
            continue;
        }
        if(node->getType() == binary_tree_node_RABE::INTERNAL){
            p.push(node->getLeftChild());
            p.push(node->getRightChild());
        }
    }
    return res;
}