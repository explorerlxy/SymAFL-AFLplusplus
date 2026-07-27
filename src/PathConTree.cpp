#include <z3++.h>
#include <regex>
#include <vector>
#include <queue>
#include <set>
#include <unordered_set>
#include <fstream>
#include <iostream>


extern "C" {
#include "afl-fuzz.h"
#include "types.h"
#include "list.h"
#include "afl-mutations.h"
}

using namespace std;
using namespace z3;

void log_exception(const std::string& message) {
    std::cerr << "Error: " << message << std::endl;  // 打印到控制台
    std::ofstream logfile("error.log", std::ios::app); // 追加写入文件
    if (logfile.is_open()) {
        logfile << "Error: " << message << std::endl;
    }
}

class PathConNode{
public:
    PathConNode(context &c, func_decl_vector &d, expr pc): ctx(c), decls(d), pathCon(pc), left(nullptr), right(nullptr), parent(nullptr), expCnt(0), rCnt(0) {init();}
    PathConNode(context &c, func_decl_vector &d, expr pc, PathConNode *p): ctx(c), decls(d), pathCon(pc), left(nullptr), right(nullptr), parent(p), expCnt(0), rCnt(0) {init();}

    void init(){
        if(parent){
            depth = parent->depth + 1;
        }
        else{
            depth = 0;
        }
        queue<expr> q;
        // Memoize over the shared DAG: without this, the traversal re-visits
        // shared subexpressions once per path and blows up combinatorially on
        // large unsimplified constraints.
        unordered_set<unsigned> visited;
        q.push(pathCon);
        while(!q.empty()){
            expr e = q.front();
            q.pop();
            if(!visited.insert(e.id()).second)
                continue;
            if(e.is_app()){
                for (unsigned i = 0; i < e.num_args(); ++i)
                    q.push(e.arg(i));
            }
            if(e.is_const()){
                // cout<<"const:"<<e<<endl;
                string var = e.to_string();
                if(var.size() >= 2 && var.compare(0, 2, "k!") == 0)
                    symVarSet.insert(stoul(var.substr(2)));
            }
        }
        // Solver construction and assertion of the path condition are
        // deferred to the first check() on this node: most inserted nodes are
        // never queried, and eager construction dominated InsertTrace cost.
    }

    void AddChild(PathConNode *c, bool taken) {
        if(taken){
            left = c;
        }
        else{
            right = c;
        }
    }

    bool IsLeaf() {
        return left == nullptr && right == nullptr;
    }

    const expr &GetPathCon() {
        return pathCon;
    }

    uint32_t GetRChildCnt() {
        return rCnt;
    }

    PathConNode *GetChild(bool taken) {
        if(taken){
            return left;
        }
        else{
            return right;
        }
    }

    PathConNode *GetParent(){
        return parent;
    }

    uint8_t GetExpCnt(){
        return expCnt;
    }

    int32_t GetDepth(){
        return depth;
    }

    const set<uint32_t> &GetSymVarSet(){
        return symVarSet;
    }

    void AddRChildHitCnt(){
        rCnt++;
    }

    void AddExpCnt(){
        expCnt++;
    }

    bool check(const uint8_t* input, uint32_t size){
        if(!solverReady){
            params p(ctx);
            p.set("timeout", (u32)1000);
            checkSolver.set(p);
            checkSolver.add(pathCon);
            solverReady = true;
        }
        checkSolver.push();
        for(auto sv : symVarSet){
            if(sv >= size){
                checkSolver.pop();
                return false;
            }
            checkSolver.add(decls[sv]() == ctx.bv_val(input[sv], 8));
        }
        auto res = checkSolver.check();
        if(res == sat){
            checkSolver.pop();
            return true;
        }
        else if(res == unsat){
            checkSolver.pop();
            return false;
        }
        else{
            log_exception("Solver exception during CheckInput!\n");
            exit(0);
        }
    }

private:
    context &ctx;
    func_decl_vector &decls;
    solver checkSolver = solver(ctx);
    bool solverReady = false;
    expr pathCon;
    PathConNode *left, *right, *parent;
    uint32_t rCnt;
    uint8_t expCnt;                                 // the number of fully explored subtree
    int32_t depth;                                  // the depth of the path constraint
    set<uint32_t> symVarSet;                        // the set of symbolic variables（input byte index） in the path constraint
};


class PathConTree{
public:
    PathConTree(uint32_t idc): initDecCnt(idc) {init();}
    void init(){
        root = nullptr;
        insertPoint = nullptr;
        declPathConCnt.reserve(1024);
        maxInputSize = 0;
        insertDepth = -1;
        pathConCnt = 0;

        if(auto *tmp = getenv("MAX_ALLOWED_RIGHT_CHILD_CNT")){
            try{
                maxRCnt = atoi(tmp);
            }
            catch(...){
                maxRCnt = 128;
            }
        }
        else{
            maxRCnt = 128;
        }

        if(auto *tmp = getenv("MAX_ALLOWED_SOLVER_TIMEOUT")){
            try{
                solverTimeout = atoi(tmp);
            }
            catch(...){
                solverTimeout = 1000;
            }
        }
        else{
            solverTimeout = 1000;
        }

        sorts.push_back(bv8);
        for(uint32_t i = 0; i < initDecCnt; i++){
            // 测试发现int_symbol似乎无法支持增量解析，所以还是使用str_symbol
            // decls.push_back(ctx.function(ctx.int_symbol(i), 0, nullptr, bv8));
            decls.push_back(ctx.function(ctx.str_symbol(("k!" + to_string(i)).c_str()), 0, nullptr, bv8));
            declPathConCnt.push_back(0);
        }
    }

    void SaveStats(afl_state_t *afl){
        std::ofstream file(string((char *)(afl->out_dir)) + "/sym_mode_stats");
        if (file.is_open()) {
            //save information of hybrid fuzzing
            file << "sym_fuzz_per_sec: " << afl->sym_fuzz_per_sec << endl;

            file << "check_input_cnt: " << afl->check_input_cnt << endl;
            if(afl->check_input_tm)
                file << "ci_per_second: " << afl->check_input_cnt / (double)(afl->check_input_tm) * 1000 << endl;
            else
                file << "ci_per_second: " << "~" << endl;

            file << "con_exec_cnt: " << afl->con_exec_cnt << endl;
            if(afl->con_exec_tm)
                file << "ce_per_second: " << afl->con_exec_cnt / (double)(afl->con_exec_tm) * 1000 << endl;
            else
                file << "ce_per_second: " << "~" << endl;

            // PCBT candidate screening statistics (SymAFL-v1 throughput metrics)
            file << "pcbt_candidate_cnt: " << afl->pcbt_candidate_cnt << endl;
            file << "pcbt_admitted_cnt: " << afl->pcbt_admitted_cnt << endl;
            file << "pcbt_rejected_cnt: " << afl->pcbt_rejected_cnt << endl;
            file << "pcbt_exhausted_cnt: " << afl->pcbt_exhausted_cnt << endl;
            if(afl->pcbt_candidate_cnt)
                file << "pcbt_rejection_rate: " << afl->pcbt_rejected_cnt / (double)afl->pcbt_candidate_cnt << endl;
            else
                file << "pcbt_rejection_rate: " << "~" << endl;

            u64 pcbt_wall_tm = 0;
            if(afl->pcbt_first_check_ms && afl->pcbt_last_check_ms > afl->pcbt_first_check_ms)
                pcbt_wall_tm = afl->pcbt_last_check_ms - afl->pcbt_first_check_ms;
            file << "pcbt_wall_tm: " << pcbt_wall_tm << endl;
            if(pcbt_wall_tm)
                file << "pcbt_candidate_per_second: " << afl->pcbt_candidate_cnt / (double)pcbt_wall_tm * 1000 << endl;
            else
                file << "pcbt_candidate_per_second: " << "~" << endl;

            file << "pcbt_concolic_exec_cnt: " << afl->pcbt_concolic_exec_cnt << endl;
            if(afl->pcbt_concolic_exec_tm)
                file << "pcbt_concolic_exec_per_second: " << afl->pcbt_concolic_exec_cnt / (double)(afl->pcbt_concolic_exec_tm) * 1000 << endl;
            else
                file << "pcbt_concolic_exec_per_second: " << "~" << endl;
            file << "pcbt_trace_insert_cnt: " << afl->pcbt_trace_insert_cnt << endl;
            file << "pcbt_no_cov_gain_cnt: " << afl->pcbt_no_cov_gain_cnt << endl;
            file << "pcbt_saturated_branch_cnt: " << afl->pcbt_saturated_branch_cnt << endl;
            file << "pcbt_replay_cnt: " << afl->pcbt_replay_cnt << endl;
            file << "pcbt_replay_mismatch_cnt: " << afl->pcbt_replay_mismatch_cnt << endl;

            // save number of input byte's related path constraints
            file << "max_input_size: " << maxInputSize << endl;
            for(uint32_t i = 0; i < maxInputSize; i++){
                file << declPathConCnt[i] << endl;
            }
            // save size of path con node's symVarSet
            queue<PathConNode*> nodeQueue;
            PathConNode *node = GetRoot();
            PathConNode *child;
            if(node && !node->IsLeaf())
                nodeQueue.push(node);
            while(!nodeQueue.empty()){
                node = nodeQueue.front();
                nodeQueue.pop();
                file << node->GetSymVarSet().size() << endl;
                child = node->GetChild(true);
                if(child && !child->IsLeaf()){
                    nodeQueue.push(child);
                }
                child = node->GetChild(false);
                if(child && !child->IsLeaf()){
                    nodeQueue.push(child);
                }
            }
            file.close();
        }
    }
    int32_t CheckInput(const uint8_t* input, uint32_t size){
        if(root == nullptr)
            return 0;
        if(root->GetExpCnt() == 2){
            return -2;
        }
        if(size > maxInputSize){
            if(size > initDecCnt)
                for(maxInputSize = (maxInputSize > initDecCnt) ? maxInputSize: initDecCnt; maxInputSize < size; maxInputSize++){
                    // decls.push_back(ctx.function(ctx.int_symbol(maxInputSize), 0, nullptr, bv8));
                    decls.push_back(ctx.function(ctx.str_symbol(("k!" + to_string(maxInputSize)).c_str()), 0, nullptr, bv8));
                    declPathConCnt.push_back(0);
                }
            else
                maxInputSize = size;
        }
        PathConNode *node = root;
        while(!node->IsLeaf() && node->GetExpCnt() != 2){
            bool res = node->check(input, size);
            if(res == false){
                if(node->GetChild(false) == nullptr){
                    if(node->GetRChildCnt() < maxRCnt){
                        insertPoint = node;
                        return node->GetDepth() + 1;
                    }
                    else{
                        break;
                    }
                }
                else{
                    node = node->GetChild(false);
                }
            }
            else if(res == true){
                node = node->GetChild(true);
            }
        }
        insertPoint = nullptr;
        return -1;
    }

    void MarkExplored(PathConNode *node){
        PathConNode *p = node;
        p->AddExpCnt();
        while(p->GetExpCnt() == 2){
            p = p->GetParent();
            if(!p)
                break;
            p->AddExpCnt();
        }
    }

    uint8_t NoteNoCoverageGain(){
        if(insertPoint == nullptr)
            return 0;

        PathConNode *node = insertPoint;
        insertPoint = nullptr;
        node->AddRChildHitCnt();
        if(node->GetRChildCnt() < maxRCnt)
            return 0;

        MarkExplored(node);
        return 1;
    }

    // Except the first path con trace, CheckInput() must be called before InsertTrace().
    // int InsertTrace(char const *smtfile){
    int32_t InsertTrace(afl_state_t *afl, const char *smtfile, struct queue_entry *qe){
        (void)qe;  // queue entry no longer tracked per node since focus removal
        expr_vector pathConTrace = ctx.parse_file(smtfile, sorts, decls);
        PathConNode *p;
        // insert first path con trace
        if(root == nullptr){
            // create root node
            if(pathConTrace.size()){
                root = new PathConNode(ctx, decls, pathConTrace[0]);
                pathConCnt++;
                p = root;
            }
            else{
                log_exception("Trying to build a PCT with empty smtfile\n");
                return 0;
            }
        }
        // incremental insertion
        else{
            if(insertPoint == nullptr){
                log_exception("Call CheckInput before InsertTrace\n");
                return 0;
            }
            if(pathConTrace.size()){
                p = new PathConNode(ctx, decls, pathConTrace[0], insertPoint);
                pathConCnt++;
                insertPoint->AddChild(p, false);
                insertPoint = nullptr;
                for(auto symVar : p->GetSymVarSet())
                    declPathConCnt[symVar]++;
            }
            else{
                PathConNode *falseLeaf = new PathConNode(ctx, decls, ctx.bool_val(false));
                insertPoint->AddChild(falseLeaf, false);
                MarkExplored(insertPoint);
                insertPoint = nullptr;
                return 1;
            }
        }
        // cout<<p->GetPathCon()<<endl;
        for (uint32_t i = 1; i < pathConTrace.size(); ++i) {
                PathConNode *newNode = new PathConNode(ctx, decls, pathConTrace[i], p);
                pathConCnt++;
                // cout<<newNode->GetPathCon()<<endl;
                p->AddChild(newNode, true);
                for(auto symVar : p->GetSymVarSet())
                    declPathConCnt[symVar]++;
                p = newNode;
        }
        PathConNode *trueLeaf = new PathConNode(ctx, decls, ctx.bool_val(true));
        p->AddChild(trueLeaf, true);
        p->AddExpCnt();
        return 1;
     }

    PathConNode *GetRoot(){
        return root;
    }

private:
    context ctx;
    z3::sort bv8 = ctx.bv_sort(8);
    // expr_vector &allAssertions;
    sort_vector sorts = sort_vector(ctx);
    func_decl_vector decls = func_decl_vector(ctx);
    vector<uint32_t> declPathConCnt;
    uint32_t initDecCnt, maxInputSize, maxRCnt, solverTimeout, pathConCnt;
    PathConNode *root, *insertPoint;
    int32_t insertDepth;
};


class BinaryTreeVisualizer {
public:
    // 生成DOT文件并渲染图片
    static void visualize(PathConNode* root, const std::string& filename = "dot") {
        std::string dotContent = generateDot(root);
        saveDotFile(dotContent, filename);
        renderImage(filename);
    }

private:

    static string PathConStr(PathConNode *node){
        string res = node->GetPathCon().to_string();
        replace(res.begin(), res.end(), '"', '\'');
        res = res + " " + std::to_string(node->GetRChildCnt());
        return res;
    }
    // 使用队列实现非递归遍历生成DOT
    static string generateDot(PathConNode* root) {
        std::ostringstream dot;
        dot << "digraph BinaryTree {\n";
        dot << "  node [shape=rectangle, style=filled, fillcolor=lightblue];\n";

        if (!root) {
            dot << "}\n";
            return dot.str();
        }

        queue<PathConNode*> nodeQueue;
        nodeQueue.push(root);
        uint32_t unknownCount = 0, maxRCnt;
        if(auto *tmp = getenv("MAX_ALLOWED_RIGHT_CHILD_CNT")){
            try{
                maxRCnt = atoi(tmp);
            }
            catch(...){
                maxRCnt = 128;
            }
        }
        else{
            maxRCnt = 128;
        }

        while (!nodeQueue.empty()) {
            PathConNode* current = nodeQueue.front();
            nodeQueue.pop();


            // 定义当前节点
            dot << "  node" << current
                << " [label=\"" << PathConStr(current) << "\"];\n";

            if(current->GetChild(true) == nullptr && current->GetChild(false) == nullptr)
                continue;

            // 处理左子树
            if (current->GetChild(true)) {
                dot << "  node" << current << " -> node" << current->GetChild(true)
                    << " [label=\"T\"];\n";
                nodeQueue.push(current->GetChild(true));
            } else {
                std::string nullNode = "null" + std::to_string(unknownCount++);
                dot << "  node" << nullNode << " [label=\"Unknown\"];\n";
                dot << "  node" << current << " -> " << "  node" << nullNode
                    << " [label=\"T\", style=dashed];\n";
            }

            // 处理右子树
            if (current->GetChild(false)) {
                dot << "  node" << current << " -> node" << current->GetChild(false)
                    << " [label=\"F\"];\n";
                nodeQueue.push(current->GetChild(false));
            } else {
                std::string nullNode = "null" + std::to_string(unknownCount++);
                if(current->GetRChildCnt() < maxRCnt)
                    dot << "  node" << nullNode << " [label=\"Unknown\"];\n";
                else
                    dot << "  node" << nullNode << " [label=\"Valueless\"];\n";
                dot << "  node" << current << " -> " << "  node" << nullNode
                    << " [label=\"F\", style=dashed];\n";
            }
        }

        dot << "}\n";
        return dot.str();
    }

    // 保存DOT文件
    static void saveDotFile(const std::string& content,
                           const std::string& filename) {
        std::ofstream file(filename + ".dot");
        if (file.is_open()) {
            file << content;
            file.close();
        }
    }

    // 调用系统命令渲染图片
    static void renderImage(const std::string& filename) {
        // Rendering with graphviz costs seconds on large trees and runs on
        // every trace insertion, which stalls the fuzz loop. Keep the .dot
        // output always; render PNGs only when explicitly requested.
        static const bool enabled = getenv("AFL_PCBT_RENDER") != nullptr;
        if (!enabled)
            return;
        std::string command = "dot -Tpng " + filename + ".dot -o "
                            + filename + ".png";
        system(command.c_str());
    }
};

extern "C" {
    PathConTree* path_con_tree_create(uint32_t init_dec_cnt) {
        return new PathConTree(init_dec_cnt);
    }

    void path_con_tree_destroy(afl_state_t *afl) {
        delete afl->path_con_tree;
    }

    int32_t path_con_tree_check_input(afl_state_t *afl, const uint8_t* input, uint32_t size) {
        return afl->path_con_tree->CheckInput(input, size);
    }

    uint8_t path_con_tree_note_no_cov_gain(afl_state_t *afl) {
        return afl->path_con_tree->NoteNoCoverageGain();
    }

    // Except the first path con trace, path_con_tree_check_input() must be called before path_con_tree_insert_trace().
    int32_t path_con_tree_insert_trace(afl_state_t *afl, const char* smtfile, struct queue_entry *qe) {
        try {
            return afl->path_con_tree->InsertTrace(afl, smtfile, qe);
        }
        catch (const std::exception& e) {
            log_exception(e.what());
            exit(-1);
        }
        catch (...) {
            log_exception("Unknown exception occurred when inserting trace!\n");
            exit(-1);
        }
    }

    void visualize_path_con_tree(PathConTree* tree, const char* filename) {
        BinaryTreeVisualizer::visualize(
            tree->GetRoot(),
            filename
        );
    }

    void path_con_tree_save_stats(afl_state_t *afl){
        afl->path_con_tree->SaveStats(afl);
    }
}


// int main() {
//     PathConTree pcTree;
//     pcTree.InsertTrace("solver:000000");
//     BinaryTreeVisualizer::visualize(pcTree.GetRoot(), "advanced_tree");
//     return 0;
// }