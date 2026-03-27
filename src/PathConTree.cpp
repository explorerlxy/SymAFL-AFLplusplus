#include <z3++.h>
#include <unordered_map>
#include <map>
#include <regex>
#include <vector>
#include <queue>
#include <set>
#include <fstream>
#include <iostream>
#include <random>
#include <chrono>


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

uint32_t get_random(uint32_t min, uint32_t max) {
    static std::mt19937 gen(std::random_device{}()); // 保持引擎复用
    return std::uniform_int_distribution<>(min, max)(gen);
}

class PathConNode{
public:
    PathConNode(context &c, func_decl_vector &d, expr pc): ctx(c), decls(d), pathCon(pc), left(nullptr), right(nullptr), parent(nullptr), expCnt(0), rCnt(0), queueEntryListSize(0) {init();}
    PathConNode(context &c, func_decl_vector &d, expr pc, PathConNode *p): ctx(c), decls(d), pathCon(pc), left(nullptr), right(nullptr), parent(p), expCnt(0), rCnt(0), queueEntryListSize(0) {init();}

    void init(){
        if(parent){
            depth = parent->depth + 1;
            focusFuzzed = parent->focusFuzzed;
        }
        else{
            depth = 0;
            focusFuzzed = 0;
        }
        dict.reserve(128);
        queue<expr> q;
        q.push(pathCon);
        while(!q.empty()){ 
            expr e = q.front();
            q.pop();
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
        params p(ctx);
        p.set("timeout", (u32)1000);
        checkSolver.set(p);
        checkSolver.add(pathCon);
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

    uint8_t GetFocusFuzzed(){
        return focusFuzzed;
    }

    struct queue_entry **GetQueueEntryList(){
        return queueEntryList;
    }
    uint32_t GetQueueEntryListSize(){
        return queueEntryListSize;
    }

    const set<uint32_t> &GetSymVarSet(){
        return symVarSet;
    }

    vector<uint8_t> &GetDict(){
        return dict;
    }

    set<PathConNode *> *GetKeyPathConSet(){
        return &keyPathConSet;
    }

    set<uint32_t> *GetKeySymVarSet(){
        return &keySymVarSet;
    }

    void AddRChildHitCnt(){
        rCnt++;
    }

    void AddExpCnt(){
        expCnt++;
    }

    void AddQueueEntry(struct queue_entry *qe){
        queueEntryList[queueEntryListSize++ % 128] = qe; // only reserve the newest 128 queue entries
    }

    void SetFocusFuzzed(){
        focusFuzzed = 1;
    }
    void SetKeyPathConSet(const set<PathConNode *> & kpcs){
        keyPathConSet = kpcs;
    }

    void SetKeySymVarSet(const set<uint32_t> & ksvs){
        keySymVarSet = ksvs;
    }

    bool check(const uint8_t* input, uint32_t size){
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
    expr pathCon;
    PathConNode *left, *right, *parent;
    struct queue_entry *queueEntryList[128];
    uint32_t rCnt, queueEntryListSize;
    uint8_t focusFuzzed;                            // whether the path constraint is solved by focus fuzzing
    uint8_t expCnt;                                 // the number of fully explored subtree
    int32_t depth;                                  // the depth of the path constraint
    set<uint32_t> symVarSet;                        // the set of symbolic variables（input byte index） in the path constraint
    vector<uint8_t> dict;                           // dictionary of symbolic variables
    set<PathConNode *> keyPathConSet;               // the set of key path constraints
    set<uint32_t> keySymVarSet;                          // the set of key symbolic variables
};


class PathConTree{
public:
    PathConTree(uint32_t idc): initDecCnt(idc) {init();}
    void init(){
        focusMode = false;
        root = nullptr;
        insertPoint = nullptr;
        nonNegPathConNode.reserve(8096);
        declPathConCnt.reserve(1024);
        maxInputSize = 0;
        insertDepth = -1;
        targetNode = -1;
        realDictCnt = 0;
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
        
        if(auto *tmp = getenv("MAX_ALLOWED_RIGHT_CHILD_CNT_FOCUS")){
            try{
                maxRCntFocus = atoi(tmp);
            }
            catch(...){
                maxRCntFocus = 128;
            }
        }
        else{
            maxRCntFocus = 128;
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

        if(auto *tmp = getenv("MAX_ALLOWED_DICT_CNT")){
            try{
                maxDictCnt = atoi(tmp);
            }
            catch(...){
                maxDictCnt = 1;
            }
        }
        else{
            maxDictCnt = 1;
        }

        params p(ctx);
        p.set("timeout", solverTimeout);
        focusSolver.set(p);
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
            
            file << "foc_exec_cnt: " << afl->foc_exec_cnt << endl;
            if(afl->foc_exec_tm)
                file << "foc_per_second: " << afl->foc_exec_cnt / (double)(afl->foc_exec_tm) * 1000 << endl;
            else
                file << "foc_per_second: " << "~" << endl;
            
            if(realDictCnt)
                file << "average_single_path_con_sol_tm: " << afl->single_path_con_sol_tm / (double)realDictCnt << endl;
            else
                file << "average_single_path_con_sol_tm: " << "~" << endl;

            file << "single_path_con_sol_suc: " << afl->single_path_con_sol_suc << endl;
            file << "single_path_con_sol_suc_rate: " << afl->single_path_con_sol_suc / (double)afl->single_path_con_sol_cnt << endl;
            file << "foc_sol_cnt: " << afl->foc_sol_cnt << endl;
            file << "foc_sol_rate: " << afl->foc_sol_cnt / (double)pathConCnt << endl;

            // save number of input byte's related path constraints
            file << "max_input_size: " << maxInputSize << endl;
            for(uint32_t i = 0; i < maxInputSize; i++){
                file << declPathConCnt[i] << endl;
            }
            // save size of path con node's symVarSet and keySymVarSet 
            queue<PathConNode*> nodeQueue;
            PathConNode *node = GetRoot();
            PathConNode *child;
            if(node && !node->IsLeaf())
                nodeQueue.push(node);
            while(!nodeQueue.empty()){
                node = nodeQueue.front();
                nodeQueue.pop();
                file << node->GetSymVarSet().size() << ", " << node->GetKeySymVarSet()->size() << endl;
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
        // if(focusMode){
        //     ACTF("Current focus path con:");
        //     cout<<nonNegPathConNode[targetNode - 1]->GetPathCon()<<endl;
        //     ACTF("New Test case");
        //     printf("%s", input);
        //     ACTF("Check Input");
        // }
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
                    uint32_t rCC = node->GetRChildCnt();
                    if(node->GetRChildCnt() <= maxRCnt){
                    // if(get_random(0u, maxRCnt) >= (rCC)){
                        node->AddRChildHitCnt();
                        if(node->GetRChildCnt() > maxRCnt){
                            PathConNode *p = node;
                            p->AddExpCnt();
                            while(1){
                                if(p->GetExpCnt() == 2){
                                    p = p->GetParent();
                                    if(p)
                                        p->AddExpCnt();
                                    else
                                        break;
                                }
                                else{
                                    break;
                                }
                            }
                        }
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

    // Except the first path con trace, CheckInput() must be called before InsertTrace().
    // int InsertTrace(char const *smtfile){
    int32_t InsertTrace(afl_state_t *afl, const char *smtfile, struct queue_entry *qe){
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
                for(auto symVar : p->GetSymVarSet())
                    declPathConCnt[symVar]++;
                afl->foc_sol_cnt += p->GetFocusFuzzed();
            }
            else{
                PathConNode *falseLeaf = new PathConNode(ctx, decls, ctx.bool_val(false));
                insertPoint->AddChild(falseLeaf, false);
                insertPoint->AddExpCnt();
                p = insertPoint;
                while(1){
                    if(p->GetExpCnt() == 2){
                        p = p->GetParent();
                        if(p)
                            p->AddExpCnt();
                        else
                            break;
                    }
                    else{
                        break;
                    }
                }
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
                afl->foc_sol_cnt += newNode->GetFocusFuzzed();
                p = newNode;
        }
        PathConNode *trueLeaf = new PathConNode(ctx, decls, ctx.bool_val(true));
        p->AddChild(trueLeaf, true);
        p->AddExpCnt();
        while(1){
            p->AddQueueEntry(qe);
            p = p->GetParent();
            if(p == nullptr)
                break;
        }
        return 1;      
     }

    PathConNode *GetRoot(){
        return root;
    }

    bool IsFocusMode(){
        return focusMode;
    }

    uint32_t SetupFocusMode(){
        focusMode = true;
        // traverse the path con tree and collect all path con nodes that have no right children
        queue<PathConNode*> nodeQueue;
        nodeQueue.push(root);
        while (!nodeQueue.empty()) {
            PathConNode* current = nodeQueue.front();
            if(current->GetExpCnt() > 2){
                ACTF("PathConNode with > 2 expcnt");
                cout<<current->GetPathCon()<<endl;
            }
            nodeQueue.pop();
            PathConNode *lChild = current->GetChild(true), *rChild = current->GetChild(false);
            if(!rChild){
                if(current->GetRChildCnt() <= maxRCntFocus){
                    nonNegPathConNode.push_back(current);
                }
            }
            else{
                if(!rChild->IsLeaf() && rChild->GetExpCnt() < 2)
                    nodeQueue.push(rChild);
            }
            if(!lChild->IsLeaf() && lChild->GetExpCnt() < 2)
                nodeQueue.push(lChild);
        }
        //return 1 if there are path con nodes with RCnt <= maxRCntFocus that have no right children 
        if(nonNegPathConNode.size()){
            targetNode = 0;
            return 1;
        }
        // return 0 if there is no suitable path con node to focus fuzzing
        return 0;
    }

    void ExitFocusMode(){
        focusMode = false;
        nonNegPathConNode.clear();
        targetNode = -1;
        focusSolver.reset();
    }
    
    uint32_t SetupFocusTarget(afl_state_t *afl){
        // Choose the target node to focus fuzzing
        if(targetNode == -1){
            log_exception("there is no non negative path con node\n");
            return 0;
        }
        while(targetNode < nonNegPathConNode.size()){
            uint32_t rCC = nonNegPathConNode[targetNode]->GetRChildCnt();
            if(get_random(0u, maxRCntFocus) >= rCC){
                break;
            }
            else{
                targetNode++;
            }
        }
        if(targetNode >= nonNegPathConNode.size())
            return 0;
        PathConNode *target = nonNegPathConNode[targetNode];

        // Get the key path constraints and symbolic variables
        if(!target->GetKeyPathConSet()->size()){
            GetKeyPathConSymVarSet();
        }
        // set up the focus solver
        focusSolver.reset();
        for(PathConNode * pcn : *target->GetKeyPathConSet()){
            if(pcn != target)
                focusSolver.add(pcn->GetPathCon());
            else
                focusSolver.add(!pcn->GetPathCon());
        }

        // single path constraints solving
        vector<uint8_t> &dict = target->GetDict();
        if(!dict.size()){
            solver s(ctx);
            params p(ctx);
            p.set("timeout", solverTimeout);
            s.set(p);
            s.add(!target->GetPathCon());

            auto start = std::chrono::steady_clock::now();
            uint32_t dictCnt = 0;
            while(s.check() == sat && dictCnt < maxDictCnt){
                model m = s.get_model();
                for(auto symVar : target->GetSymVarSet()){
                    expr var = m.eval(decls[symVar]());
                    dict.push_back(static_cast<uint8_t>(var.get_numeral_uint()));
                }
                expr block = ctx.bool_val(true);
                for (auto symVar : target->GetSymVarSet()) {
                    block = block && (decls[symVar]() == m.eval(decls[symVar]()));
                }
                s.add(!block);
                dictCnt++;
                realDictCnt++;
            }
            auto end = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
            afl->single_path_con_sol_tm += duration.count();
        }

        targetNode++;
        return target->GetKeySymVarSet()->size();
    }

    void GetKeyPathConSymVarSet(){
        if(targetNode == -1){
            return;
        }
        PathConNode *target = nonNegPathConNode[targetNode], *tmp = target;
        unordered_map<int, set<PathConNode *>> symVar2Expr;
        while(tmp){
            for(uint32_t symVar : tmp->GetSymVarSet()){
                symVar2Expr[symVar].insert(tmp);
            }
            tmp = tmp->GetParent();
        }
        set<PathConNode *> *keyPathConSet = target->GetKeyPathConSet();
        set<uint32_t> *keySymVarSet = target->GetKeySymVarSet();
        keyPathConSet->insert(target);
        for(uint32_t symVar : target->GetSymVarSet()){
            keySymVarSet->insert(symVar);
        }
        while(1){
            bool flag = false;
            for(uint32_t symVar : *keySymVarSet){
                for(PathConNode *pathConNode : symVar2Expr[symVar]){
                    auto res = keyPathConSet->insert(pathConNode);
                    flag |= res.second;
                }
            }
            if(!flag)
                break;
            flag = false;
            for(PathConNode *pcn : *keyPathConSet){
                for(uint32_t symVar : pcn->GetSymVarSet()){
                    auto res = keySymVarSet->insert(symVar);
                    flag |= res.second;
                }
            }
            if(!flag)
                break;
        }
        for(PathConNode *pathConNode : *keyPathConSet){
            if(pathConNode != target){
                pathConNode->SetKeyPathConSet(*keyPathConSet);
                pathConNode->SetKeySymVarSet(*keySymVarSet);
            }
        }
    }

    void FocusFuzzing(afl_state_t *afl){
        PathConNode *target = nonNegPathConNode[targetNode - 1];
        struct queue_entry **qelist = target->GetQueueEntryList();
        uint32_t size = target->GetQueueEntryListSize();
        size = (size > 128 ? 128 : size);
        auto start = std::chrono::steady_clock::now();
        for(uint32_t i = 0; i < size; i++){
            struct queue_entry *qe = qelist[i];
            afl->queue_cur = qe;
            afl->current_entry = qe->id;
            uint8_t *inBuf = queue_testcase_get(afl, qe);
            uint32_t len = qe->len, keyBytesCnt = target->GetKeySymVarSet()->size(), idx = 0;
            uint8_t *keyBytesBuf = (uint8_t *)calloc(keyBytesCnt + 1, 1);
            if (unlikely(!keyBytesBuf)) { PFATAL("alloc"); }
            std::map<uint32_t, uint32_t> symVar2keyByteIdx;
            for(uint32_t symVar : *target->GetKeySymVarSet()){
                keyBytesBuf[idx] = inBuf[symVar];
                symVar2keyByteIdx[symVar] = idx++;
            }
            // ACTF("Current focus bytes:");
            // printf("%s--%d\n", keyBytesBuf, keyBytesCnt);
            uint32_t dictSize = target->GetDict().size();
            if(dictSize){
                idx = 0;
                vector<uint8_t> &dict = target->GetDict();
                while(idx < dictSize){
                    for(uint32_t symVar : target->GetSymVarSet()){
                        keyBytesBuf[symVar2keyByteIdx[symVar]] = dict[idx++];
                    }
                    afl->single_path_con_sol_cnt++;
                    if(FocusMutating(afl, keyBytesBuf, keyBytesCnt) == 2){
                        auto end = std::chrono::steady_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                        afl->foc_exec_tm += duration.count();
                        return;
                    }
                }
            }
            else{
                if(FocusMutating(afl, keyBytesBuf, keyBytesCnt) == 2){
                    auto end = std::chrono::steady_clock::now();
                    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                    afl->foc_exec_tm += duration.count();
                    return;
                }
            }
        }
        auto end = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        afl->foc_exec_tm += duration.count();
        return;
    }

    uint32_t FocusMutating(afl_state_t *afl, uint8_t *in_buf, uint32_t len){ 
        PathConNode *target = nonNegPathConNode[targetNode - 1];
        struct queue_entry **qelist = target->GetQueueEntryList();
        uint32_t size = target->GetQueueEntryListSize(),idx;
        size = (size > 128 ? 128 : size);
        uint32_t i, j;
        uint8_t *out_buf, *keyBytesBuf;
        uint64_t havoc_queued = 0, orig_hit_cnt, new_hit_cnt = 0;
        uint32_t perf_score = 100;

        u8 ret_val = 1, doing_det = 0;
        /****************
         * FOCUS RANDOM HAVOC *
         ****************/
        afl->stage_name = (u8 *)"focus";
        afl->stage_short = (u8 *)"foc";
        afl->stage_max = ((doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) *
                        perf_score / afl->havoc_div) >>
                        8;
        afl->stage_cur_byte = -1;
        if (unlikely(afl->stage_max < HAVOC_MIN)) { afl->stage_max = HAVOC_MIN; }
        orig_hit_cnt = afl->queued_items + afl->saved_crashes;
        havoc_queued = afl->queued_items;

        // try single path constraint solving result
        keyBytesBuf = (uint8_t *)calloc(len + 1, 1);
        if (unlikely(!keyBytesBuf)) { PFATAL("alloc"); }
        out_buf = (u8 *)afl_realloc(AFL_BUF_PARAM(out), len);
        if (unlikely(!out_buf)) { PFATAL("alloc"); }
        memcpy(out_buf, in_buf, len);
        if(FocusCheckInput(out_buf, len)){
            afl->single_path_con_sol_suc++;
            target->SetFocusFuzzed();
            memcpy(keyBytesBuf, out_buf, len);
            for(uint32_t i = 0; i < size; i++){
                idx = 0;
                struct queue_entry *qe = qelist[i];
                uint8_t *inBuf = queue_testcase_get(afl, qe);
                out_buf = (u8 *)afl_realloc(AFL_BUF_PARAM(out), qe->len);
                if (unlikely(!out_buf)) { PFATAL("alloc"); }
                memcpy(out_buf, inBuf, qe->len);
                for(uint32_t keySymVar : *target->GetKeySymVarSet()){
                    out_buf[keySymVar] = keyBytesBuf[idx++];
                }
                out_buf[qe->len] = '\0';
                if (common_fuzz_stuff(afl, out_buf, qe->len)) { goto abandon_entry; }
                // exit(0);
                if(target->GetRChildCnt() > maxRCnt){
                    ret_val = 2;
                    return ret_val;
                }
            }
        }
        else{
            afl->fsrv.total_execs++;
            afl->foc_exec_cnt++;
            if (!(afl->stage_cur % afl->stats_update_freq) ||
                afl->stage_cur + 1 == afl->stage_max) {
                show_stats(afl);
            }
        }

        if (unlikely(afl->custom_only)) {

            /* Force UI update */
            show_stats(afl);
            /* Skip other stages */
            ret_val = 0;
            goto abandon_entry;

        }


        if (afl->custom_mutators_count) {

            LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

            if (el->stacked_custom && el->afl_custom_havoc_mutation_probability) {

                el->stacked_custom_prob =
                    el->afl_custom_havoc_mutation_probability(el->data);
                if (el->stacked_custom_prob > 100) {

                FATAL(
                    "The probability returned by "
                    "afl_custom_havoc_mutation_propability "
                    "has to be in the range 0-100.");

                }

            }

            });

        }

        /* We essentially just do several thousand runs (depending on perf_score)
            where we take the input file and make random stacked tweaks. */

        u32 *mutation_array;
        u32  stack_max, rand_max;  // stack_max_pow = afl->havoc_stack_pow2;

        switch (afl->input_mode) {

            case 1: {  // TEXT

            if (likely(afl->fuzz_mode == 0)) {  // is exploration?
                mutation_array = (unsigned int *)&binary_array;
                rand_max = MUT_BIN_ARRAY_SIZE;

            } else {  // exploitation mode

                mutation_array = (unsigned int *)&text_array;
                rand_max = MUT_TXT_ARRAY_SIZE;

            }

            break;

            }

            case 2: {  // BINARY

            if (likely(afl->fuzz_mode == 0)) {  // is exploration?
                mutation_array = (unsigned int *)&mutation_strategy_exploration_binary;
                rand_max = MUT_STRATEGY_ARRAY_SIZE;

            } else {  // exploitation mode

                mutation_array = (unsigned int *)&mutation_strategy_exploitation_binary;
                rand_max = MUT_STRATEGY_ARRAY_SIZE;
                // or this one? we do not have enough binary bug benchmarks :-(
                // mutation_array = (unsigned int *)&binary_array;
                // rand_max = MUT_BIN_ARRAY_SIZE;

            }

            break;

            }

            default: {  // DEFAULT/GENERIC

            if (likely(afl->fuzz_mode == 0)) {  // is exploration?
                mutation_array = (unsigned int *)&binary_array;
                rand_max = MUT_BIN_ARRAY_SIZE;

            } else {  // exploitation mode

                mutation_array = (unsigned int *)&text_array;
                rand_max = MUT_TXT_ARRAY_SIZE;

            }

            break;

            }

        }

        stack_max = 1 << (1 + rand_below(afl, afl->havoc_stack_pow2));

        // + (afl->extras_cnt ? 2 : 0) + (afl->a_extras_cnt ? 2 : 0);

        for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

            u32 use_stacking = 1 + rand_below(afl, stack_max);

            afl->stage_cur_val = use_stacking;

            for (i = 0; i < use_stacking; ++i) {

            if (afl->custom_mutators_count) {

                LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

                if (unlikely(el->stacked_custom &&
                            rand_below(afl, 100) < el->stacked_custom_prob)) {

                    u8    *custom_havoc_buf = NULL;
                    size_t new_len = el->afl_custom_havoc_mutation(
                        el->data, out_buf, len, &custom_havoc_buf, MAX_FILE);
                    if (unlikely(!custom_havoc_buf)) {

                    FATAL("Error in custom_havoc (return %zu)", new_len);

                    }

                    if (likely(new_len > 0 && custom_havoc_buf)) {

                    len = new_len;
                    if (out_buf != custom_havoc_buf) {

                        out_buf = (u8 *)afl_realloc(AFL_BUF_PARAM(out), len);
                        if (unlikely(!afl->out_buf)) { PFATAL("alloc"); }
                        memcpy(out_buf, custom_havoc_buf, len);

                    }

                    }

                }

                });

            }

            retry_havoc_step: {

            u32 r = rand_below(afl, rand_max), item;

            switch (mutation_array[r]) {

                case MUT_FLIPBIT: {

                /* Flip a single bit somewhere. Spooky! */
                u8  bit = rand_below(afl, 8);
                u32 off = rand_below(afl, len);
                out_buf[off] ^= 1 << bit;

        #ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " FLIP-BIT_%u", bit);
                strcat(afl->mutation, afl->m_tmp);
        #endif
                break;

                }

                case MUT_INTERESTING8: {

                /* Set byte to interesting value. */

                item = rand_below(afl, sizeof(interesting_8));
        #ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING8_%u", item);
                strcat(afl->mutation, afl->m_tmp);
        #endif
                out_buf[rand_below(afl, len)] = interesting_8[item];
                break;

                }

                case MUT_INTERESTING16: {

                /* Set word to interesting value, little endian. */

                if (unlikely(len < 2)) { break; }  // no retry

                item = rand_below(afl, sizeof(interesting_16) >> 1);
        #ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING16_%u", item);
                strcat(afl->mutation, afl->m_tmp);
        #endif

                *(u16 *)(out_buf + rand_below(afl, len - 1)) =
                    interesting_16[item];

                break;

                }

                case MUT_INTERESTING16BE: {

                /* Set word to interesting value, big endian. */

                if (unlikely(len < 2)) { break; }  // no retry

                item = rand_below(afl, sizeof(interesting_16) >> 1);
        #ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING16BE_%u", item);
                strcat(afl->mutation, afl->m_tmp);
        #endif
                *(u16 *)(out_buf + rand_below(afl, len - 1)) =
                    SWAP16(interesting_16[item]);

                break;

                }

                case MUT_INTERESTING32: {

                /* Set dword to interesting value, little endian. */

                if (unlikely(len < 4)) { break; }  // no retry

                item = rand_below(afl, sizeof(interesting_32) >> 2);
        #ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING32_%u", item);
                strcat(afl->mutation, afl->m_tmp);
        #endif

                *(u32 *)(out_buf + rand_below(afl, len - 3)) =
                    interesting_32[item];

                break;

                }

                case MUT_INTERESTING32BE: {

                /* Set dword to interesting value, big endian. */

                if (unlikely(len < 4)) { break; }  // no retry

                item = rand_below(afl, sizeof(interesting_32) >> 2);
        #ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING32BE_%u", item);
                strcat(afl->mutation, afl->m_tmp);
        #endif
                *(u32 *)(out_buf + rand_below(afl, len - 3)) =
                    SWAP32(interesting_32[item]);

                break;

                }

                case MUT_ARITH8_: {

                /* Randomly subtract from byte. */

                item = 1 + rand_below(afl, ARITH_MAX);
        #ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH8-_%u", item);
                strcat(afl->mutation, afl->m_tmp);
        #endif
                out_buf[rand_below(afl, len)] -= item;
                break;

                }

                case MUT_ARITH8: {

                /* Randomly add to byte. */

                item = 1 + rand_below(afl, ARITH_MAX);
        #ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH8+_%u", item);
                strcat(afl->mutation, afl->m_tmp);
        #endif
                out_buf[rand_below(afl, len)] += item;
                break;

                }

                case MUT_ARITH16_: {

                /* Randomly subtract from word, little endian. */

                if (unlikely(len < 2)) { break; }  // no retry

                u32 pos = rand_below(afl, len - 1);
                item = 1 + rand_below(afl, ARITH_MAX);

        #ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16-_%u", item);
                strcat(afl->mutation, afl->m_tmp);
        #endif
                *(u16 *)(out_buf + pos) -= item;

                break;

                }

                case MUT_ARITH16BE_: {

                /* Randomly subtract from word, big endian. */

                if (unlikely(len < 2)) { break; }  // no retry

                u32 pos = rand_below(afl, len - 1);
                u16 num = 1 + rand_below(afl, ARITH_MAX);

        #ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16BE-_%u", num);
                strcat(afl->mutation, afl->m_tmp);
        #endif
                *(u16 *)(out_buf + pos) =
                    SWAP16(SWAP16(*(u16 *)(out_buf + pos)) - num);

                break;

                }

                case MUT_ARITH16: {

                /* Randomly add to word, little endian. */

                if (unlikely(len < 2)) { break; }  // no retry

                u32 pos = rand_below(afl, len - 1);
                item = 1 + rand_below(afl, ARITH_MAX);

        #ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16+_%u", item);
                strcat(afl->mutation, afl->m_tmp);
        #endif
                *(u16 *)(out_buf + pos) += item;

                break;

                }

                case MUT_ARITH16BE: {

                /* Randomly add to word, big endian. */

                if (unlikely(len < 2)) { break; }  // no retry

                u32 pos = rand_below(afl, len - 1);
                u16 num = 1 + rand_below(afl, ARITH_MAX);

        #ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16BE+__%u", num);
                strcat(afl->mutation, afl->m_tmp);
        #endif
                *(u16 *)(out_buf + pos) =
                    SWAP16(SWAP16(*(u16 *)(out_buf + pos)) + num);

                break;

                }

                case MUT_ARITH32_: {

                /* Randomly subtract from dword, little endian. */

                if (unlikely(len < 4)) { break; }  // no retry

                u32 pos = rand_below(afl, len - 3);
                item = 1 + rand_below(afl, ARITH_MAX);

        #ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH32-_%u", item);
                strcat(afl->mutation, afl->m_tmp);
        #endif
                *(u32 *)(out_buf + pos) -= item;

                break;

                }

                case MUT_ARITH32BE_: {

                /* Randomly subtract from dword, big endian. */

                if (unlikely(len < 4)) { break; }  // no retry

                u32 pos = rand_below(afl, len - 3);
                u32 num = 1 + rand_below(afl, ARITH_MAX);

        #ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH32BE-_%u", num);
                strcat(afl->mutation, afl->m_tmp);
        #endif
                *(u32 *)(out_buf + pos) =
                    SWAP32(SWAP32(*(u32 *)(out_buf + pos)) - num);

                break;

                }

                case MUT_ARITH32: {

                /* Randomly add to dword, little endian. */

                if (unlikely(len < 4)) { break; }  // no retry

                u32 pos = rand_below(afl, len - 3);
                item = 1 + rand_below(afl, ARITH_MAX);

        #ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH32+_%u", item);
                strcat(afl->mutation, afl->m_tmp);
        #endif
                *(u32 *)(out_buf + pos) += item;

                break;

                }

                case MUT_ARITH32BE: {

                /* Randomly add to dword, big endian. */

                if (unlikely(len < 4)) { break; }  // no retry

                u32 pos = rand_below(afl, len - 3);
                u32 num = 1 + rand_below(afl, ARITH_MAX);

        #ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH32BE+_%u", num);
                strcat(afl->mutation, afl->m_tmp);
        #endif
                *(u32 *)(out_buf + pos) =
                    SWAP32(SWAP32(*(u32 *)(out_buf + pos)) + num);

                break;

                }

                case MUT_RAND8: {

                /* Just set a random byte to a random value. Because,
                    why not. We use XOR with 1-255 to eliminate the
                    possibility of a no-op. */

                u32 pos = rand_below(afl, len);
                item = 1 + rand_below(afl, 255);
        #ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " RAND8_%u",
                        out_buf[pos] ^ item);
                strcat(afl->mutation, afl->m_tmp);
        #endif
                out_buf[pos] ^= item;
                break;

                }

                case MUT_CLONE_COPY: {
                    goto retry_havoc_step;
                }

                case MUT_CLONE_FIXED: {
                    goto retry_havoc_step;
                }

                case MUT_OVERWRITE_COPY: {

                /* Overwrite bytes with a randomly selected chunk bytes. */

                if (unlikely(len < 2)) { break; }  // no retry

                u32 copy_from, copy_to,
                    copy_len = choose_block_len(afl, len - 1);

                do {

                    copy_from = rand_below(afl, len - copy_len + 1);
                    copy_to = rand_below(afl, len - copy_len + 1);

                } while (unlikely(copy_from == copy_to));

        #ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " OVERWRITE-COPY_%u_%u_%u",
                        copy_from, copy_to, copy_len);
                strcat(afl->mutation, afl->m_tmp);
        #endif
                memmove(out_buf + copy_to, out_buf + copy_from, copy_len);

                break;

                }

                case MUT_OVERWRITE_FIXED: {

                /* Overwrite bytes with fixed bytes. */

                if (unlikely(len < 2)) { break; }  // no retry

                u32 copy_len = choose_block_len(afl, len - 1);
                u32 copy_to = rand_below(afl, len - copy_len + 1);
                u32 strat = rand_below(afl, 2);
                u32 copy_from = copy_to ? copy_to - 1 : 0;
                item = strat ? rand_below(afl, 256) : out_buf[copy_from];

        #ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                        " OVERWRITE-FIXED_%u_%u_%u-%u", strat, item, copy_to,
                        copy_len);
                strcat(afl->mutation, afl->m_tmp);
        #endif
                memset(out_buf + copy_to, item, copy_len);

                break;

                }

                case MUT_BYTEADD: {

                /* Increase byte by 1. */

        #ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " BYTEADD_");
                strcat(afl->mutation, afl->m_tmp);
        #endif
                out_buf[rand_below(afl, len)]++;
                break;

                }

                case MUT_BYTESUB: {

                /* Decrease byte by 1. */

        #ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " BYTESUB_");
                strcat(afl->mutation, afl->m_tmp);
        #endif
                out_buf[rand_below(afl, len)]--;
                break;

                }

                case MUT_FLIP8: {

                /* Flip byte with a XOR 0xff. This is the same as NEG. */

        #ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " FLIP8_");
                strcat(afl->mutation, afl->m_tmp);
        #endif
                out_buf[rand_below(afl, len)] ^= 0xff;
                break;

                }

                case MUT_SWITCH: {

                if (unlikely(len < 4)) { break; }  // no retry

                /* Switch bytes. */

                u32 to_end, switch_to, switch_len, switch_from;
                switch_from = rand_below(afl, len);
                do {

                    switch_to = rand_below(afl, len);

                } while (unlikely(switch_from == switch_to));

                if (switch_from < switch_to) {

                    switch_len = switch_to - switch_from;
                    to_end = len - switch_to;

                } else {

                    switch_len = switch_from - switch_to;
                    to_end = len - switch_from;

                }

                switch_len = choose_block_len(afl, MIN(switch_len, to_end));

        #ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " SWITCH-%s_%u_%u_%u",
                        "switch", switch_from, switch_to, switch_len);
                strcat(afl->mutation, afl->m_tmp);
        #endif
                u8 *new_buf = (u8 *)afl_realloc(AFL_BUF_PARAM(out_scratch), switch_len);
                if (unlikely(!new_buf)) { PFATAL("alloc"); }

                /* Backup */

                memcpy(new_buf, out_buf + switch_from, switch_len);

                /* Switch 1 */

                memcpy(out_buf + switch_from, out_buf + switch_to, switch_len);

                /* Switch 2 */

                memcpy(out_buf + switch_to, new_buf, switch_len);

                break;

                }

                case MUT_DEL: {
                    goto retry_havoc_step;
                }

                case MUT_SHUFFLE: {

                /* Shuffle bytes. */

                if (unlikely(len < 4)) { break; }  // no retry

                u32 size = choose_block_len(afl, len - 1);
                u32 off = rand_below(afl, len - size + 1);

        #ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " SHUFFLE_%u", len);
                strcat(afl->mutation, afl->m_tmp);
        #endif

                for (u32 i = size - 1; i > 0; i--) {

                    u32 j;
                    do {

                    j = rand_below(afl, i + 1);

                    } while (unlikely(i == j));

                    unsigned char temp = out_buf[off + i];
                    out_buf[off + i] = out_buf[off + j];
                    out_buf[off + j] = temp;

                }

                break;

                }

                case MUT_DELONE: {
                    goto retry_havoc_step;
                }

                case MUT_INSERTONE: {
                    goto retry_havoc_step;
                }

                case MUT_ASCIINUM: {
                    goto retry_havoc_step;
                }

                case MUT_INSERTASCIINUM: {

                u32 size = 1 + rand_below(afl, 8);
                u32 pos = rand_below(afl, len);
                /* Insert ascii number. */
                if (unlikely(len < pos + size)) {

                    if (unlikely(len < 8)) {

                    break;

                    } else {

                    goto retry_havoc_step;

                    }

                }

        #ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INSERTASCIINUM_");
                strcat(afl->mutation, afl->m_tmp);
        #endif
                u64  val = rand_next(afl);
                char buf[20];
                snprintf(buf, sizeof(buf), "%llu", val);
                memcpy(out_buf + pos, buf, size);

                break;

                }

                case MUT_EXTRA_OVERWRITE: {
                    goto retry_havoc_step;
                }

                case MUT_AUTO_EXTRA_OVERWRITE: {
                    goto retry_havoc_step;
                }

                case MUT_SPLICE_OVERWRITE: {

                if (unlikely(afl->ready_for_splicing_count <= 1)) {

                    goto retry_havoc_step;

                }

                /* Pick a random queue entry and seek to it. */

                u32 tid;
                do {

                    tid = rand_below(afl, afl->queued_items);

                } while (unlikely(tid == afl->current_entry ||

                                    afl->queue_buf[tid]->len < 4));

                /* Get the testcase for splicing. */
                struct queue_entry *target = afl->queue_buf[tid];
                u32                 new_len = target->len;
                u8                 *new_buf = queue_testcase_get(afl, target);

                /* overwrite mode */

                u32 copy_from, copy_to, copy_len;

                copy_len = choose_block_len(afl, new_len - 1);
                if (copy_len > len) copy_len = len;

                copy_from = rand_below(afl, new_len - copy_len + 1);
                copy_to = rand_below(afl, len - copy_len + 1);

        #ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                        " SPLICE-OVERWRITE_%u_%u_%u_%s", copy_from, copy_to,
                        copy_len, target->fname);
                strcat(afl->mutation, afl->m_tmp);
        #endif
                memmove(out_buf + copy_to, new_buf + copy_from, copy_len);

                break;

                }

                case MUT_SPLICE_INSERT: {
                    goto retry_havoc_step;
                }

            }

            }

            }

            if(FocusCheckInput(out_buf, len)){
                memcpy(keyBytesBuf, out_buf, len);
                for(uint32_t i = 0; i < size; i++){
                    idx = 0;
                    struct queue_entry *qe = qelist[i];
                    uint8_t *inBuf = queue_testcase_get(afl, qe);
                    out_buf = (u8 *)afl_realloc(AFL_BUF_PARAM(out), qe->len);
                    if (unlikely(!out_buf)) { PFATAL("alloc"); }
                    memcpy(out_buf, inBuf, qe->len);
                    for(uint32_t keySymVar : *target->GetKeySymVarSet()){
                        out_buf[keySymVar] = keyBytesBuf[idx++];
                    }
                    out_buf[qe->len] = '\0';
                    if (common_fuzz_stuff(afl, out_buf, qe->len)) { goto abandon_entry; }
                    // exit(0);
                    if(target->GetRChildCnt() > maxRCnt){
                        ret_val = 2;
                        return ret_val;
                    }
                }
            }
            else{
                afl->fsrv.total_execs++;
                afl->foc_exec_cnt++;
                if (!(afl->stage_cur % afl->stats_update_freq) ||
                    afl->stage_cur + 1 == afl->stage_max) {
                    show_stats(afl);
                }
            }

            /* out_buf might have been mangled a bit, so let's restore it to its
            original size and shape. */

            out_buf = (u8 *)afl_realloc(AFL_BUF_PARAM(out), len);
            if (unlikely(!out_buf)) { PFATAL("alloc"); }
            memcpy(out_buf, in_buf, len);

            /* If we're finding new stuff, let's run for a bit longer, limits
            permitting. */

            if (afl->queued_items != havoc_queued) {

            if (perf_score <= afl->havoc_max_mult * 100) {

                afl->stage_max *= 2;
                perf_score *= 2;

            }

            havoc_queued = afl->queued_items;

            }

        }


        new_hit_cnt = afl->queued_items + afl->saved_crashes;

        afl->stage_finds[STAGE_FOCUS] += new_hit_cnt - orig_hit_cnt;
        afl->stage_cycles[STAGE_FOCUS] += afl->stage_max;

        /* we are through with this queue entry - for this iteration */
        abandon_entry:

        afl->splicing_with = -1;

        /* Update afl->pending_not_fuzzed count if we made it through the calibration
            cycle and have not seen this entry before. */

        if (!afl->stop_soon && !afl->queue_cur->cal_failed &&
            !afl->queue_cur->was_fuzzed && !afl->queue_cur->disabled) {

            --afl->pending_not_fuzzed;
            afl->queue_cur->was_fuzzed = 1;
            afl->reinit_table = 1;
            if (afl->queue_cur->favored) {

            --afl->pending_favored;
            afl->smallest_favored = -1;

            }

        }

        ++afl->queue_cur->fuzz_level;
        return ret_val;
    }

    bool FocusCheckInput(uint8_t *focusbytes, uint32_t size){
        if(!focusMode){
            log_exception("Call FocusCheckInput when not in focus mode!\n");
            return false;
        }
        PathConNode *target = nonNegPathConNode[targetNode - 1];
        set<uint32_t> keySymVarSet = *target->GetKeySymVarSet();
        if(size != keySymVarSet.size()){
            log_exception("Unmatched Focus Bytes!\n");
            return false;
        }
        uint32_t index = 0;
        focusSolver.push();
        for(uint32_t keyvar : keySymVarSet){
            focusSolver.add(decls[keyvar]() == ctx.bv_val(focusbytes[index++], 8));
        }
        auto res = focusSolver.check();
        if(res == sat){
            focusSolver.pop();
            return true;
        }
        else if(res == unsat){
            focusSolver.pop();
            return false;
        }else{
            log_exception("Solver exception during FocusCheckInput!\n");
            focusSolver.pop();
            exit(-1);
        }
    }

private:
    context ctx;
    z3::sort bv8 = ctx.bv_sort(8);
    // expr_vector &allAssertions;
    sort_vector sorts = sort_vector(ctx);
    func_decl_vector decls = func_decl_vector(ctx);
    vector<uint32_t> declPathConCnt;
    solver focusSolver = solver(ctx);
    bool focusMode;
    uint32_t initDecCnt, maxInputSize, maxRCnt, maxRCntFocus, solverTimeout, maxDictCnt, realDictCnt, pathConCnt;
    PathConNode *root, *insertPoint;
    vector<PathConNode *> nonNegPathConNode;
    int32_t insertDepth, targetNode;
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
                if(current->GetRChildCnt() <= maxRCnt)
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

    bool path_con_tree_is_focus_mode(afl_state_t *afl) {
        return afl->path_con_tree->IsFocusMode();
    }
    int32_t path_con_tree_check_input(afl_state_t *afl, const uint8_t* input, uint32_t size) {
        return afl->path_con_tree->CheckInput(input, size);
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

    uint32_t path_con_tree_set_up_focus_mode(afl_state_t *afl){
        return afl->path_con_tree->SetupFocusMode();
    }

    void path_con_tree_exit_focus_mode(afl_state_t *afl){
        afl->path_con_tree->ExitFocusMode();
    }

    uint32_t path_con_tree_set_up_focus_target(afl_state_t *afl){
        return afl->path_con_tree->SetupFocusTarget(afl);
    }

    void path_con_tree_focus_fuzzing(afl_state_t *afl){
        afl->path_con_tree->FocusFuzzing(afl);
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