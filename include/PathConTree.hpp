#ifndef PATHCON_TREE_H
#define PATHCON_TREE_H

#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
// 前向声明不透明指针
typedef struct PathConTree PathConTree;

// #include "afl-mutations.h"

// #define LIST_FOREACH(list, type, block)                            \
//   do {                                                             \
//                                                                    \
//     list_t    *li = (list);                                        \
//     element_t *head = get_head((li));                              \
//     element_t *el_box = (head)->next;                              \
//     if (!el_box) FATAL("foreach over uninitialized list");         \
//     while (el_box != head) {                                       \
//                                                                    \
//       __attribute__((unused)) type *el = (type *)((el_box)->data); \
//       /* get next so el_box can be unlinked */                     \
//       element_t *next = el_box->next;                              \
//       {block};                                                     \
//       el_box = next;                                               \
//                                                                    \
//     }                                                              \
//                                                                    \
//   } while (0);


// 构造函数
PathConTree* path_con_tree_create(uint32_t init_dec_cnt);
// 析构函数
void path_con_tree_destroy(afl_state_t *afl);

bool path_con_tree_is_focus_mode(afl_state_t *afl);

// 插入pc trace
int32_t path_con_tree_insert_trace(afl_state_t *afl, const char* smtfile, struct queue_entry *qe);
// 输入校验
int32_t path_con_tree_check_input(afl_state_t *afl, const uint8_t* input, uint32_t size);

// 可视化接口
void visualize_path_con_tree(PathConTree* tree, const char* filename);

uint32_t path_con_tree_set_up_focus_mode(afl_state_t *afl);

void path_con_tree_exit_focus_mode(afl_state_t *afl);

uint32_t path_con_tree_set_up_focus_target(afl_state_t *afl);

void path_con_tree_focus_fuzzing(afl_state_t *afl);

void path_con_tree_save_stats(afl_state_t *afl);

#ifdef __cplusplus
}
#endif

#endif // PATHCON_TREE_H