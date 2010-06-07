#ifndef _PAM_CHROOT_TEST_H
#define _PAM_CHROOT_TEST_H

/* reset location of the pam_chroot config file */
#undef CONFIG
#define CONFIG  "test_chroot.conf"

/* structure representing state of a single test. */
typedef struct _test_single {
  int8_t result;
  int8_t (*test_fn)();
  char* description;
  struct _test_single* next;
} test_single;

/* structure for tracking state of tests. */
typedef struct _test_tracker {
  test_single* tests;
  char* description;
  struct _test_tracker* next;
} test_tracker;

int set_chroot_cfg_contents(const char* cfg);
void clean_chroot_cfg();

test_single* init_test_single(int8_t (*test_fn)(), const char* description);
test_tracker* init_test_tracker(const char* description);
void free_tracker_tests(test_tracker* tracker);
void free_tracker(test_tracker* tracker);

test_tracker* add_test(test_tracker* tracker, int test_id);
void run_tests(test_tracker *tracker);

void print_test_result(test_single* test);
void print_test_results(test_tracker *tracker);
int count_test_errors(test_tracker* tracker);

test_tracker* process_args(int argc, char** argv);

/* function definitions for all the test functions */

/* system tests */
int8_t test_syscall_overrides();
int8_t test_config_mangling();

enum TEST_CODES {
  SYSCALL_OVERRIDES,
  CONFIG_MANGLING
};

#endif
