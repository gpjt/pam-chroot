/*
 * regression tests for pam_chroot
 *
 * $Id: pam_chroot_test.c,v 1.2 2007/10/03 07:49:20 schmolli Exp $
 */

#include "pam_chroot.h"
#include "pam_chroot_test.h"

#define  PAM_SM_AUTH
#define  PAM_SM_ACCOUNT
#define  PAM_SM_SESSION
#include <security/pam_modules.h>
#include <security/_pam_macros.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

int set_chroot_cfg_contents(const char* cfg) {
  int fd;
  int cfg_len = strlen(cfg);
  int written = 0;

  fd = open(CONFIG, O_WRONLY | O_CREAT | O_TRUNC, S_IREAD | S_IWRITE);
  if (fd == -1) {
    fprintf(stderr, "%s: unable to open config '"CONFIG"': %s", __FUNCTION__,
            strerror(errno));
    return 1;
  }

  written = write(fd, cfg, cfg_len);
  close(fd);
  if (written == -1) {
    fprintf(stderr, "%s: write to '"CONFIG"' failed: %s\n", __FUNCTION__,
            strerror(errno));
    return 1;
  } else if (written != cfg_len) {
    fprintf(stderr, "%s: failed to write entire config "
            "(wrote %d bytes of %d)\n", __FUNCTION__, written, cfg_len);
    return 1;
  }
  return 0;
}

void clean_chroot_cfg() {
  unlink(CONFIG);
}

/* initialize test state for a single test */
test_single* init_test_single(int8_t (*test_fn)(), const char* description) {
  test_single* test = malloc(sizeof(test_single));
  if (test == NULL) { return NULL; }
  test->result = 1;
  test->test_fn = test_fn;
  test->description = strdup(description);
  test->next = NULL;
  return test;
}

/* initialize state for a test container */
test_tracker* init_test_tracker(const char* description) {
  test_tracker* tracker = malloc(sizeof(test_tracker));
  if (tracker == NULL) { return NULL; }
  tracker->tests = NULL;
  tracker->description = strdup(description);
  return tracker;
}

test_tracker* add_test(test_tracker* tracker, int test_id) {
  test_single* new_test = NULL;
  char* description = NULL;
  int8_t (*test_fn)() = NULL;

  switch (test_id) {
    case SYSCALL_OVERRIDES:
      test_fn = &test_syscall_overrides;
      description = "Test syscall overrides";
      break;
    case CONFIG_MANGLING:
      test_fn = &test_config_mangling;
      description = "Test config file mangling";
      break;
    default:
      test_fn = NULL;
      description = NULL;
  };
  if (test_fn == NULL) {
    fprintf(stderr, "add_test: unrecognized test_id %d\n", test_id);
    return NULL;
  }

  new_test = init_test_single(test_fn, description);
  if (new_test == NULL) { return NULL; }

  new_test->next = tracker->tests;
  tracker->tests = new_test;
  return tracker;
}

/* free a single tracker's tests */
void free_tracker_tests(test_tracker* tracker) {
  if (tracker == NULL) { return; }

  while (tracker->tests) {
    test_single* test = tracker->tests;
    tracker->tests = tracker->tests->next;
    free(test->description);
    free(test);
  }
}
/* free a list of trackers */
void free_tracker(test_tracker* tracker) {
  if (tracker == NULL) { return; }

  while (tracker) {
    test_tracker* next_tracker = tracker->next;
    free_tracker_tests(tracker);
    free(tracker->description);
    free(tracker);
    tracker = next_tracker;
  }
}

void print_test_result(test_single* test) {
  printf("  [%s] %s\n", (test->result == 0 ? " OK " : "FAIL"),
         test->description);
}
void print_test_results(test_tracker *tracker) {
  test_single* test = tracker->tests;

  printf("[%s] %s\n", (count_test_errors(tracker) == 0 ? " OK " : "FAIL"),
         tracker->description);
  while (test) {
    print_test_result(test);
    test = test->next;
  }
}
int count_test_errors(test_tracker* tracker) {
  int errors = 0;
  test_single* test = tracker->tests;

  while (test) {
    errors += test->result;
    test = test->next;
  }
  return errors;
}
void run_tests(test_tracker *tracker) {
  test_single* test = tracker->tests;

  while (test) {
    test->result = (*(test->test_fn))();
    test = test->next;
  }
}

/* fake out some system calls */
int chdir(const char *path) {
  /* magic pathname for testing failures */
  if (strcmp(path, "/no-chdir") == 0) {
    return 1;
  }
  return 0;
}
int chroot(const char *path) {
  /* magic pathname for testing failures */
  if (strcmp(path, "/no-chroot") == 0) {
    return 1;
  }
  return 0;
}

/* test that the test environment is set up correctly */
int8_t test_syscall_overrides() {
  if ((chdir("/chroot") != 0) || (chdir("/no-chdir") == 0)) {
    return 1;
  }
  if ((chroot("/chroot") != 0) || (chroot("/no-chroot") == 0)) {
    return 1;
  }
  return 0;
}

#define _CONFIG_BUF_SIZE 10
int8_t test_config_mangling() {
  char config_text[] = "hi mom!\n";
  char config_buf[_CONFIG_BUF_SIZE];
  int fd;
  struct stat stat_buf;

  if (set_chroot_cfg_contents(config_text) != 0) {
    fprintf(stderr, "%s: failed to write config '"CONFIG"'\n", __FUNCTION__);
    return 1;
  }

  memset(config_buf, 0, _CONFIG_BUF_SIZE);
  fd = open(CONFIG, O_RDONLY);
  if (fd == -1) {
    fprintf(stderr, "%s: unable to open config '"CONFIG"': %s\n", __FUNCTION__,
            strerror(errno));
    return 1;
  }

  if (read(fd, config_buf, _CONFIG_BUF_SIZE) == -1) {
    fprintf(stderr, "%s: read of '"CONFIG"' failed: %s\n", __FUNCTION__,
            strerror(errno));
    return 1;
  } else if (strcmp(config_text, config_buf) != 0) {
    fprintf(stderr, "%s: read config did not match written config:\n"
            "WRITTEN CONFIG:\n\"\"\"\n%s\"\"\"\n"
            "READ CONFIG:\n\"\"\"\n%s\"\"\"\n",
            __FUNCTION__, config_text, config_buf);
    return 1;
  }
  close(fd);

  /* clean up the config file, then make sure it is really gone */
  clean_chroot_cfg();
  if ((stat(CONFIG, &stat_buf) != -1) || (errno != ENOENT)) {
    fprintf(stderr, "%s: config file '"CONFIG"' still exists after cleanup.",
            __FUNCTION__);
    return 1;
  }

  return 0;
}

/* utility function to init a new test_tracker and slap it into an appropriate
 * spot in the argument tracker list.  in the event that initialization of the
 * new tracker fails, we clean up the existing list.  otherwise, return a
 * pointer to the new tracker so the caller knows which tracker to add
 * sub-tests to. */
test_tracker* _get_new_or_cleanup(const char* description,
                                         test_tracker** current_tracker) {
  test_tracker* new_tracker = init_test_tracker(description);
  if (new_tracker == NULL) {
    if (*current_tracker) { free_tracker(*current_tracker); }
    return NULL;
  } else {
    if (*current_tracker == NULL) {
      *current_tracker = new_tracker;
    } else {
      /* append the new tracker to the end of the existing list */
      test_tracker* tracker = *current_tracker;
      while (tracker->next) { tracker = tracker->next; }
      tracker->next = new_tracker;
    }
  }
  return new_tracker;
}

/* TODO: there should be ordering in the arg processing.  perhaps process the
 * args far enough to figure out what needs to be done, then seperately build
 * up the test_trackers. */
test_tracker* process_args(int argc, char** argv) {
  /* valid command line opts */
  char* opts = "as";
  test_tracker* tracker = NULL;

  while(1) {
    test_tracker* new_tracker;
    int c = getopt(argc, argv, opts);
    if (c == -1) { break; }
    switch (c) {
      case 'a': /* all non-system tests */
        /* i feel like there should be an easier way to do this than to have a
         * second add_test call. */
        new_tracker = _get_new_or_cleanup("Dummy test module", &tracker);
        if (new_tracker == NULL) { return NULL; }
        break;

      case 's': /* system tests */
        new_tracker = _get_new_or_cleanup("Run system tests", &tracker);
        if (new_tracker == NULL) { return NULL; }
        add_test(new_tracker, SYSCALL_OVERRIDES);
        add_test(new_tracker, CONFIG_MANGLING);
        break;

      default: /* including the '?' case */
        fprintf(stderr, "unrecognized option '%c'\n", c);
        return NULL;
        break;
    }
  }
  return tracker;
}

int main(int argc, char** argv) {
  test_tracker* tracker;
  int errors = 0;

  tracker = process_args(argc, argv);
  if (tracker == NULL) {
    fprintf(stderr, "test setup failed\n");
    return 1;
  }

  run_tests(tracker);
  print_test_results(tracker);

  errors = count_test_errors(tracker);
  free_tracker(tracker);

  return errors;
}

