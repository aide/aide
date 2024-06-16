/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2024 Hannes von Haugwitz
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <check.h>
#include <stdlib.h>
#include <stdbool.h>

#include "seltree.h"
#include "gen_list.h"
#include "rx_rule.h"
#include "log.h"

#include "db_config.h"

typedef struct {
    char *regex;
    AIDE_RULE_TYPE type;
    RESTRICTION_TYPE restriction;
} check_seltree_rule_t;

typedef struct {
    char *file_name;
    RESTRICTION_TYPE file_type;
    match_result expected_match;
} check_seltree_test_t;

static seltree *add_rules(check_seltree_rule_t rules[], size_t num_of_rules) {
    seltree *tree = init_tree();
    char* node_path = NULL;
    for (int i = 0 ; i < num_of_rules ; i++) {
        add_rx_to_tree(rules[i].regex, rules[i].restriction, rules[i].type, tree, i, "check_seltree", "n/a", &node_path);
    }
    log_tree(LOG_LEVEL_RULE, tree, 0);
    return tree;
}

static void test_rules(seltree *tree, check_seltree_test_t tests[], size_t num_of_tests) {
    for (int i = 0 ; i < num_of_tests ; i++) {
        log_msg(LOG_LEVEL_RULE, "\u252c check '%s' (filetype: %c)", tests[i].file_name, get_restriction_char(tests[i].file_type));
        match_t match = check_seltree(tree, tests[i].file_name, tests[i].file_type, true);
        log_msg(LOG_LEVEL_RULE, "\u2534 result: %s", get_match_result_string(match.result));

        ck_assert_msg(tests[i].expected_match == match.result , "check_seltree %s (f_type: %c): returned %s (%d) (expected: %s (%d))",
                tests[i].file_name, get_restriction_char(tests[i].file_type), get_match_result_string(match.result), match.result, get_match_result_string(tests[i].expected_match), tests[i].expected_match);
    }
}
START_TEST (test_unrestricted_equal_rule) {
    log_msg(LOG_LEVEL_INFO, "test_unrestricted_equal_rule");
    check_seltree_rule_t rules[] = {
        { .regex = "/dev",                              .type = AIDE_EQUAL_RULE,                  .restriction = FT_NULL },
    };
    check_seltree_test_t tests[] = {
        { .file_name = "/",                       .file_type = FT_DIR, .expected_match = RESULT_PARTIAL_MATCH      },
        { .file_name = "/dev",                    .file_type = FT_DIR, .expected_match = RESULT_EQUAL_MATCH        },
        { .file_name = "/dev/sda",                .file_type = FT_BLK, .expected_match = RESULT_NO_RULE_MATCH      },
        { .file_name = "/dev/pts",                .file_type = FT_DIR, .expected_match = RESULT_NO_RULE_MATCH      },
        { .file_name = "/dev/pts/0",              .file_type = FT_BLK, .expected_match = RESULT_NO_RULE_MATCH      },
        { .file_name = "/dev/pts/deep/down/0",    .file_type = FT_DIR, .expected_match = RESULT_NO_RULE_MATCH      },
        { .file_name = "/etc",                    .file_type = FT_DIR, .expected_match = RESULT_NO_RULE_MATCH      },
        { .file_name = "/etc/deep/down/0",        .file_type = FT_REG, .expected_match = RESULT_NO_RULE_MATCH      },
    };
    test_rules(add_rules(rules, sizeof(rules)/sizeof(check_seltree_rule_t)), tests, sizeof(tests)/sizeof(check_seltree_test_t));
}
END_TEST

START_TEST (test_unrestricted_equal_rule_slash) {
    log_msg(LOG_LEVEL_INFO, "test_unrestricted_equal_rule_slash");
    check_seltree_rule_t rules[] = {
        { .regex = "/dev/",                              .type = AIDE_EQUAL_RULE,                  .restriction = FT_NULL },
    };
    check_seltree_test_t tests[] = {
        { .file_name = "/",                       .file_type = FT_DIR, .expected_match = RESULT_PARTIAL_MATCH     },
        { .file_name = "/dev",                    .file_type = FT_DIR, .expected_match = RESULT_PARTIAL_MATCH     },
        { .file_name = "/dev/sda",                .file_type = FT_BLK, .expected_match = RESULT_EQUAL_MATCH       },
        { .file_name = "/dev/pts",                .file_type = FT_DIR, .expected_match = RESULT_EQUAL_MATCH       },
        { .file_name = "/dev/pts/0",              .file_type = FT_BLK, .expected_match = RESULT_NO_RULE_MATCH     },
        { .file_name = "/dev/pts/deep/down/0",    .file_type = FT_DIR, .expected_match = RESULT_NO_RULE_MATCH     },
        { .file_name = "/etc",                    .file_type = FT_DIR, .expected_match = RESULT_NO_RULE_MATCH     },
        { .file_name = "/etc/deep/down/0",        .file_type = FT_REG, .expected_match = RESULT_NO_RULE_MATCH     },
    };
    test_rules(add_rules(rules, sizeof(rules)/sizeof(check_seltree_rule_t)), tests, sizeof(tests)/sizeof(check_seltree_test_t));
}
END_TEST

START_TEST (test_unrestricted_recursive_negative_rule_eol) {
    log_msg(LOG_LEVEL_INFO, "test_unrestricted_recursive_negative_rule_eol");
    check_seltree_rule_t rules[] = {
        { .regex = "/dev$",                           .type = AIDE_RECURSIVE_NEGATIVE_RULE,     .restriction = FT_NULL },
        { .regex = "/",                               .type = AIDE_SELECTIVE_RULE,              .restriction = FT_NULL },
    };
    check_seltree_test_t tests[] = {
        { .file_name = "/",                       .file_type = FT_DIR, .expected_match = RESULT_SELECTIVE_MATCH          },
        { .file_name = "/dev",                    .file_type = FT_DIR, .expected_match = RESULT_RECURSIVE_NEGATIVE_MATCH },
        { .file_name = "/dev/sda",                .file_type = FT_BLK, .expected_match = RESULT_SELECTIVE_MATCH          },
        { .file_name = "/dev/pts",                .file_type = FT_DIR, .expected_match = RESULT_SELECTIVE_MATCH          },
        { .file_name = "/dev/pts/0",              .file_type = FT_BLK, .expected_match = RESULT_SELECTIVE_MATCH          },
        { .file_name = "/dev/pts/deep/down/0",    .file_type = FT_DIR, .expected_match = RESULT_SELECTIVE_MATCH          },
        { .file_name = "/etc",                    .file_type = FT_DIR, .expected_match = RESULT_SELECTIVE_MATCH          },
        { .file_name = "/etc/deep/down/0",        .file_type = FT_REG, .expected_match = RESULT_SELECTIVE_MATCH          },
    };
    test_rules(add_rules(rules, sizeof(rules)/sizeof(check_seltree_rule_t)), tests, sizeof(tests)/sizeof(check_seltree_test_t));
}
END_TEST

START_TEST (test_unrestricted_recursive_negative_rule) {
    log_msg(LOG_LEVEL_INFO, "test_unrestricted_recursive_negative_rule");
    check_seltree_rule_t rules[] = {
        { .regex = "/dev",                            .type = AIDE_RECURSIVE_NEGATIVE_RULE,     .restriction = FT_NULL },
        { .regex = "/",                               .type = AIDE_SELECTIVE_RULE,              .restriction = FT_NULL },
    };
    check_seltree_test_t tests[] = {
        { .file_name = "/",                       .file_type = FT_DIR, .expected_match = RESULT_SELECTIVE_MATCH          },
        { .file_name = "/dev",                    .file_type = FT_DIR, .expected_match = RESULT_RECURSIVE_NEGATIVE_MATCH },
        { .file_name = "/dev/sda",                .file_type = FT_BLK, .expected_match = RESULT_RECURSIVE_NEGATIVE_MATCH },
        { .file_name = "/dev/pts",                .file_type = FT_DIR, .expected_match = RESULT_RECURSIVE_NEGATIVE_MATCH },
        { .file_name = "/dev/pts/0",              .file_type = FT_BLK, .expected_match = RESULT_RECURSIVE_NEGATIVE_MATCH },
        { .file_name = "/dev/pts/deep/down/0",    .file_type = FT_DIR, .expected_match = RESULT_RECURSIVE_NEGATIVE_MATCH },
        { .file_name = "/etc",                    .file_type = FT_DIR, .expected_match = RESULT_SELECTIVE_MATCH          },
        { .file_name = "/etc/deep/down/0",        .file_type = FT_REG, .expected_match = RESULT_SELECTIVE_MATCH          },
    };
    test_rules(add_rules(rules, sizeof(rules)/sizeof(check_seltree_rule_t)), tests, sizeof(tests)/sizeof(check_seltree_test_t));
}
END_TEST

START_TEST (test_unrestricted_non_recursive_negative_rule_eol) {
    log_msg(LOG_LEVEL_INFO, "test_unrestricted_non_recursive_negative_rule_eol");
    check_seltree_rule_t rules[] = {
        { .regex = "/dev$",                           .type = AIDE_NON_RECURSIVE_NEGATIVE_RULE, .restriction = FT_NULL },
        { .regex = "/",                               .type = AIDE_SELECTIVE_RULE,              .restriction = FT_NULL },
    };
    check_seltree_test_t tests[] = {
        { .file_name = "/",                       .file_type = FT_DIR, .expected_match = RESULT_SELECTIVE_MATCH              },
        { .file_name = "/dev",                    .file_type = FT_DIR, .expected_match = RESULT_NON_RECURSIVE_NEGATIVE_MATCH },
        { .file_name = "/dev/sda",                .file_type = FT_BLK, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/dev/pts",                .file_type = FT_DIR, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/dev/pts/0",              .file_type = FT_BLK, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/dev/pts/deep/down/0",    .file_type = FT_DIR, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/etc",                    .file_type = FT_DIR, .expected_match = RESULT_SELECTIVE_MATCH              },
        { .file_name = "/etc/deep/down/0",        .file_type = FT_REG, .expected_match = RESULT_SELECTIVE_MATCH              },
    };
    test_rules(add_rules(rules, sizeof(rules)/sizeof(check_seltree_rule_t)), tests, sizeof(tests)/sizeof(check_seltree_test_t));
}
END_TEST

START_TEST (test_unrestricted_non_recursive_negative_rule) {
    log_msg(LOG_LEVEL_INFO, "test_unrestricted_non_recursive_negative_rule");
    check_seltree_rule_t rules[] = {
        { .regex = "/dev",                            .type = AIDE_NON_RECURSIVE_NEGATIVE_RULE, .restriction = FT_NULL },
        { .regex = "/",                               .type = AIDE_SELECTIVE_RULE,              .restriction = FT_NULL },
    };
    check_seltree_test_t tests[] = {
        { .file_name = "/",                       .file_type = FT_DIR, .expected_match = RESULT_SELECTIVE_MATCH              },
        { .file_name = "/dev",                    .file_type = FT_DIR, .expected_match = RESULT_NON_RECURSIVE_NEGATIVE_MATCH },
        { .file_name = "/dev/sda",                .file_type = FT_BLK, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/dev/pts",                .file_type = FT_DIR, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/dev/pts/0",              .file_type = FT_BLK, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/dev/pts/deep/down/0",    .file_type = FT_DIR, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/etc",                    .file_type = FT_DIR, .expected_match = RESULT_SELECTIVE_MATCH              },
        { .file_name = "/etc/deep/down/0",        .file_type = FT_REG, .expected_match = RESULT_SELECTIVE_MATCH              },
    };
    test_rules(add_rules(rules, sizeof(rules)/sizeof(check_seltree_rule_t)), tests, sizeof(tests)/sizeof(check_seltree_test_t));
}
END_TEST

START_TEST (test_unrestricted_recursive_negative_rule_deep_selective) {
    log_msg(LOG_LEVEL_INFO, "test_unrestricted_recursive_negative_rule_deep_selective");
    check_seltree_rule_t rules[] = {
        { .regex = "/dev",                            .type = AIDE_RECURSIVE_NEGATIVE_RULE, .restriction = FT_NULL },
        { .regex = "/dev/pts",                        .type = AIDE_SELECTIVE_RULE,          .restriction = FT_NULL },
    };
    check_seltree_test_t tests[] = {
        { .file_name = "/",                       .file_type = FT_DIR, .expected_match = RESULT_PARTIAL_MATCH            },
        { .file_name = "/dev",                    .file_type = FT_DIR, .expected_match = RESULT_PARTIAL_MATCH            },
        { .file_name = "/dev/sda",                .file_type = FT_BLK, .expected_match = RESULT_NO_RULE_MATCH            },
        { .file_name = "/dev/pts",                .file_type = FT_DIR, .expected_match = RESULT_RECURSIVE_NEGATIVE_MATCH },
        { .file_name = "/dev/pts/0",              .file_type = FT_BLK, .expected_match = RESULT_RECURSIVE_NEGATIVE_MATCH },
        { .file_name = "/dev/pts/deep/down/0",    .file_type = FT_DIR, .expected_match = RESULT_RECURSIVE_NEGATIVE_MATCH },
        { .file_name = "/etc",                    .file_type = FT_DIR, .expected_match = RESULT_NO_RULE_MATCH            },
        { .file_name = "/etc/deep/down/0",        .file_type = FT_REG, .expected_match = RESULT_NO_RULE_MATCH            },
    };
    test_rules(add_rules(rules, sizeof(rules)/sizeof(check_seltree_rule_t)), tests, sizeof(tests)/sizeof(check_seltree_test_t));
}
END_TEST

START_TEST (test_unrestricted_recursive_negative_rule_eol_deep_selective) {
    log_msg(LOG_LEVEL_INFO, "test_unrestricted_recursive_negative_rule_eol_deep_selective");
    check_seltree_rule_t rules[] = {
        { .regex = "/dev$",                           .type = AIDE_RECURSIVE_NEGATIVE_RULE, .restriction = FT_NULL },
        { .regex = "/dev/pts",                        .type = AIDE_SELECTIVE_RULE,          .restriction = FT_NULL },
    };
    check_seltree_test_t tests[] = {
        { .file_name = "/",                       .file_type = FT_DIR, .expected_match = RESULT_PARTIAL_MATCH            },
        { .file_name = "/dev",                    .file_type = FT_DIR, .expected_match = RESULT_PARTIAL_MATCH            },
        { .file_name = "/dev/sda",                .file_type = FT_BLK, .expected_match = RESULT_NO_RULE_MATCH            },
        { .file_name = "/dev/pts",                .file_type = FT_DIR, .expected_match = RESULT_SELECTIVE_MATCH          },
        { .file_name = "/dev/pts/0",              .file_type = FT_BLK, .expected_match = RESULT_SELECTIVE_MATCH          },
        { .file_name = "/dev/pts/deep/down/0",    .file_type = FT_DIR, .expected_match = RESULT_SELECTIVE_MATCH          },
        { .file_name = "/etc",                    .file_type = FT_DIR, .expected_match = RESULT_NO_RULE_MATCH            },
        { .file_name = "/etc/deep/down/0",        .file_type = FT_REG, .expected_match = RESULT_NO_RULE_MATCH            },
    };
    test_rules(add_rules(rules, sizeof(rules)/sizeof(check_seltree_rule_t)), tests, sizeof(tests)/sizeof(check_seltree_test_t));
}
END_TEST

START_TEST (test_unrestricted_non_recursive_negative_rule_deep_selective) {
    log_msg(LOG_LEVEL_INFO, "test_unrestricted_non_recursive_negative_rule_deep_selective");
    check_seltree_rule_t rules[] = {
        { .regex = "/dev",                            .type = AIDE_NON_RECURSIVE_NEGATIVE_RULE, .restriction = FT_NULL },
        { .regex = "/dev/pts",                        .type = AIDE_SELECTIVE_RULE,              .restriction = FT_NULL },
    };
    check_seltree_test_t tests[] = {
        { .file_name = "/",                       .file_type = FT_DIR, .expected_match = RESULT_PARTIAL_MATCH                },
        { .file_name = "/dev",                    .file_type = FT_DIR, .expected_match = RESULT_NON_RECURSIVE_NEGATIVE_MATCH },
        { .file_name = "/dev/sda",                .file_type = FT_BLK, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/dev/pts",                .file_type = FT_DIR, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/dev/pts/0",              .file_type = FT_BLK, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/dev/pts/deep/down/0",    .file_type = FT_DIR, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/etc",                    .file_type = FT_DIR, .expected_match = RESULT_NO_RULE_MATCH                },
        { .file_name = "/etc/deep/down/0",        .file_type = FT_REG, .expected_match = RESULT_NO_RULE_MATCH   },
    };
    test_rules(add_rules(rules, sizeof(rules)/sizeof(check_seltree_rule_t)), tests, sizeof(tests)/sizeof(check_seltree_test_t));
}
END_TEST

START_TEST (test_unrestricted_non_recursive_negative_rule_eol_deep_selective) {
    log_msg(LOG_LEVEL_INFO, "test_unrestricted_non_recursive_negative_rule_eol_deep_selective");
    check_seltree_rule_t rules[] = {
        { .regex = "/dev$",                           .type = AIDE_NON_RECURSIVE_NEGATIVE_RULE, .restriction = FT_NULL },
        { .regex = "/dev/pts",                        .type = AIDE_SELECTIVE_RULE,              .restriction = FT_NULL },
    };
    check_seltree_test_t tests[] = {
        { .file_name = "/",                       .file_type = FT_DIR, .expected_match = RESULT_PARTIAL_MATCH                },
        { .file_name = "/dev",                    .file_type = FT_DIR, .expected_match = RESULT_NON_RECURSIVE_NEGATIVE_MATCH },
        { .file_name = "/dev/sda",                .file_type = FT_BLK, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/dev/pts",                .file_type = FT_DIR, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/dev/pts/0",              .file_type = FT_BLK, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/dev/pts/deep/down/0",    .file_type = FT_DIR, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/etc",                    .file_type = FT_DIR, .expected_match = RESULT_NO_RULE_MATCH                },
        { .file_name = "/etc/deep/down/0",        .file_type = FT_REG, .expected_match = RESULT_NO_RULE_MATCH   },
    };
    test_rules(add_rules(rules, sizeof(rules)/sizeof(check_seltree_rule_t)), tests, sizeof(tests)/sizeof(check_seltree_test_t));
}
END_TEST

START_TEST (test_unrestricted_deep_selective_rule) {
    log_msg(LOG_LEVEL_INFO, "test_unrestricted_deep_selective_rule");
    check_seltree_rule_t rules[] = {
        { .regex = "/dev/.*/[0-9]",               .type = AIDE_SELECTIVE_RULE,              .restriction = FT_NULL },
        { .regex = "/etc/deep/down/0",            .type = AIDE_SELECTIVE_RULE,              .restriction = FT_NULL },
    };
    check_seltree_test_t tests[] = {
        { .file_name = "/",                       .file_type = FT_DIR, .expected_match = RESULT_PARTIAL_MATCH     },
        { .file_name = "/dev",                    .file_type = FT_DIR, .expected_match = RESULT_PARTIAL_MATCH     },
        { .file_name = "/dev/sda",                .file_type = FT_BLK, .expected_match = RESULT_PARTIAL_MATCH     },
        { .file_name = "/dev/pts",                .file_type = FT_DIR, .expected_match = RESULT_PARTIAL_MATCH     },
        { .file_name = "/dev/pts/0",              .file_type = FT_BLK, .expected_match = RESULT_SELECTIVE_MATCH   },
        { .file_name = "/dev/pts/deep/down/0",    .file_type = FT_DIR, .expected_match = RESULT_SELECTIVE_MATCH   },
        { .file_name = "/etc",                    .file_type = FT_DIR, .expected_match = RESULT_PARTIAL_MATCH     },
        { .file_name = "/etc/deep/down/0",        .file_type = FT_REG, .expected_match = RESULT_SELECTIVE_MATCH   },
    };
    test_rules(add_rules(rules, sizeof(rules)/sizeof(check_seltree_rule_t)), tests, sizeof(tests)/sizeof(check_seltree_test_t));
}
END_TEST

START_TEST (test_unrestricted_forbid_root) {
    log_msg(LOG_LEVEL_INFO, "test_unrestricted_forbid_root");
    check_seltree_rule_t rules[] = {
        { .regex = "/dev",            .type = AIDE_SELECTIVE_RULE,              .restriction = FT_NULL },
        { .regex = "/",               .type = AIDE_NON_RECURSIVE_NEGATIVE_RULE, .restriction = FT_NULL },
    };
    check_seltree_test_t tests[] = {
        { .file_name = "/",                       .file_type = FT_DIR, .expected_match = RESULT_NON_RECURSIVE_NEGATIVE_MATCH },
        { .file_name = "/dev",                    .file_type = FT_DIR, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/dev/sda",                .file_type = FT_BLK, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/dev/pts",                .file_type = FT_BLK, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/dev/pts/0",              .file_type = FT_BLK, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/dev/pts/deep/down/0",    .file_type = FT_DIR, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/etc",                    .file_type = FT_DIR, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/etc/deep/down/0",        .file_type = FT_REG, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
    };
    test_rules(add_rules(rules, sizeof(rules)/sizeof(check_seltree_rule_t)), tests, sizeof(tests)/sizeof(check_seltree_test_t));
}
END_TEST

START_TEST (test_f_type_restricted_equal_rule) {
    log_msg(LOG_LEVEL_INFO, "test_f_type_restricted_equal_rule");
    check_seltree_rule_t rules[] = {
        { .regex = "/dev",                              .type = AIDE_EQUAL_RULE,                  .restriction = FT_DIR },
    };
    check_seltree_test_t tests[] = {
        { .file_name = "/",                       .file_type = FT_DIR, .expected_match = RESULT_PARTIAL_MATCH      },
        { .file_name = "/dev",                    .file_type = FT_DIR, .expected_match = RESULT_EQUAL_MATCH        },
        { .file_name = "/dev/sda",                .file_type = FT_BLK, .expected_match = RESULT_NO_RULE_MATCH      },
        { .file_name = "/dev/pts",                .file_type = FT_DIR, .expected_match = RESULT_NO_RULE_MATCH      },
        { .file_name = "/dev/pts/0",              .file_type = FT_BLK, .expected_match = RESULT_NO_RULE_MATCH      },
        { .file_name = "/dev/pts/deep/down/0",    .file_type = FT_DIR, .expected_match = RESULT_NO_RULE_MATCH      },
        { .file_name = "/etc",                    .file_type = FT_DIR, .expected_match = RESULT_NO_RULE_MATCH      },
        { .file_name = "/etc/deep/down/0",        .file_type = FT_REG, .expected_match = RESULT_NO_RULE_MATCH      },
    };
    test_rules(add_rules(rules, sizeof(rules)/sizeof(check_seltree_rule_t)), tests, sizeof(tests)/sizeof(check_seltree_test_t));
}
END_TEST

START_TEST (test_f_type_restricted_equal_rule_slash) {
    log_msg(LOG_LEVEL_INFO, "test_f_type_restricted_equal_rule_slash");
    check_seltree_rule_t rules[] = {
        { .regex = "/dev/",                              .type = AIDE_EQUAL_RULE,                  .restriction = FT_DIR },
    };
    check_seltree_test_t tests[] = {
        { .file_name = "/",                       .file_type = FT_DIR, .expected_match = RESULT_PARTIAL_MATCH     },
        { .file_name = "/dev",                    .file_type = FT_DIR, .expected_match = RESULT_PARTIAL_MATCH     },
        { .file_name = "/dev/sda",                .file_type = FT_BLK, .expected_match = RESULT_PARTIAL_MATCH     },
        { .file_name = "/dev/pts",                .file_type = FT_DIR, .expected_match = RESULT_EQUAL_MATCH       },
        { .file_name = "/dev/pts/0",              .file_type = FT_BLK, .expected_match = RESULT_NO_RULE_MATCH     },
        { .file_name = "/dev/pts/deep/down/0",    .file_type = FT_DIR, .expected_match = RESULT_NO_RULE_MATCH     },
        { .file_name = "/etc",                    .file_type = FT_DIR, .expected_match = RESULT_NO_RULE_MATCH     },
        { .file_name = "/etc/deep/down/0",        .file_type = FT_REG, .expected_match = RESULT_NO_RULE_MATCH     },
    };
    test_rules(add_rules(rules, sizeof(rules)/sizeof(check_seltree_rule_t)), tests, sizeof(tests)/sizeof(check_seltree_test_t));
}
END_TEST

START_TEST (test_f_type_restricted_recursive_negative_rule_eol) {
    log_msg(LOG_LEVEL_INFO, "test_f_type_restricted_recursive_negative_rule_eol");
    check_seltree_rule_t rules[] = {
        { .regex = "/dev$",                           .type = AIDE_RECURSIVE_NEGATIVE_RULE,     .restriction = FT_DIR  },
        { .regex = "/",                               .type = AIDE_SELECTIVE_RULE,              .restriction = FT_NULL },
    };
    check_seltree_test_t tests[] = {
        { .file_name = "/",                       .file_type = FT_DIR, .expected_match = RESULT_SELECTIVE_MATCH          },
        { .file_name = "/dev",                    .file_type = FT_DIR, .expected_match = RESULT_RECURSIVE_NEGATIVE_MATCH },
        { .file_name = "/dev/sda",                .file_type = FT_BLK, .expected_match = RESULT_SELECTIVE_MATCH          },
        { .file_name = "/dev/pts",                .file_type = FT_DIR, .expected_match = RESULT_SELECTIVE_MATCH          },
        { .file_name = "/dev/pts/0",              .file_type = FT_BLK, .expected_match = RESULT_SELECTIVE_MATCH          },
        { .file_name = "/dev/pts/deep/down/0",    .file_type = FT_DIR, .expected_match = RESULT_SELECTIVE_MATCH          },
        { .file_name = "/etc",                    .file_type = FT_DIR, .expected_match = RESULT_SELECTIVE_MATCH          },
        { .file_name = "/etc/deep/down/0",        .file_type = FT_REG, .expected_match = RESULT_SELECTIVE_MATCH          },
    };
    test_rules(add_rules(rules, sizeof(rules)/sizeof(check_seltree_rule_t)), tests, sizeof(tests)/sizeof(check_seltree_test_t));
}
END_TEST

START_TEST (test_f_type_restricted_recursive_negative_rule) {
    log_msg(LOG_LEVEL_INFO, "test_f_type_restricted_recursive_negative_rule");
    check_seltree_rule_t rules[] = {
        { .regex = "/dev",                            .type = AIDE_RECURSIVE_NEGATIVE_RULE,     .restriction = FT_DIR  },
        { .regex = "/",                               .type = AIDE_SELECTIVE_RULE,              .restriction = FT_NULL },
    };
    check_seltree_test_t tests[] = {
        { .file_name = "/",                       .file_type = FT_DIR, .expected_match = RESULT_SELECTIVE_MATCH          },
        { .file_name = "/dev",                    .file_type = FT_DIR, .expected_match = RESULT_RECURSIVE_NEGATIVE_MATCH },
        { .file_name = "/dev/sda",                .file_type = FT_BLK, .expected_match = RESULT_SELECTIVE_MATCH          },
        { .file_name = "/dev/pts",                .file_type = FT_DIR, .expected_match = RESULT_RECURSIVE_NEGATIVE_MATCH },
        { .file_name = "/dev/pts/0",              .file_type = FT_BLK, .expected_match = RESULT_SELECTIVE_MATCH          },
        { .file_name = "/dev/pts/deep/down/0",    .file_type = FT_DIR, .expected_match = RESULT_RECURSIVE_NEGATIVE_MATCH },
        { .file_name = "/etc",                    .file_type = FT_DIR, .expected_match = RESULT_SELECTIVE_MATCH          },
        { .file_name = "/etc/deep/down/0",        .file_type = FT_REG, .expected_match = RESULT_SELECTIVE_MATCH          },
    };
    test_rules(add_rules(rules, sizeof(rules)/sizeof(check_seltree_rule_t)), tests, sizeof(tests)/sizeof(check_seltree_test_t));
}
END_TEST

START_TEST (test_f_type_restricted_non_recursive_negative_rule_eol) {
    log_msg(LOG_LEVEL_INFO, "test_f_type_restricted_non_recursive_negative_rule_eol");
    check_seltree_rule_t rules[] = {
        { .regex = "/dev$",                           .type = AIDE_NON_RECURSIVE_NEGATIVE_RULE, .restriction = FT_DIR  },
        { .regex = "/",                               .type = AIDE_SELECTIVE_RULE,              .restriction = FT_NULL },
    };
    check_seltree_test_t tests[] = {
        { .file_name = "/",                       .file_type = FT_DIR, .expected_match = RESULT_SELECTIVE_MATCH              },
        { .file_name = "/dev",                    .file_type = FT_DIR, .expected_match = RESULT_NON_RECURSIVE_NEGATIVE_MATCH },
        { .file_name = "/dev/sda",                .file_type = FT_BLK, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/dev/pts",                .file_type = FT_DIR, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/dev/pts/0",              .file_type = FT_BLK, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/dev/pts/deep/down/0",    .file_type = FT_DIR, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/etc",                    .file_type = FT_DIR, .expected_match = RESULT_SELECTIVE_MATCH              },
        { .file_name = "/etc/deep/down/0",        .file_type = FT_REG, .expected_match = RESULT_SELECTIVE_MATCH              },
    };
    test_rules(add_rules(rules, sizeof(rules)/sizeof(check_seltree_rule_t)), tests, sizeof(tests)/sizeof(check_seltree_test_t));
}
END_TEST

START_TEST (test_restricted_recursive_negative_rule_deep_selective) {
    log_msg(LOG_LEVEL_INFO, "test_restricted_recursive_negative_rule_deep_selective");
    check_seltree_rule_t rules[] = {
        { .regex = "/dev",                            .type = AIDE_RECURSIVE_NEGATIVE_RULE, .restriction = FT_DIR  },
        { .regex = "/dev/pts",                        .type = AIDE_SELECTIVE_RULE,          .restriction = FT_NULL },
    };
    check_seltree_test_t tests[] = {
        { .file_name = "/",                       .file_type = FT_DIR, .expected_match = RESULT_PARTIAL_MATCH            },
        { .file_name = "/dev",                    .file_type = FT_DIR, .expected_match = RESULT_PARTIAL_MATCH            },
        { .file_name = "/dev/sda",                .file_type = FT_BLK, .expected_match = RESULT_NO_RULE_MATCH            },
        { .file_name = "/dev/pts",                .file_type = FT_DIR, .expected_match = RESULT_RECURSIVE_NEGATIVE_MATCH },
        { .file_name = "/dev/pts/0",              .file_type = FT_BLK, .expected_match = RESULT_SELECTIVE_MATCH          },
        { .file_name = "/dev/pts/deep/down/0",    .file_type = FT_DIR, .expected_match = RESULT_RECURSIVE_NEGATIVE_MATCH },
        { .file_name = "/etc",                    .file_type = FT_DIR, .expected_match = RESULT_NO_RULE_MATCH            },
        { .file_name = "/etc/deep/down/0",        .file_type = FT_REG, .expected_match = RESULT_NO_RULE_MATCH            },
    };
    test_rules(add_rules(rules, sizeof(rules)/sizeof(check_seltree_rule_t)), tests, sizeof(tests)/sizeof(check_seltree_test_t));
}
END_TEST

START_TEST (test_restricted_recursive_negative_rule_eol_deep_selective) {
    log_msg(LOG_LEVEL_INFO, "test_restricted_recursive_negative_rule_eol_deep_selective");
    check_seltree_rule_t rules[] = {
        { .regex = "/dev$",                           .type = AIDE_RECURSIVE_NEGATIVE_RULE, .restriction = FT_DIR  },
        { .regex = "/dev/pts",                        .type = AIDE_SELECTIVE_RULE,          .restriction = FT_NULL },
    };
    check_seltree_test_t tests[] = {
        { .file_name = "/",                       .file_type = FT_DIR, .expected_match = RESULT_PARTIAL_MATCH            },
        { .file_name = "/dev",                    .file_type = FT_DIR, .expected_match = RESULT_PARTIAL_MATCH            },
        { .file_name = "/dev/sda",                .file_type = FT_BLK, .expected_match = RESULT_NO_RULE_MATCH            },
        { .file_name = "/dev/pts",                .file_type = FT_DIR, .expected_match = RESULT_SELECTIVE_MATCH          },
        { .file_name = "/dev/pts/0",              .file_type = FT_BLK, .expected_match = RESULT_SELECTIVE_MATCH          },
        { .file_name = "/dev/pts/deep/down/0",    .file_type = FT_DIR, .expected_match = RESULT_SELECTIVE_MATCH          },
        { .file_name = "/etc",                    .file_type = FT_DIR, .expected_match = RESULT_NO_RULE_MATCH            },
        { .file_name = "/etc/deep/down/0",        .file_type = FT_REG, .expected_match = RESULT_NO_RULE_MATCH            },
    };
    test_rules(add_rules(rules, sizeof(rules)/sizeof(check_seltree_rule_t)), tests, sizeof(tests)/sizeof(check_seltree_test_t));
}
END_TEST

START_TEST (test_restricted_non_recursive_negative_rule_deep_selective) {
    log_msg(LOG_LEVEL_INFO, "test_restricted_non_recursive_negative_rule_deep_selective");
    check_seltree_rule_t rules[] = {
        { .regex = "/dev",                            .type = AIDE_NON_RECURSIVE_NEGATIVE_RULE, .restriction = FT_DIR  },
        { .regex = "/dev/pts",                        .type = AIDE_SELECTIVE_RULE,              .restriction = FT_NULL },
    };
    check_seltree_test_t tests[] = {
        { .file_name = "/",                       .file_type = FT_DIR, .expected_match = RESULT_PARTIAL_MATCH                },
        { .file_name = "/dev",                    .file_type = FT_DIR, .expected_match = RESULT_NON_RECURSIVE_NEGATIVE_MATCH },
        { .file_name = "/dev/sda",                .file_type = FT_BLK, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/dev/pts",                .file_type = FT_DIR, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/dev/pts/0",              .file_type = FT_BLK, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/dev/pts/deep/down/0",    .file_type = FT_DIR, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/etc",                    .file_type = FT_DIR, .expected_match = RESULT_NO_RULE_MATCH                },
        { .file_name = "/etc/deep/down/0",        .file_type = FT_REG, .expected_match = RESULT_NO_RULE_MATCH                },
    };
    test_rules(add_rules(rules, sizeof(rules)/sizeof(check_seltree_rule_t)), tests, sizeof(tests)/sizeof(check_seltree_test_t));
}
END_TEST

START_TEST (test_restricted_non_recursive_negative_rule_eol_deep_selective) {
    log_msg(LOG_LEVEL_INFO, "test_restricted_non_recursive_negative_rule_eol_deep_selective");
    check_seltree_rule_t rules[] = {
        { .regex = "/dev$",                           .type = AIDE_NON_RECURSIVE_NEGATIVE_RULE, .restriction = FT_DIR  },
        { .regex = "/dev/pts",                        .type = AIDE_SELECTIVE_RULE,              .restriction = FT_NULL },
    };
    check_seltree_test_t tests[] = {
        { .file_name = "/",                       .file_type = FT_DIR, .expected_match = RESULT_PARTIAL_MATCH                },
        { .file_name = "/dev",                    .file_type = FT_DIR, .expected_match = RESULT_NON_RECURSIVE_NEGATIVE_MATCH },
        { .file_name = "/dev/sda",                .file_type = FT_BLK, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/dev/pts",                .file_type = FT_DIR, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/dev/pts/0",              .file_type = FT_BLK, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/dev/pts/deep/down/0",    .file_type = FT_DIR, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/etc",                    .file_type = FT_DIR, .expected_match = RESULT_NO_RULE_MATCH                },
        { .file_name = "/etc/deep/down/0",        .file_type = FT_REG, .expected_match = RESULT_NO_RULE_MATCH                },
    };
    test_rules(add_rules(rules, sizeof(rules)/sizeof(check_seltree_rule_t)), tests, sizeof(tests)/sizeof(check_seltree_test_t));
}
END_TEST

START_TEST (test_f_type_restricted_non_recursive_negative_rule) {
    log_msg(LOG_LEVEL_INFO, "test_f_type_restricted_non_recursive_negative_rule");
    check_seltree_rule_t rules[] = {
        { .regex = "/dev",                            .type = AIDE_NON_RECURSIVE_NEGATIVE_RULE, .restriction = FT_DIR  },
        { .regex = "/",                               .type = AIDE_SELECTIVE_RULE,              .restriction = FT_NULL },
    };
    check_seltree_test_t tests[] = {
        { .file_name = "/",                       .file_type = FT_DIR, .expected_match = RESULT_SELECTIVE_MATCH              },
        { .file_name = "/dev",                    .file_type = FT_DIR, .expected_match = RESULT_NON_RECURSIVE_NEGATIVE_MATCH },
        { .file_name = "/dev/sda",                .file_type = FT_BLK, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/dev/pts",                .file_type = FT_DIR, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/dev/pts/0",              .file_type = FT_BLK, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/dev/pts/deep/down/0",    .file_type = FT_DIR, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/etc",                    .file_type = FT_DIR, .expected_match = RESULT_SELECTIVE_MATCH              },
        { .file_name = "/etc/deep/down/0",        .file_type = FT_REG, .expected_match = RESULT_SELECTIVE_MATCH              },
    };
    test_rules(add_rules(rules, sizeof(rules)/sizeof(check_seltree_rule_t)), tests, sizeof(tests)/sizeof(check_seltree_test_t));
}
END_TEST

START_TEST (test_f_type_restricted_deep_selective_rule) {
    log_msg(LOG_LEVEL_INFO, "test_f_type_restricted_deep_selective_rule");
    check_seltree_rule_t rules[] = {
        { .regex = "/dev/.*/[0-9]",               .type = AIDE_SELECTIVE_RULE,              .restriction = FT_BLK },
        { .regex = "/etc/deep/down/0",            .type = AIDE_SELECTIVE_RULE,              .restriction = FT_REG },
    };
    check_seltree_test_t tests[] = {
        { .file_name = "/",                       .file_type = FT_DIR, .expected_match = RESULT_PARTIAL_MATCH     },
        { .file_name = "/dev",                    .file_type = FT_DIR, .expected_match = RESULT_PARTIAL_MATCH     },
        { .file_name = "/dev/sda",                .file_type = FT_BLK, .expected_match = RESULT_PARTIAL_MATCH     },
        { .file_name = "/dev/pts",                .file_type = FT_BLK, .expected_match = RESULT_PARTIAL_MATCH     },
        { .file_name = "/dev/pts/0",              .file_type = FT_BLK, .expected_match = RESULT_SELECTIVE_MATCH   },
        { .file_name = "/dev/pts/deep/down/0",    .file_type = FT_DIR, .expected_match = RESULT_PARTIAL_MATCH     },
        { .file_name = "/etc",                    .file_type = FT_DIR, .expected_match = RESULT_PARTIAL_MATCH     },
        { .file_name = "/etc/deep/down/0",        .file_type = FT_REG, .expected_match = RESULT_SELECTIVE_MATCH   },
    };
    test_rules(add_rules(rules, sizeof(rules)/sizeof(check_seltree_rule_t)), tests, sizeof(tests)/sizeof(check_seltree_test_t));
}
END_TEST

START_TEST (test_f_type_restricted_forbid_root) {
    log_msg(LOG_LEVEL_INFO, "test_f_type_restricted_forbid_root");
    check_seltree_rule_t rules[] = {
        { .regex = "/dev",            .type = AIDE_SELECTIVE_RULE,              .restriction = FT_BLK },
        { .regex = "/",               .type = AIDE_NON_RECURSIVE_NEGATIVE_RULE, .restriction = FT_DIR },
    };
    check_seltree_test_t tests[] = {
        { .file_name = "/",                       .file_type = FT_DIR, .expected_match = RESULT_NON_RECURSIVE_NEGATIVE_MATCH },
        { .file_name = "/dev",                    .file_type = FT_DIR, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/dev/sda",                .file_type = FT_BLK, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/dev/pts",                .file_type = FT_BLK, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/dev/pts/0",              .file_type = FT_BLK, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/dev/pts/deep/down/0",    .file_type = FT_DIR, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/etc",                    .file_type = FT_DIR, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
        { .file_name = "/etc/deep/down/0",        .file_type = FT_REG, .expected_match = RESULT_NEGATIVE_PARENT_MATCH        },
    };
    test_rules(add_rules(rules, sizeof(rules)/sizeof(check_seltree_rule_t)), tests, sizeof(tests)/sizeof(check_seltree_test_t));
}
END_TEST

Suite *make_seltree_suite(void) {

    Suite *s = suite_create ("seltree");

    TCase *tc_check_seltree = tcase_create ("check_seltree");

    tcase_add_test(tc_check_seltree, test_unrestricted_equal_rule);
    tcase_add_test(tc_check_seltree, test_unrestricted_equal_rule_slash);
    tcase_add_test(tc_check_seltree, test_unrestricted_recursive_negative_rule_eol);
    tcase_add_test(tc_check_seltree, test_unrestricted_recursive_negative_rule);
    tcase_add_test(tc_check_seltree, test_unrestricted_non_recursive_negative_rule_eol);
    tcase_add_test(tc_check_seltree, test_unrestricted_non_recursive_negative_rule);
    tcase_add_test(tc_check_seltree, test_unrestricted_recursive_negative_rule_deep_selective);
    tcase_add_test(tc_check_seltree, test_unrestricted_recursive_negative_rule_eol_deep_selective);
    tcase_add_test(tc_check_seltree, test_unrestricted_non_recursive_negative_rule_deep_selective);
    tcase_add_test(tc_check_seltree, test_unrestricted_non_recursive_negative_rule_eol_deep_selective);
    tcase_add_test(tc_check_seltree, test_unrestricted_deep_selective_rule);
    tcase_add_test(tc_check_seltree, test_unrestricted_forbid_root);

    tcase_add_test(tc_check_seltree, test_f_type_restricted_equal_rule);
    tcase_add_test(tc_check_seltree, test_f_type_restricted_equal_rule_slash);
    tcase_add_test(tc_check_seltree, test_f_type_restricted_recursive_negative_rule_eol);
    tcase_add_test(tc_check_seltree, test_f_type_restricted_recursive_negative_rule);
    tcase_add_test(tc_check_seltree, test_f_type_restricted_non_recursive_negative_rule_eol);
    tcase_add_test(tc_check_seltree, test_f_type_restricted_non_recursive_negative_rule);
    tcase_add_test(tc_check_seltree, test_restricted_recursive_negative_rule_deep_selective);
    tcase_add_test(tc_check_seltree, test_restricted_recursive_negative_rule_eol_deep_selective);
    tcase_add_test(tc_check_seltree, test_restricted_non_recursive_negative_rule_deep_selective);
    tcase_add_test(tc_check_seltree, test_restricted_non_recursive_negative_rule_eol_deep_selective);
    tcase_add_test(tc_check_seltree, test_f_type_restricted_deep_selective_rule);
    tcase_add_test(tc_check_seltree, test_f_type_restricted_forbid_root);

    set_log_level(LOG_LEVEL_DEBUG);
    set_colored_log(false);

    suite_add_tcase (s, tc_check_seltree);

    return s;
}
