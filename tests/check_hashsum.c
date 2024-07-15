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

#include "attributes.h"
#include "hashsum.h"
#include "md.h"
#include "util.h"

typedef struct {
    size_t size;
    char expected[num_hashes][128 + 1];
} hashsum_test_t;

static char *message = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";

static hashsum_test_t hashsum_tests[] = {
    { .size = 0, .expected = {
                                "d41d8cd98f00b204e9800998ecf8427e",  /* md5 */
                                "da39a3ee5e6b4b0d3255bfef95601890afd80709",  /* sha1 */
                                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  /* sha256 */
                                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",  /* sha512 */
                                "9c1185a5c5e9fc54612808977ee8f548b2258d31",  /* rmd160 */
                                "24f0130c63ac933216166e76b1bb925ff373de2d49584e7a",  /* tiger */
                                "00000000",  /* crc32 */
                                "00000000",  /* crc32b */
                                "4f6938531f0bc8991f62da7bbd6f7de3fad44562b8c6f4ebf146d5b4e46f7c17",  /* haval */
                                "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3",  /* whirlpool */
                                "ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d",  /* gost */
                                "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb",  /* stribog256 */
                                "8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a",  /* stribog512 */
                                "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",  /* sha512_256 */
                                "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",  /* sha3-256 */
                                "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",  /* sha3-512 */
                             }
    },
    { .size = 12, .expected = {
                                "2b0dc568e588e46a5a7cd56dcec348af",  /* md5 */
                                "2aa36a1111059c0bbd7ad0c6bba108f50df8e867",  /* sha1 */
                                "922429ccdb7045d11143e2e3982a11afc11b537bf259d88d2425fa8806e86e78",  /* sha256 */
                                "5d8b766d3b37ce8aa68dd354a50af9c94201286d7993d42e20bb7a93c0cc9897fd2714a2860ec8c4d79912376c8234dfb52e841eff0eb960370a84ea5735e8b3",  /* sha512 */
                                "14d3deb9667ab31c0f76a57ef5055f29f4bc432e",  /* rmd160 */
                                "0c26dd2215a6d6168ece5bce5a8d02afcfcd57c4759da8e5",  /* tiger */
                                "634a5234",  /* crc32 */
                                "34524a63",  /* crc32b */
                                "3e3ae002124d7fabd23b04e596bbaab7760ad02b9d46ae761a724c3a0751e143",  /* haval */
                                "8535c1b311244a56aba746411d74b1a2bafe1238983def9da7aaa61e3e80d365ab00d7be6753341b45ade19d858d2b9f8a0cf27a5a7b2ff77952b8a780d8d587",  /* whirlpool */
                                "5ecd800c05dea7b6badd7aba7e329c7aca5b42e38784b6a0efb83bd65a7c50ec",  /* gost */
                                "c367afdb2a05726b46f82e1cd32d6a8cb06c7a03b5cebfc94df0d1a4153e90af",  /* stribog256 */
                                "f4d24b77221fe6734eaefe2c85899ba7dc66f88be0fbde61f4a9e34198f606501ac67ad246d0f44e4722b42c5837d0c0af5e0a32d3f891ee8dd90e6dceef7f9b",  /* stribog512 */
                                "e39ab44f3128533b5a3092a13c6de7e759f0d048a58df860fe3d9d5341e1b507",  /* sha512_256 */
                                "d99428764cc43a2ff5c1ac4db1e5da826a97dae5530e268650318adb2e2e246f",  /* sha3-256 */
                                "644f8950457497a7ad3b89ff1bae0d5104604dfe7191b95fed4750a551bb0705173fba66cb71bac5e89dbef418096a76f74db060298c3e2ab54a3513fe50b9ea",  /* sha3-512 */
                             }
    },
    { .size = 62, .expected = {
                                "bef25ba0f6a4d8f8ec8d5d5122241a10",  /* md5 */
                                "bb814cf15cf9478829e6b85205824b0f1fd8ca08",  /* sha1 */
                                "4931ea748296a1cd4fed8cf6275ecb0f2df8e11bafa9457b9ab62c47bc0bc2df",  /* sha256 */
                                "509fdf28fefbc5ef33e88ef0b239115ab620ed1e94a7adf95549b03f23359c9a38131ad8056957c279e8f74b9c23feba57bd6501bb2d06546398242079fefbb7",  /* sha512 */
                                "93a67b62a5e060ef799259c41430c49f9a4e0a10",  /* rmd160 */
                                "266b9f823d34ec3acf51ce37f28040f885cd24494c9a682b",  /* tiger */
                                "9f5b8ff1",  /* crc32 */
                                "f18f5b9f",  /* crc32b */
                                "46d100b49ce74d6a1a02af140f3720d9d65bde7342b36ca3c92fcf893451f021",  /* haval */
                                "fc63bb82de354304a63af835e2596136639f365aec5be609a4a1264fa496c4a5eadb3d615d9f9c06f3aa9eb4654780b461b51b79ad25a15aebe1033babc120c8",  /* whirlpool */
                                "8fd10ed0d94fbacef168095b733cc82ba091e98f1947b12cb46090dafa345150",  /* gost */
                                "82985767032f0a24c7b0be97daf3fde20b0a26c58ba0fc629488f0006b061c05",  /* stribog256 */
                                "11115c0e8f26b6c9ad6b94f04c7fb4269c32c9ef841c10068df1f0a0f031df3b010bcbd6442e1f4ac35ea50e5a01f96e1a196ae9654da51cb7dec4daf22aed23",  /* stribog512 */
                                "f288ffd88561cb7fa728dbaa80fe195016a188959be61f1c297826fec2a11864",  /* sha512_256 */
                                "4d877e02ff6f9ffdf4fe894a5814fb8836db7b1e18f8c94788cf8144d6eca616",  /* sha3-256 */
                                "15b6d95c749b322c9d91e92bc5498cdabe0919fb7a7d3d7f9940092077e61370f96b46079b4858ee14906c929d0217acaf58d3fa8c2d622b29a95dd643978cd6",  /* sha3-512 */
                             }
    },
};

static int num_hashsum_tests = sizeof hashsum_tests / sizeof(hashsum_test_t);

START_TEST(test_hashsum) {
    char *dummy_filename = "<test:check_hashsum>";
    md_hashsums md;

    struct md_container mdc;
    mdc.todo_attr = get_hashes(false);
    init_md(&mdc, dummy_filename);
    update_md(&mdc, message, hashsum_tests[_i].size);
    close_md(&mdc, &md, dummy_filename);

    for (int i = 0; i < num_hashes; ++i) {
        if (algorithms[i] >= 0) {
            char *hashsum = byte_to_base16(md.hashsums[i], hashsums[i].length);
            ck_assert_msg(stricmp(hashsum, hashsum_tests[_i].expected[i]) == 0,
                          "\n"
                          "%10s hashsum retruned: %s\n"
                          "                   expected: %s",
                          attributes[hashsums[i].attribute].config_name, hashsum, hashsum_tests[_i].expected[i]);
            free(hashsum);
        }
    }
}
END_TEST

Suite *make_hashsum_suite(void) {

    Suite *s = suite_create("hashsum");

    TCase *tc_hashsum = tcase_create("hashsum");

    tcase_add_loop_test(tc_hashsum, test_hashsum, 0, num_hashsum_tests);

    suite_add_tcase(s, tc_hashsum);

    return s;
}
