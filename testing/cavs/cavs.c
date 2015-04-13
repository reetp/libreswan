/*
 * Copyright (C) 2015, Stephan Mueller <smueller@chronox.de>
 * Copyright (C) 2015, Andrew Cagney
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU General Public License, in which case the provisions of the GPL2
 * are required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>

#include "constants.h"
#include "lswalloc.h"
#include "ike_alg.h"
#include "crypto.h"
#include "ikev2_prf.h"
#include "crypt_prf.h"
#include "crypt_symkey.h"
#include "test_buffer.h"
#include "libreswan/passert.h"

libreswan_passert_fail_t libreswan_passert_fail;
enum kernel_interface kern_interface;
extern void exit_pluto(int status);
void exit_pluto(int status UNUSED) { }
extern void show_setup_plutomain();
void show_setup_plutomain() { }
extern char *pluto_listen;
char *pluto_listen = NULL;
deltatime_t crl_check_interval = { 0 };

static void usage(void)
{
	fprintf(stderr, "\nLibreswan KDF CAVS Test\n\n");
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\t-g --gir\tDiffie-Hellman shared secret\n");
	fprintf(stderr, "\t-n --girnew\tDiffie-Hellman shared secret (rekey)\n");
	fprintf(stderr, "\t-a --ni\t\tNi value\n");
	fprintf(stderr, "\t-b --nr\t\tNr value\n");
	fprintf(stderr, "\t-c --spii\tSPIi value\n");
	fprintf(stderr, "\t-d --spir\tSPIr value\n");
	fprintf(stderr, "\t-l --dkmlen\tLength of DKM\n");
	fprintf(stderr, "\t-h --hash\tHash algorithm:???\n");
	fprintf(stderr, "\t\t\t2 -> SHA-1\n");
	fprintf(stderr, "\t\t\t5 -> SHA-256\n");
	fprintf(stderr, "\t\t\t6 -> SHA-384\n");
	fprintf(stderr, "\t\t\t7 -> SHA-512\n");
}

static void print_symkey(const char *prefix, PK11SymKey *key, size_t binlen)
{
	printf("%s = ", prefix);
	chunk_t chunk = chunk_from_symkey_bytes(prefix, key, 0,
						PK11_GetKeyLength(key));
	size_t chars = binlen == 0 ? chunk.len
		: binlen < chunk.len ? binlen
		: chunk.len;
	
	size_t i = 0;
	for (i = 0; i <  chars; i++) {
		printf("%02x", chunk.ptr[i]);
	}	
	freeanychunk(chunk);
	printf("\n");
}

struct kdf_cavs {
	chunk_t gir;
	chunk_t girnew;
	chunk_t Ni;
	chunk_t Nr;
	chunk_t SPIi;
	chunk_t SPIr;
	/*
	 * according to include/ietf_constants.h:
	 * 	IKEv2_PRF_HMAC_SHA1 2
	 * 	IKEv2_PRF_HMAC_SHA2_256 -> 5
	 * 	IKEv2_PRF_HMAC_SHA2_384 -> 6
	 * 	IKEv2_PRF_HMAC_SHA2_512 -> 7
	 */
	unsigned int hash_algo;

	unsigned int dkmlen;
};

static int ikev2kdf_cavs(struct kdf_cavs *test)
{
	struct hash_desc *hasher = (struct hash_desc *)
		ike_alg_get_hasher(test->hash_algo);

	/* SKEYSEED = prf(Ni | Nr, g^ir) */
	PK11SymKey *gir = chunk_to_key(CKM_DH_PKCS_DERIVE, test->gir);
	PK11SymKey *skeyseed =
		ikev2_ike_sa_skeyseed(hasher, test->Ni, test->Nr, gir);
	print_symkey("SKEYSEED", skeyseed, 0);

	/* prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr) */
	PK11SymKey *dkm =
		ikev2_ike_sa_keymat(hasher, skeyseed,
				    test->Ni, test->Nr,
				    test->SPIi, test->SPIr,
				    test->dkmlen);
	print_symkey("DKM", dkm, test->dkmlen);

	/* prf+(SK_d, Ni | Nr) */
	PK11SymKey *SK_d = key_from_symkey_bytes(dkm, 0, hasher->hash_digest_len);
	PK11SymKey *dkm_child_sa =
		ikev2_child_sa_keymat(hasher, SK_d, NULL, test->Ni, test->Nr,
				      test->dkmlen);
	print_symkey("DKM(Child SA)", dkm_child_sa, test->dkmlen);

	/* prf+(SK_d, g^ir (new) | Ni | Nr) */
	PK11SymKey *girnew = chunk_to_key(CKM_DH_PKCS_DERIVE, test->girnew);
	PK11SymKey *dkm_child_sa_dh =
		ikev2_child_sa_keymat(hasher, SK_d, girnew,
				      test->Ni, test->Nr,
				      test->dkmlen);
	print_symkey("DKM(Child SA D-H)", dkm_child_sa_dh, test->dkmlen);

	/* prf(SK_d (old), g^ir (new) | Ni | Nr) */
	PK11SymKey *skeyseed_rekey =
		ikev2_ike_sa_rekey_skeyseed(hasher, SK_d, girnew,
					    test->Ni, test->Nr);
	print_symkey("SKEYSEED(Rekey)", skeyseed_rekey, 0);

	return 0;
}

/*
 *./libreswan-ikev2-cavs -g 4b2c1f971981a8ad8d0abeafabf38cf75fc8349c148142465ed9c8b516b8be52 -n 863f3c9d06efd39d2b907b97f8699e5dd5251ef64a2a176f36ee40c87d4f9330 -a 32b50d5f4a3763f3 -b 9206a04b26564cb1 -c 34c9e7c188868785 -d 3ff77d760d2b2199 -l 132 -h 2
 *
SKEYSEED = a9a7b222b59f8f48645f28a1db5b5f5d7479cba7
DKM = a14293677cc80ff8f9cc0eee30d895da9d8f405666e30ef0dfcb63c634a46002a2a63080e514a062768b76606f9fa5e992204fc5a670bde3f10d6b027113936a5c55b648a194ae587b0088d52204b702c979fa280870d2ed41efa9c549fd11198af1670b143d384bd275c5f594cf266b05ebadca855e4249520a441a81157435a7a56cc4
DKM(Child SA) = 8059e3ee8810e6c3a91bc8bcd2a7a41151b8d0e6ae239c7b38093ad85ef4c5811a8e7b5d1cdabd9560b2d5e092d1f24e2d4b85eccdf0ad0dc9abd94b51ee71814ca6dbc8bb51b6309f5b9545c7eb35cf5580b1e521a8fe20754a2d883ba0c2cf285f524aea6545b33106bc03e614296d319d41d4b50b3f510b1c0a22f3e664994d234cb4
DKM(Child SA D-H) = bb43244c1860ad65ee1e211ffe8bb3661750c8f89cb9f547df7f4fa61d37301628190e38c66232eab4b3ab14c400a5197dd3730ed4820a8a10394d51e1c0400052f63ebd36b0e7ef53aaed31eba4a5080d7d4b5666023a8bbb5ffb7857240f9a05884d1b7d2f933708450b7b3288f1fc863ab49fa901227cffc06e27899c7054d56fd74c
SKEYSEED(Rekey) = 63e81194946ebd05df7df5ebf5d8750056bf1f1d
 */
int main(int argc, char *argv[])
{
	NSS_NoDB_Init(".");
	init_crypto();

	struct kdf_cavs test;
	int ret = 1;
	int c = 0;

	memset(&test, 0, sizeof(struct kdf_cavs));
	while(1)
	{
		int opt_index = 0;
		static struct option opts[] =
		{
			{"gir", 1, 0, 'g'},
			{"girnew", 1, 0, 'n'},
			{"ni", 1, 0, 'a'},
			{"nr", 1, 0, 'b'},
			{"spii", 1, 0, 'c'},
			{"spir", 1, 0, 'd'},
			{"dkmlen", 1, 0, 'l'},
			{"hash", 1, 0, 'h'},
			{0, 0, 0, 0}
		};
		c = getopt_long(argc, argv, "g:n:a:b:c:d:l:h:", opts, &opt_index);
		if(-1 == c)
			break;
		switch(c)
		{
			case 'g':
				test.gir = decode_hex_to_chunk("gir", optarg);
				break;
			case 'n':
				test.girnew = decode_hex_to_chunk("girnew", optarg);
				break;
			case 'a':
				test.Ni = decode_hex_to_chunk("Ni", optarg);
				break;
			case 'b':
				test.Nr = decode_hex_to_chunk("Nr", optarg);
				break;
			case 'c':
				test.SPIi = decode_hex_to_chunk("SPIi", optarg);
				break;
			case 'd':
				test.SPIr = decode_hex_to_chunk("SPIr", optarg);
				break;
			case 'l':
				test.dkmlen = strtoul(optarg, NULL, 10);
				break;
			case 'h':
				test.hash_algo = atoi(optarg);
				switch (test.hash_algo) {
					case 2:
					case 5:
					case 6:
					case 7:
						continue;
				}
				/* fall through */
			default:
				usage();
				goto out;
		}
	}

	ret = ikev2kdf_cavs(&test);

out:
	freeanychunk(test.gir);
	freeanychunk(test.girnew);
	freeanychunk(test.Ni);
	freeanychunk(test.Nr);
	freeanychunk(test.SPIi);
	freeanychunk(test.SPIr);
	return ret;
}
