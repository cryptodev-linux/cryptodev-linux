/* ---- PRNG Stuff ---- */

typedef union Prng_state {
	char dummy[1];
} prng_state;

/** PRNG descriptor */
extern struct ltc_prng_descriptor {
    /** Name of the PRNG */
	char *name;
    /** size in bytes of exported state */
	int export_size;
    /** Start a PRNG state
        @param prng   [out] The state to initialize
        @return CRYPT_OK if successful
    */
	int (*start) (prng_state * prng);
    /** Add entropy to the PRNG
        @param in         The entropy
        @param inlen      Length of the entropy (octets)\
        @param prng       The PRNG state
        @return CRYPT_OK if successful
    */
	int (*add_entropy) (const unsigned char *in, unsigned long inlen,
			    prng_state * prng);
    /** Ready a PRNG state to read from
        @param prng       The PRNG state to ready
        @return CRYPT_OK if successful
    */
	int (*ready) (prng_state * prng);
    /** Read from the PRNG
        @param out     [out] Where to store the data
        @param outlen  Length of data desired (octets)
        @param prng    The PRNG state to read from
        @return Number of octets read
    */
	unsigned long (*read) (unsigned char *out, unsigned long outlen,
			       prng_state * prng);
    /** Terminate a PRNG state
        @param prng   The PRNG state to terminate
        @return CRYPT_OK if successful
    */
	int (*done) (prng_state * prng);
    /** Export a PRNG state  
        @param out     [out] The destination for the state
        @param outlen  [in/out] The max size and resulting size of the PRNG state
        @param prng    The PRNG to export
        @return CRYPT_OK if successful
    */
	int (*pexport) (unsigned char *out, unsigned long *outlen,
			prng_state * prng);
    /** Import a PRNG state
        @param in      The data to import
        @param inlen   The length of the data to import (octets)
        @param prng    The PRNG to initialize/import
        @return CRYPT_OK if successful
    */
	int (*pimport) (const unsigned char *in, unsigned long inlen,
			prng_state * prng);
    /** Self-test the PRNG
        @return CRYPT_OK if successful, CRYPT_NOP if self-testing has been disabled
    */
	int (*test) (void);
} prng_descriptor[];

int linux_start(prng_state * prng);
int linux_add_entropy(const unsigned char *in, unsigned long inlen,
		      prng_state * prng);
int linux_ready(prng_state * prng);
unsigned long linux_read(unsigned char *out, unsigned long outlen,
			 prng_state * prng);
int linux_done(prng_state * prng);
int linux_export(unsigned char *out, unsigned long *outlen, prng_state * prng);
int linux_import(const unsigned char *in, unsigned long inlen,
		 prng_state * prng);
int linux_test(void);

extern const struct ltc_prng_descriptor linux_desc;

int find_prng(const char *name);
int register_prng(const struct ltc_prng_descriptor *prng);
int unregister_prng(const struct ltc_prng_descriptor *prng);
int prng_is_valid(int idx);

/* $Source: /cvs/libtom/libtomcrypt/src/headers/tomcrypt_prng.h,v $ */
/* $Revision: 1.9 $ */
/* $Date: 2007/05/12 14:32:35 $ */
