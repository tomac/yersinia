/* $Id: md5.h 2 2006-04-03 21:04:25Z tomac $ */

#ifndef MD5_H
#define MD5_H

#ifdef SOLARIS
typedef uint32_t u_int32_t;
typedef uint16_t u_int16_t;
typedef uint8_t  u_int8_t;
#endif


struct MD5Context {
	u_int32_t buf[4];
	u_int32_t bits[2];
	unsigned char in[64];
};

void MD5Init(struct MD5Context *context);
void MD5Update(struct MD5Context *context, unsigned char const *buf,
	       unsigned len);
void MD5Final(unsigned char digest[16], struct MD5Context *context);
void MD5Transform(u_int32_t buf[4], u_int32_t const in[16]);

#ifdef REMARK
/* This' been commented out because it conflicts with openssl */

/*
 * This is needed to make RSAREF happy on some MS-DOS compilers.
 */
typedef struct MD5Context MD5_CTX;

#endif /* REMARK */

#endif /* !MD5_H */
/* vim:set tabstop=4:set expandtab:set shiftwidth=4:set textwidth=78: */
