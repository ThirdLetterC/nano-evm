#include <gmp.h>
#include <stddef.h>
#include <stdint.h>

#include "bn254_pairing.h"

typedef struct {
  mpz_t x;
  mpz_t y;
} bn254_pair_fp2_t;

typedef struct {
  bn254_pair_fp2_t x;
  bn254_pair_fp2_t y;
  bn254_pair_fp2_t z;
} bn254_pair_fp6_t;

typedef struct {
  bn254_pair_fp6_t x;
  bn254_pair_fp6_t y;
} bn254_pair_fp12_t;

typedef struct {
  mpz_t x;
  mpz_t y;
  mpz_t z;
  mpz_t t;
} bn254_pair_g1_t;

typedef struct {
  bn254_pair_fp2_t x;
  bn254_pair_fp2_t y;
  bn254_pair_fp2_t z;
  bn254_pair_fp2_t t;
} bn254_pair_g2_t;

typedef struct {
  mpz_t field_modulus;
  mpz_t group_order;
  mpz_t bn_u;
  bn254_pair_fp2_t xi;
  bn254_pair_fp2_t xi_to_p_minus_1_over_6;
  bn254_pair_fp2_t xi_to_p_minus_1_over_3;
  bn254_pair_fp2_t xi_to_p_minus_1_over_2;
  bn254_pair_fp2_t xi_to_2p_minus_2_over_3;
  bn254_pair_fp2_t xi_to_psquared_minus_1_over_3;
  bn254_pair_fp2_t xi_to_2psquared_minus_2_over_3;
  bn254_pair_fp2_t xi_to_psquared_minus_1_over_6;
  bn254_pair_fp2_t twist_b;
  int8_t six_u_plus_2_naf[192];
  size_t six_u_plus_2_naf_len;
} bn254_pair_ctx_t;

static void bn254_pair_fp2_init(bn254_pair_fp2_t *value) {
  mpz_init(value->x);
  mpz_init(value->y);
}

static void bn254_pair_fp2_clear(bn254_pair_fp2_t *value) {
  mpz_clear(value->x);
  mpz_clear(value->y);
}

static void bn254_pair_fp2_set(bn254_pair_fp2_t *out,
                               const bn254_pair_fp2_t *in) {
  mpz_set(out->x, in->x);
  mpz_set(out->y, in->y);
}

static void bn254_pair_fp2_set_zero(bn254_pair_fp2_t *out) {
  mpz_set_ui(out->x, 0U);
  mpz_set_ui(out->y, 0U);
}

static void bn254_pair_fp2_set_one(bn254_pair_fp2_t *out) {
  mpz_set_ui(out->x, 0U);
  mpz_set_ui(out->y, 1U);
}

static bool bn254_pair_fp2_is_zero(const bn254_pair_fp2_t *value) {
  return mpz_sgn(value->x) == 0 && mpz_sgn(value->y) == 0;
}

static bool bn254_pair_fp2_is_one(const bn254_pair_fp2_t *value) {
  return mpz_sgn(value->x) == 0 && mpz_cmp_ui(value->y, 1U) == 0;
}

static void bn254_pair_mod(mpz_t value, const mpz_t modulus) {
  mpz_mod(value, value, modulus);
}

static void bn254_pair_fp2_conjugate(bn254_pair_fp2_t *out,
                                     const bn254_pair_fp2_t *in,
                                     const mpz_t field_modulus) {
  mpz_neg(out->x, in->x);
  bn254_pair_mod(out->x, field_modulus);
  mpz_set(out->y, in->y);
  bn254_pair_mod(out->y, field_modulus);
}

static void bn254_pair_fp2_negative(bn254_pair_fp2_t *out,
                                    const bn254_pair_fp2_t *in,
                                    const mpz_t field_modulus) {
  mpz_neg(out->x, in->x);
  bn254_pair_mod(out->x, field_modulus);
  mpz_neg(out->y, in->y);
  bn254_pair_mod(out->y, field_modulus);
}

static void bn254_pair_fp2_add(bn254_pair_fp2_t *out, const bn254_pair_fp2_t *a,
                               const bn254_pair_fp2_t *b,
                               const mpz_t field_modulus) {
  mpz_add(out->x, a->x, b->x);
  bn254_pair_mod(out->x, field_modulus);
  mpz_add(out->y, a->y, b->y);
  bn254_pair_mod(out->y, field_modulus);
}

static void bn254_pair_fp2_sub(bn254_pair_fp2_t *out, const bn254_pair_fp2_t *a,
                               const bn254_pair_fp2_t *b,
                               const mpz_t field_modulus) {
  mpz_sub(out->x, a->x, b->x);
  bn254_pair_mod(out->x, field_modulus);
  mpz_sub(out->y, a->y, b->y);
  bn254_pair_mod(out->y, field_modulus);
}

static void bn254_pair_fp2_double(bn254_pair_fp2_t *out,
                                  const bn254_pair_fp2_t *in,
                                  const mpz_t field_modulus) {
  mpz_mul_ui(out->x, in->x, 2U);
  bn254_pair_mod(out->x, field_modulus);
  mpz_mul_ui(out->y, in->y, 2U);
  bn254_pair_mod(out->y, field_modulus);
}

static void bn254_pair_fp2_mul(bn254_pair_fp2_t *out, const bn254_pair_fp2_t *a,
                               const bn254_pair_fp2_t *b,
                               const mpz_t field_modulus) {
  mpz_t tx;
  mpz_t ty;
  mpz_t tmp;
  mpz_inits(tx, ty, tmp, (mpz_ptr)nullptr);

  mpz_mul(tx, a->x, b->y);
  mpz_mul(tmp, b->x, a->y);
  mpz_add(tx, tx, tmp);
  bn254_pair_mod(tx, field_modulus);

  mpz_mul(ty, a->y, b->y);
  mpz_mul(tmp, a->x, b->x);
  mpz_sub(ty, ty, tmp);
  bn254_pair_mod(ty, field_modulus);

  mpz_set(out->x, tx);
  mpz_set(out->y, ty);

  mpz_clears(tx, ty, tmp, (mpz_ptr)nullptr);
}

static void bn254_pair_fp2_mul_scalar(bn254_pair_fp2_t *out,
                                      const bn254_pair_fp2_t *a,
                                      const mpz_t scalar,
                                      const mpz_t field_modulus) {
  mpz_mul(out->x, a->x, scalar);
  bn254_pair_mod(out->x, field_modulus);
  mpz_mul(out->y, a->y, scalar);
  bn254_pair_mod(out->y, field_modulus);
}

static void bn254_pair_fp2_mul_xi(bn254_pair_fp2_t *out,
                                  const bn254_pair_fp2_t *a,
                                  const mpz_t field_modulus) {
  // xi = i + 9.
  mpz_t tx;
  mpz_t ty;
  mpz_inits(tx, ty, (mpz_ptr)nullptr);

  mpz_mul_ui(tx, a->x, 9U);
  mpz_add(tx, tx, a->y);
  bn254_pair_mod(tx, field_modulus);

  mpz_mul_ui(ty, a->y, 9U);
  mpz_sub(ty, ty, a->x);
  bn254_pair_mod(ty, field_modulus);

  mpz_set(out->x, tx);
  mpz_set(out->y, ty);

  mpz_clears(tx, ty, (mpz_ptr)nullptr);
}

static void bn254_pair_fp2_square(bn254_pair_fp2_t *out,
                                  const bn254_pair_fp2_t *a,
                                  const mpz_t field_modulus) {
  mpz_t t1;
  mpz_t t2;
  mpz_t ty;
  mpz_inits(t1, t2, ty, (mpz_ptr)nullptr);

  mpz_sub(t1, a->y, a->x);
  mpz_add(t2, a->x, a->y);
  mpz_mul(ty, t1, t2);
  bn254_pair_mod(ty, field_modulus);

  mpz_mul(t1, a->x, a->y);
  mpz_mul_ui(t1, t1, 2U);
  bn254_pair_mod(t1, field_modulus);

  mpz_set(out->x, t1);
  mpz_set(out->y, ty);

  mpz_clears(t1, t2, ty, (mpz_ptr)nullptr);
}

static bool bn254_pair_fp2_invert(bn254_pair_fp2_t *out,
                                  const bn254_pair_fp2_t *a,
                                  const mpz_t field_modulus) {
  mpz_t t;
  mpz_t t2;
  mpz_t inv;
  mpz_inits(t, t2, inv, (mpz_ptr)nullptr);

  mpz_mul(t, a->y, a->y);
  mpz_mul(t2, a->x, a->x);
  mpz_add(t, t, t2);
  bn254_pair_mod(t, field_modulus);

  if (mpz_invert(inv, t, field_modulus) == 0) {
    mpz_clears(t, t2, inv, (mpz_ptr)nullptr);
    return false;
  }

  mpz_neg(out->x, a->x);
  mpz_mul(out->x, out->x, inv);
  bn254_pair_mod(out->x, field_modulus);

  mpz_mul(out->y, a->y, inv);
  bn254_pair_mod(out->y, field_modulus);

  mpz_clears(t, t2, inv, (mpz_ptr)nullptr);
  return true;
}

static void bn254_pair_fp2_exp(bn254_pair_fp2_t *out,
                               const bn254_pair_fp2_t *base,
                               const mpz_t exponent,
                               const mpz_t field_modulus) {
  bn254_pair_fp2_t sum;
  bn254_pair_fp2_t tmp;
  bn254_pair_fp2_init(&sum);
  bn254_pair_fp2_init(&tmp);
  bn254_pair_fp2_set_one(&sum);

  size_t bit_len = mpz_sizeinbase(exponent, 2U);
  for (ptrdiff_t bit = (ptrdiff_t)bit_len - 1; bit >= 0; --bit) {
    bn254_pair_fp2_square(&tmp, &sum, field_modulus);
    if (mpz_tstbit(exponent, (mp_bitcnt_t)bit) != 0U) {
      bn254_pair_fp2_mul(&sum, &tmp, base, field_modulus);
    } else {
      bn254_pair_fp2_set(&sum, &tmp);
    }
  }

  bn254_pair_fp2_set(out, &sum);
  bn254_pair_fp2_clear(&sum);
  bn254_pair_fp2_clear(&tmp);
}

static void bn254_pair_fp6_init(bn254_pair_fp6_t *value) {
  bn254_pair_fp2_init(&value->x);
  bn254_pair_fp2_init(&value->y);
  bn254_pair_fp2_init(&value->z);
}

static void bn254_pair_fp6_clear(bn254_pair_fp6_t *value) {
  bn254_pair_fp2_clear(&value->x);
  bn254_pair_fp2_clear(&value->y);
  bn254_pair_fp2_clear(&value->z);
}

static void bn254_pair_fp6_set(bn254_pair_fp6_t *out,
                               const bn254_pair_fp6_t *in) {
  bn254_pair_fp2_set(&out->x, &in->x);
  bn254_pair_fp2_set(&out->y, &in->y);
  bn254_pair_fp2_set(&out->z, &in->z);
}

static void bn254_pair_fp6_set_zero(bn254_pair_fp6_t *out) {
  bn254_pair_fp2_set_zero(&out->x);
  bn254_pair_fp2_set_zero(&out->y);
  bn254_pair_fp2_set_zero(&out->z);
}

static void bn254_pair_fp6_set_one(bn254_pair_fp6_t *out) {
  bn254_pair_fp2_set_zero(&out->x);
  bn254_pair_fp2_set_zero(&out->y);
  bn254_pair_fp2_set_one(&out->z);
}

static bool bn254_pair_fp6_is_zero(const bn254_pair_fp6_t *value) {
  return bn254_pair_fp2_is_zero(&value->x) &&
         bn254_pair_fp2_is_zero(&value->y) && bn254_pair_fp2_is_zero(&value->z);
}

static bool bn254_pair_fp6_is_one(const bn254_pair_fp6_t *value) {
  return bn254_pair_fp2_is_zero(&value->x) &&
         bn254_pair_fp2_is_zero(&value->y) && bn254_pair_fp2_is_one(&value->z);
}

static void bn254_pair_fp6_negative(bn254_pair_fp6_t *out,
                                    const bn254_pair_fp6_t *in,
                                    const mpz_t field_modulus) {
  bn254_pair_fp2_negative(&out->x, &in->x, field_modulus);
  bn254_pair_fp2_negative(&out->y, &in->y, field_modulus);
  bn254_pair_fp2_negative(&out->z, &in->z, field_modulus);
}

static void bn254_pair_fp6_add(bn254_pair_fp6_t *out, const bn254_pair_fp6_t *a,
                               const bn254_pair_fp6_t *b,
                               const mpz_t field_modulus) {
  bn254_pair_fp2_add(&out->x, &a->x, &b->x, field_modulus);
  bn254_pair_fp2_add(&out->y, &a->y, &b->y, field_modulus);
  bn254_pair_fp2_add(&out->z, &a->z, &b->z, field_modulus);
}

static void bn254_pair_fp6_sub(bn254_pair_fp6_t *out, const bn254_pair_fp6_t *a,
                               const bn254_pair_fp6_t *b,
                               const mpz_t field_modulus) {
  bn254_pair_fp2_sub(&out->x, &a->x, &b->x, field_modulus);
  bn254_pair_fp2_sub(&out->y, &a->y, &b->y, field_modulus);
  bn254_pair_fp2_sub(&out->z, &a->z, &b->z, field_modulus);
}

static void bn254_pair_fp6_double(bn254_pair_fp6_t *out,
                                  const bn254_pair_fp6_t *in,
                                  const mpz_t field_modulus) {
  bn254_pair_fp2_double(&out->x, &in->x, field_modulus);
  bn254_pair_fp2_double(&out->y, &in->y, field_modulus);
  bn254_pair_fp2_double(&out->z, &in->z, field_modulus);
}

static void bn254_pair_fp6_mul(bn254_pair_fp6_t *out, const bn254_pair_fp6_t *a,
                               const bn254_pair_fp6_t *b,
                               const mpz_t field_modulus) {
  bn254_pair_fp2_t v0;
  bn254_pair_fp2_t v1;
  bn254_pair_fp2_t v2;
  bn254_pair_fp2_t t0;
  bn254_pair_fp2_t t1;
  bn254_pair_fp2_t tx;
  bn254_pair_fp2_t ty;
  bn254_pair_fp2_t tz;
  bn254_pair_fp2_init(&v0);
  bn254_pair_fp2_init(&v1);
  bn254_pair_fp2_init(&v2);
  bn254_pair_fp2_init(&t0);
  bn254_pair_fp2_init(&t1);
  bn254_pair_fp2_init(&tx);
  bn254_pair_fp2_init(&ty);
  bn254_pair_fp2_init(&tz);

  bn254_pair_fp2_mul(&v0, &a->z, &b->z, field_modulus);
  bn254_pair_fp2_mul(&v1, &a->y, &b->y, field_modulus);
  bn254_pair_fp2_mul(&v2, &a->x, &b->x, field_modulus);

  bn254_pair_fp2_add(&t0, &a->x, &a->y, field_modulus);
  bn254_pair_fp2_add(&t1, &b->x, &b->y, field_modulus);
  bn254_pair_fp2_mul(&tz, &t0, &t1, field_modulus);
  bn254_pair_fp2_sub(&tz, &tz, &v1, field_modulus);
  bn254_pair_fp2_sub(&tz, &tz, &v2, field_modulus);
  bn254_pair_fp2_mul_xi(&tz, &tz, field_modulus);
  bn254_pair_fp2_add(&tz, &tz, &v0, field_modulus);

  bn254_pair_fp2_add(&t0, &a->y, &a->z, field_modulus);
  bn254_pair_fp2_add(&t1, &b->y, &b->z, field_modulus);
  bn254_pair_fp2_mul(&ty, &t0, &t1, field_modulus);
  bn254_pair_fp2_sub(&ty, &ty, &v0, field_modulus);
  bn254_pair_fp2_sub(&ty, &ty, &v1, field_modulus);
  bn254_pair_fp2_mul_xi(&t0, &v2, field_modulus);
  bn254_pair_fp2_add(&ty, &ty, &t0, field_modulus);

  bn254_pair_fp2_add(&t0, &a->x, &a->z, field_modulus);
  bn254_pair_fp2_add(&t1, &b->x, &b->z, field_modulus);
  bn254_pair_fp2_mul(&tx, &t0, &t1, field_modulus);
  bn254_pair_fp2_sub(&tx, &tx, &v0, field_modulus);
  bn254_pair_fp2_add(&tx, &tx, &v1, field_modulus);
  bn254_pair_fp2_sub(&tx, &tx, &v2, field_modulus);

  bn254_pair_fp2_set(&out->x, &tx);
  bn254_pair_fp2_set(&out->y, &ty);
  bn254_pair_fp2_set(&out->z, &tz);

  bn254_pair_fp2_clear(&v0);
  bn254_pair_fp2_clear(&v1);
  bn254_pair_fp2_clear(&v2);
  bn254_pair_fp2_clear(&t0);
  bn254_pair_fp2_clear(&t1);
  bn254_pair_fp2_clear(&tx);
  bn254_pair_fp2_clear(&ty);
  bn254_pair_fp2_clear(&tz);
}

static void bn254_pair_fp6_mul_scalar_fp2(bn254_pair_fp6_t *out,
                                          const bn254_pair_fp6_t *a,
                                          const bn254_pair_fp2_t *scalar,
                                          const mpz_t field_modulus) {
  bn254_pair_fp2_mul(&out->x, &a->x, scalar, field_modulus);
  bn254_pair_fp2_mul(&out->y, &a->y, scalar, field_modulus);
  bn254_pair_fp2_mul(&out->z, &a->z, scalar, field_modulus);
}

static void bn254_pair_fp6_mul_tau(bn254_pair_fp6_t *out,
                                   const bn254_pair_fp6_t *a,
                                   const mpz_t field_modulus) {
  bn254_pair_fp2_t tz;
  bn254_pair_fp2_t ty;
  bn254_pair_fp2_init(&tz);
  bn254_pair_fp2_init(&ty);

  bn254_pair_fp2_mul_xi(&tz, &a->x, field_modulus);
  bn254_pair_fp2_set(&ty, &a->y);
  bn254_pair_fp2_set(&out->y, &a->z);
  bn254_pair_fp2_set(&out->x, &ty);
  bn254_pair_fp2_set(&out->z, &tz);

  bn254_pair_fp2_clear(&tz);
  bn254_pair_fp2_clear(&ty);
}

static void bn254_pair_fp6_square(bn254_pair_fp6_t *out,
                                  const bn254_pair_fp6_t *a,
                                  const mpz_t field_modulus) {
  bn254_pair_fp2_t v0;
  bn254_pair_fp2_t v1;
  bn254_pair_fp2_t v2;
  bn254_pair_fp2_t c0;
  bn254_pair_fp2_t c1;
  bn254_pair_fp2_t c2;
  bn254_pair_fp2_t xi_v2;
  bn254_pair_fp2_init(&v0);
  bn254_pair_fp2_init(&v1);
  bn254_pair_fp2_init(&v2);
  bn254_pair_fp2_init(&c0);
  bn254_pair_fp2_init(&c1);
  bn254_pair_fp2_init(&c2);
  bn254_pair_fp2_init(&xi_v2);

  bn254_pair_fp2_square(&v0, &a->z, field_modulus);
  bn254_pair_fp2_square(&v1, &a->y, field_modulus);
  bn254_pair_fp2_square(&v2, &a->x, field_modulus);

  bn254_pair_fp2_add(&c0, &a->x, &a->y, field_modulus);
  bn254_pair_fp2_square(&c0, &c0, field_modulus);
  bn254_pair_fp2_sub(&c0, &c0, &v1, field_modulus);
  bn254_pair_fp2_sub(&c0, &c0, &v2, field_modulus);
  bn254_pair_fp2_mul_xi(&c0, &c0, field_modulus);
  bn254_pair_fp2_add(&c0, &c0, &v0, field_modulus);

  bn254_pair_fp2_add(&c1, &a->y, &a->z, field_modulus);
  bn254_pair_fp2_square(&c1, &c1, field_modulus);
  bn254_pair_fp2_sub(&c1, &c1, &v0, field_modulus);
  bn254_pair_fp2_sub(&c1, &c1, &v1, field_modulus);
  bn254_pair_fp2_mul_xi(&xi_v2, &v2, field_modulus);
  bn254_pair_fp2_add(&c1, &c1, &xi_v2, field_modulus);

  bn254_pair_fp2_add(&c2, &a->x, &a->z, field_modulus);
  bn254_pair_fp2_square(&c2, &c2, field_modulus);
  bn254_pair_fp2_sub(&c2, &c2, &v0, field_modulus);
  bn254_pair_fp2_add(&c2, &c2, &v1, field_modulus);
  bn254_pair_fp2_sub(&c2, &c2, &v2, field_modulus);

  bn254_pair_fp2_set(&out->x, &c2);
  bn254_pair_fp2_set(&out->y, &c1);
  bn254_pair_fp2_set(&out->z, &c0);

  bn254_pair_fp2_clear(&v0);
  bn254_pair_fp2_clear(&v1);
  bn254_pair_fp2_clear(&v2);
  bn254_pair_fp2_clear(&c0);
  bn254_pair_fp2_clear(&c1);
  bn254_pair_fp2_clear(&c2);
  bn254_pair_fp2_clear(&xi_v2);
}

static bool bn254_pair_fp6_invert(bn254_pair_fp6_t *out,
                                  const bn254_pair_fp6_t *a,
                                  const mpz_t field_modulus) {
  bn254_pair_fp2_t t1;
  bn254_pair_fp2_t A;
  bn254_pair_fp2_t B;
  bn254_pair_fp2_t C;
  bn254_pair_fp2_t F;
  bn254_pair_fp2_init(&t1);
  bn254_pair_fp2_init(&A);
  bn254_pair_fp2_init(&B);
  bn254_pair_fp2_init(&C);
  bn254_pair_fp2_init(&F);

  bn254_pair_fp2_square(&A, &a->z, field_modulus);
  bn254_pair_fp2_mul(&t1, &a->x, &a->y, field_modulus);
  bn254_pair_fp2_mul_xi(&t1, &t1, field_modulus);
  bn254_pair_fp2_sub(&A, &A, &t1, field_modulus);

  bn254_pair_fp2_square(&B, &a->x, field_modulus);
  bn254_pair_fp2_mul_xi(&B, &B, field_modulus);
  bn254_pair_fp2_mul(&t1, &a->y, &a->z, field_modulus);
  bn254_pair_fp2_sub(&B, &B, &t1, field_modulus);

  bn254_pair_fp2_square(&C, &a->y, field_modulus);
  bn254_pair_fp2_mul(&t1, &a->x, &a->z, field_modulus);
  bn254_pair_fp2_sub(&C, &C, &t1, field_modulus);

  bn254_pair_fp2_mul(&F, &C, &a->y, field_modulus);
  bn254_pair_fp2_mul_xi(&F, &F, field_modulus);
  bn254_pair_fp2_mul(&t1, &A, &a->z, field_modulus);
  bn254_pair_fp2_add(&F, &F, &t1, field_modulus);
  bn254_pair_fp2_mul(&t1, &B, &a->x, field_modulus);
  bn254_pair_fp2_mul_xi(&t1, &t1, field_modulus);
  bn254_pair_fp2_add(&F, &F, &t1, field_modulus);

  bool ok = bn254_pair_fp2_invert(&F, &F, field_modulus);
  if (ok) {
    bn254_pair_fp2_mul(&out->x, &C, &F, field_modulus);
    bn254_pair_fp2_mul(&out->y, &B, &F, field_modulus);
    bn254_pair_fp2_mul(&out->z, &A, &F, field_modulus);
  }

  bn254_pair_fp2_clear(&t1);
  bn254_pair_fp2_clear(&A);
  bn254_pair_fp2_clear(&B);
  bn254_pair_fp2_clear(&C);
  bn254_pair_fp2_clear(&F);
  return ok;
}

static void bn254_pair_fp6_frobenius(bn254_pair_fp6_t *out,
                                     const bn254_pair_fp6_t *in,
                                     const bn254_pair_ctx_t *ctx) {
  bn254_pair_fp2_conjugate(&out->x, &in->x, ctx->field_modulus);
  bn254_pair_fp2_conjugate(&out->y, &in->y, ctx->field_modulus);
  bn254_pair_fp2_conjugate(&out->z, &in->z, ctx->field_modulus);
  bn254_pair_fp2_mul(&out->x, &out->x, &ctx->xi_to_2p_minus_2_over_3,
                     ctx->field_modulus);
  bn254_pair_fp2_mul(&out->y, &out->y, &ctx->xi_to_p_minus_1_over_3,
                     ctx->field_modulus);
}

static void bn254_pair_fp6_frobenius_p2(bn254_pair_fp6_t *out,
                                        const bn254_pair_fp6_t *in,
                                        const bn254_pair_ctx_t *ctx) {
  bn254_pair_fp2_mul(&out->x, &in->x, &ctx->xi_to_2psquared_minus_2_over_3,
                     ctx->field_modulus);
  bn254_pair_fp2_mul(&out->y, &in->y, &ctx->xi_to_psquared_minus_1_over_3,
                     ctx->field_modulus);
  bn254_pair_fp2_set(&out->z, &in->z);
}

static void bn254_pair_fp12_init(bn254_pair_fp12_t *value) {
  bn254_pair_fp6_init(&value->x);
  bn254_pair_fp6_init(&value->y);
}

static void bn254_pair_fp12_clear(bn254_pair_fp12_t *value) {
  bn254_pair_fp6_clear(&value->x);
  bn254_pair_fp6_clear(&value->y);
}

static void bn254_pair_fp12_set(bn254_pair_fp12_t *out,
                                const bn254_pair_fp12_t *in) {
  bn254_pair_fp6_set(&out->x, &in->x);
  bn254_pair_fp6_set(&out->y, &in->y);
}

static void bn254_pair_fp12_set_one(bn254_pair_fp12_t *out) {
  bn254_pair_fp6_set_zero(&out->x);
  bn254_pair_fp6_set_one(&out->y);
}

static bool bn254_pair_fp12_is_one(const bn254_pair_fp12_t *value) {
  return bn254_pair_fp6_is_zero(&value->x) && bn254_pair_fp6_is_one(&value->y);
}

static void bn254_pair_fp12_conjugate(bn254_pair_fp12_t *out,
                                      const bn254_pair_fp12_t *in,
                                      const mpz_t field_modulus) {
  bn254_pair_fp6_negative(&out->x, &in->x, field_modulus);
  bn254_pair_fp6_set(&out->y, &in->y);
}

static void bn254_pair_fp12_mul(bn254_pair_fp12_t *out,
                                const bn254_pair_fp12_t *a,
                                const bn254_pair_fp12_t *b,
                                const mpz_t field_modulus) {
  bn254_pair_fp6_t tx;
  bn254_pair_fp6_t ty;
  bn254_pair_fp6_t t;
  bn254_pair_fp6_init(&tx);
  bn254_pair_fp6_init(&ty);
  bn254_pair_fp6_init(&t);

  bn254_pair_fp6_mul(&tx, &a->x, &b->y, field_modulus);
  bn254_pair_fp6_mul(&t, &b->x, &a->y, field_modulus);
  bn254_pair_fp6_add(&tx, &tx, &t, field_modulus);

  bn254_pair_fp6_mul(&ty, &a->y, &b->y, field_modulus);
  bn254_pair_fp6_mul(&t, &a->x, &b->x, field_modulus);
  bn254_pair_fp6_mul_tau(&t, &t, field_modulus);
  bn254_pair_fp6_add(&out->y, &ty, &t, field_modulus);
  bn254_pair_fp6_set(&out->x, &tx);

  bn254_pair_fp6_clear(&tx);
  bn254_pair_fp6_clear(&ty);
  bn254_pair_fp6_clear(&t);
}

static void bn254_pair_fp12_mul_scalar_fp6(bn254_pair_fp12_t *out,
                                           const bn254_pair_fp12_t *a,
                                           const bn254_pair_fp6_t *scalar,
                                           const mpz_t field_modulus) {
  bn254_pair_fp6_mul(&out->x, &a->x, scalar, field_modulus);
  bn254_pair_fp6_mul(&out->y, &a->y, scalar, field_modulus);
}

static void bn254_pair_fp12_square(bn254_pair_fp12_t *out,
                                   const bn254_pair_fp12_t *a,
                                   const mpz_t field_modulus) {
  bn254_pair_fp6_t v0;
  bn254_pair_fp6_t t;
  bn254_pair_fp6_t ty;
  bn254_pair_fp6_init(&v0);
  bn254_pair_fp6_init(&t);
  bn254_pair_fp6_init(&ty);

  bn254_pair_fp6_mul(&v0, &a->x, &a->y, field_modulus);

  bn254_pair_fp6_mul_tau(&t, &a->x, field_modulus);
  bn254_pair_fp6_add(&t, &a->y, &t, field_modulus);
  bn254_pair_fp6_add(&ty, &a->x, &a->y, field_modulus);
  bn254_pair_fp6_mul(&ty, &ty, &t, field_modulus);
  bn254_pair_fp6_sub(&ty, &ty, &v0, field_modulus);
  bn254_pair_fp6_mul_tau(&t, &v0, field_modulus);
  bn254_pair_fp6_sub(&ty, &ty, &t, field_modulus);

  bn254_pair_fp6_set(&out->y, &ty);
  bn254_pair_fp6_double(&out->x, &v0, field_modulus);

  bn254_pair_fp6_clear(&v0);
  bn254_pair_fp6_clear(&t);
  bn254_pair_fp6_clear(&ty);
}

static bool bn254_pair_fp12_invert(bn254_pair_fp12_t *out,
                                   const bn254_pair_fp12_t *a,
                                   const mpz_t field_modulus) {
  bn254_pair_fp6_t t1;
  bn254_pair_fp6_t t2;
  bn254_pair_fp12_t neg_a;
  bn254_pair_fp6_init(&t1);
  bn254_pair_fp6_init(&t2);
  bn254_pair_fp12_init(&neg_a);

  bn254_pair_fp6_square(&t1, &a->x, field_modulus);
  bn254_pair_fp6_square(&t2, &a->y, field_modulus);
  bn254_pair_fp6_mul_tau(&t1, &t1, field_modulus);
  bn254_pair_fp6_sub(&t1, &t2, &t1, field_modulus);

  bool ok = bn254_pair_fp6_invert(&t2, &t1, field_modulus);
  if (ok) {
    bn254_pair_fp6_negative(&neg_a.x, &a->x, field_modulus);
    bn254_pair_fp6_set(&neg_a.y, &a->y);
    bn254_pair_fp12_mul_scalar_fp6(out, &neg_a, &t2, field_modulus);
  }

  bn254_pair_fp6_clear(&t1);
  bn254_pair_fp6_clear(&t2);
  bn254_pair_fp12_clear(&neg_a);
  return ok;
}

static void bn254_pair_fp12_exp(bn254_pair_fp12_t *out,
                                const bn254_pair_fp12_t *base,
                                const mpz_t exponent,
                                const mpz_t field_modulus) {
  bn254_pair_fp12_t sum;
  bn254_pair_fp12_t tmp;
  bn254_pair_fp12_init(&sum);
  bn254_pair_fp12_init(&tmp);
  bn254_pair_fp12_set_one(&sum);

  size_t bit_len = mpz_sizeinbase(exponent, 2U);
  for (ptrdiff_t bit = (ptrdiff_t)bit_len - 1; bit >= 0; --bit) {
    bn254_pair_fp12_square(&tmp, &sum, field_modulus);
    if (mpz_tstbit(exponent, (mp_bitcnt_t)bit) != 0U) {
      bn254_pair_fp12_mul(&sum, &tmp, base, field_modulus);
    } else {
      bn254_pair_fp12_set(&sum, &tmp);
    }
  }

  bn254_pair_fp12_set(out, &sum);
  bn254_pair_fp12_clear(&sum);
  bn254_pair_fp12_clear(&tmp);
}

static void bn254_pair_fp12_frobenius(bn254_pair_fp12_t *out,
                                      const bn254_pair_fp12_t *in,
                                      const bn254_pair_ctx_t *ctx) {
  bn254_pair_fp6_frobenius(&out->x, &in->x, ctx);
  bn254_pair_fp6_frobenius(&out->y, &in->y, ctx);
  bn254_pair_fp6_mul_scalar_fp2(&out->x, &out->x, &ctx->xi_to_p_minus_1_over_6,
                                ctx->field_modulus);
}

static void bn254_pair_fp12_frobenius_p2(bn254_pair_fp12_t *out,
                                         const bn254_pair_fp12_t *in,
                                         const bn254_pair_ctx_t *ctx) {
  bn254_pair_fp6_frobenius_p2(&out->x, &in->x, ctx);
  bn254_pair_fp6_mul_scalar_fp2(&out->x, &out->x,
                                &ctx->xi_to_psquared_minus_1_over_6,
                                ctx->field_modulus);
  bn254_pair_fp6_frobenius_p2(&out->y, &in->y, ctx);
}

static void bn254_pair_g1_init(bn254_pair_g1_t *point) {
  mpz_init(point->x);
  mpz_init(point->y);
  mpz_init(point->z);
  mpz_init(point->t);
}

static void bn254_pair_g1_clear(bn254_pair_g1_t *point) {
  mpz_clear(point->x);
  mpz_clear(point->y);
  mpz_clear(point->z);
  mpz_clear(point->t);
}

static void bn254_pair_g1_set(bn254_pair_g1_t *out, const bn254_pair_g1_t *in) {
  mpz_set(out->x, in->x);
  mpz_set(out->y, in->y);
  mpz_set(out->z, in->z);
  mpz_set(out->t, in->t);
}

static void bn254_pair_g1_set_infinity(bn254_pair_g1_t *point) {
  mpz_set_ui(point->x, 0U);
  mpz_set_ui(point->y, 1U);
  mpz_set_ui(point->z, 0U);
  mpz_set_ui(point->t, 0U);
}

static bool bn254_pair_g1_is_infinity(const bn254_pair_g1_t *point) {
  return mpz_sgn(point->z) == 0;
}

static bool bn254_pair_g1_make_affine(bn254_pair_g1_t *point,
                                      const mpz_t field_modulus) {
  if (bn254_pair_g1_is_infinity(point)) {
    bn254_pair_g1_set_infinity(point);
    return true;
  }
  if (mpz_cmp_ui(point->z, 1U) == 0) {
    return true;
  }

  mpz_t z_inv;
  mpz_t t;
  mpz_t z_inv_sq;
  mpz_inits(z_inv, t, z_inv_sq, (mpz_ptr)nullptr);

  if (mpz_invert(z_inv, point->z, field_modulus) == 0) {
    mpz_clears(z_inv, t, z_inv_sq, (mpz_ptr)nullptr);
    return false;
  }

  mpz_mul(t, point->y, z_inv);
  bn254_pair_mod(t, field_modulus);
  mpz_mul(z_inv_sq, z_inv, z_inv);
  bn254_pair_mod(z_inv_sq, field_modulus);

  mpz_mul(point->y, t, z_inv_sq);
  bn254_pair_mod(point->y, field_modulus);
  mpz_mul(t, point->x, z_inv_sq);
  bn254_pair_mod(t, field_modulus);
  mpz_set(point->x, t);
  mpz_set_ui(point->z, 1U);
  mpz_set_ui(point->t, 1U);

  mpz_clears(z_inv, t, z_inv_sq, (mpz_ptr)nullptr);
  return true;
}

static bool bn254_pair_g1_is_on_curve(const bn254_pair_g1_t *point,
                                      const mpz_t field_modulus) {
  if (bn254_pair_g1_is_infinity(point)) {
    return true;
  }

  mpz_t yy;
  mpz_t xxx;
  mpz_inits(yy, xxx, (mpz_ptr)nullptr);

  mpz_mul(yy, point->y, point->y);
  bn254_pair_mod(yy, field_modulus);

  mpz_mul(xxx, point->x, point->x);
  bn254_pair_mod(xxx, field_modulus);
  mpz_mul(xxx, xxx, point->x);
  bn254_pair_mod(xxx, field_modulus);
  mpz_add_ui(xxx, xxx, 3U);
  bn254_pair_mod(xxx, field_modulus);

  bool is_on_curve = (mpz_cmp(yy, xxx) == 0);
  mpz_clears(yy, xxx, (mpz_ptr)nullptr);
  return is_on_curve;
}

static void bn254_pair_g2_init(bn254_pair_g2_t *point) {
  bn254_pair_fp2_init(&point->x);
  bn254_pair_fp2_init(&point->y);
  bn254_pair_fp2_init(&point->z);
  bn254_pair_fp2_init(&point->t);
}

static void bn254_pair_g2_clear(bn254_pair_g2_t *point) {
  bn254_pair_fp2_clear(&point->x);
  bn254_pair_fp2_clear(&point->y);
  bn254_pair_fp2_clear(&point->z);
  bn254_pair_fp2_clear(&point->t);
}

static void bn254_pair_g2_set(bn254_pair_g2_t *out, const bn254_pair_g2_t *in) {
  bn254_pair_fp2_set(&out->x, &in->x);
  bn254_pair_fp2_set(&out->y, &in->y);
  bn254_pair_fp2_set(&out->z, &in->z);
  bn254_pair_fp2_set(&out->t, &in->t);
}

static void bn254_pair_g2_set_infinity(bn254_pair_g2_t *point) {
  bn254_pair_fp2_set_zero(&point->x);
  bn254_pair_fp2_set_one(&point->y);
  bn254_pair_fp2_set_zero(&point->z);
  bn254_pair_fp2_set_zero(&point->t);
}

static bool bn254_pair_g2_is_infinity(const bn254_pair_g2_t *point) {
  return bn254_pair_fp2_is_zero(&point->z);
}

static void bn254_pair_g2_negative(bn254_pair_g2_t *out,
                                   const bn254_pair_g2_t *in,
                                   const mpz_t field_modulus) {
  bn254_pair_fp2_set(&out->x, &in->x);
  bn254_pair_fp2_set_zero(&out->y);
  bn254_pair_fp2_sub(&out->y, &out->y, &in->y, field_modulus);
  bn254_pair_fp2_set(&out->z, &in->z);
  bn254_pair_fp2_set_zero(&out->t);
}

static bool bn254_pair_g2_make_affine(bn254_pair_g2_t *point,
                                      const mpz_t field_modulus) {
  if (bn254_pair_fp2_is_one(&point->z)) {
    return true;
  }
  if (bn254_pair_g2_is_infinity(point)) {
    bn254_pair_g2_set_infinity(point);
    return true;
  }

  bn254_pair_fp2_t z_inv;
  bn254_pair_fp2_t t;
  bn254_pair_fp2_t z_inv_sq;
  bn254_pair_fp2_init(&z_inv);
  bn254_pair_fp2_init(&t);
  bn254_pair_fp2_init(&z_inv_sq);

  bool ok = bn254_pair_fp2_invert(&z_inv, &point->z, field_modulus);
  if (!ok) {
    bn254_pair_fp2_clear(&z_inv);
    bn254_pair_fp2_clear(&t);
    bn254_pair_fp2_clear(&z_inv_sq);
    return false;
  }

  bn254_pair_fp2_mul(&t, &point->y, &z_inv, field_modulus);
  bn254_pair_fp2_square(&z_inv_sq, &z_inv, field_modulus);
  bn254_pair_fp2_mul(&point->y, &t, &z_inv_sq, field_modulus);
  bn254_pair_fp2_mul(&t, &point->x, &z_inv_sq, field_modulus);
  bn254_pair_fp2_set(&point->x, &t);
  bn254_pair_fp2_set_one(&point->z);
  bn254_pair_fp2_set_one(&point->t);

  bn254_pair_fp2_clear(&z_inv);
  bn254_pair_fp2_clear(&t);
  bn254_pair_fp2_clear(&z_inv_sq);
  return true;
}

static bool bn254_pair_g2_is_on_curve(const bn254_pair_g2_t *point,
                                      const bn254_pair_fp2_t *twist_b,
                                      const mpz_t field_modulus) {
  if (bn254_pair_g2_is_infinity(point)) {
    return true;
  }

  bn254_pair_fp2_t yy;
  bn254_pair_fp2_t xxx;
  bn254_pair_fp2_init(&yy);
  bn254_pair_fp2_init(&xxx);

  bn254_pair_fp2_square(&yy, &point->y, field_modulus);
  bn254_pair_fp2_square(&xxx, &point->x, field_modulus);
  bn254_pair_fp2_mul(&xxx, &xxx, &point->x, field_modulus);
  bn254_pair_fp2_sub(&yy, &yy, &xxx, field_modulus);
  bn254_pair_fp2_sub(&yy, &yy, twist_b, field_modulus);

  bool is_on_curve = bn254_pair_fp2_is_zero(&yy);
  bn254_pair_fp2_clear(&yy);
  bn254_pair_fp2_clear(&xxx);
  return is_on_curve;
}

static void bn254_pair_g2_double(bn254_pair_g2_t *out, const bn254_pair_g2_t *a,
                                 const mpz_t field_modulus);

static void bn254_pair_g2_add(bn254_pair_g2_t *out, const bn254_pair_g2_t *a,
                              const bn254_pair_g2_t *b,
                              const mpz_t field_modulus) {
  if (bn254_pair_g2_is_infinity(a)) {
    bn254_pair_g2_set(out, b);
    return;
  }
  if (bn254_pair_g2_is_infinity(b)) {
    bn254_pair_g2_set(out, a);
    return;
  }

  bn254_pair_fp2_t z1z1;
  bn254_pair_fp2_t z2z2;
  bn254_pair_fp2_t u1;
  bn254_pair_fp2_t u2;
  bn254_pair_fp2_t t;
  bn254_pair_fp2_t s1;
  bn254_pair_fp2_t s2;
  bn254_pair_fp2_t h;
  bn254_pair_fp2_t i;
  bn254_pair_fp2_t j;
  bn254_pair_fp2_t r;
  bn254_pair_fp2_t v;
  bn254_pair_fp2_t t4;
  bn254_pair_fp2_t t6;
  bn254_pair_fp2_init(&z1z1);
  bn254_pair_fp2_init(&z2z2);
  bn254_pair_fp2_init(&u1);
  bn254_pair_fp2_init(&u2);
  bn254_pair_fp2_init(&t);
  bn254_pair_fp2_init(&s1);
  bn254_pair_fp2_init(&s2);
  bn254_pair_fp2_init(&h);
  bn254_pair_fp2_init(&i);
  bn254_pair_fp2_init(&j);
  bn254_pair_fp2_init(&r);
  bn254_pair_fp2_init(&v);
  bn254_pair_fp2_init(&t4);
  bn254_pair_fp2_init(&t6);

  bn254_pair_fp2_square(&z1z1, &a->z, field_modulus);
  bn254_pair_fp2_square(&z2z2, &b->z, field_modulus);
  bn254_pair_fp2_mul(&u1, &a->x, &z2z2, field_modulus);
  bn254_pair_fp2_mul(&u2, &b->x, &z1z1, field_modulus);

  bn254_pair_fp2_mul(&t, &b->z, &z2z2, field_modulus);
  bn254_pair_fp2_mul(&s1, &a->y, &t, field_modulus);

  bn254_pair_fp2_mul(&t, &a->z, &z1z1, field_modulus);
  bn254_pair_fp2_mul(&s2, &b->y, &t, field_modulus);

  bn254_pair_fp2_sub(&h, &u2, &u1, field_modulus);
  bool x_equal = bn254_pair_fp2_is_zero(&h);

  bn254_pair_fp2_double(&t, &h, field_modulus);
  bn254_pair_fp2_square(&i, &t, field_modulus);
  bn254_pair_fp2_mul(&j, &h, &i, field_modulus);

  bn254_pair_fp2_sub(&t, &s2, &s1, field_modulus);
  bool y_equal = bn254_pair_fp2_is_zero(&t);
  if (x_equal && y_equal) {
    bn254_pair_g2_t doubled;
    bn254_pair_g2_init(&doubled);
    bn254_pair_g2_double(&doubled, a, field_modulus);
    bn254_pair_g2_set(out, &doubled);
    bn254_pair_g2_clear(&doubled);
    goto done;
  }

  bn254_pair_fp2_double(&r, &t, field_modulus);
  bn254_pair_fp2_mul(&v, &u1, &i, field_modulus);

  bn254_pair_fp2_square(&t4, &r, field_modulus);
  bn254_pair_fp2_double(&t, &v, field_modulus);
  bn254_pair_fp2_sub(&t6, &t4, &j, field_modulus);
  bn254_pair_fp2_sub(&out->x, &t6, &t, field_modulus);

  bn254_pair_fp2_sub(&t, &v, &out->x, field_modulus);
  bn254_pair_fp2_mul(&t4, &s1, &j, field_modulus);
  bn254_pair_fp2_double(&t6, &t4, field_modulus);
  bn254_pair_fp2_mul(&t4, &r, &t, field_modulus);
  bn254_pair_fp2_sub(&out->y, &t4, &t6, field_modulus);

  bn254_pair_fp2_add(&t, &a->z, &b->z, field_modulus);
  bn254_pair_fp2_square(&t4, &t, field_modulus);
  bn254_pair_fp2_sub(&t, &t4, &z1z1, field_modulus);
  bn254_pair_fp2_sub(&t4, &t, &z2z2, field_modulus);
  bn254_pair_fp2_mul(&out->z, &t4, &h, field_modulus);

done:
  bn254_pair_fp2_clear(&z1z1);
  bn254_pair_fp2_clear(&z2z2);
  bn254_pair_fp2_clear(&u1);
  bn254_pair_fp2_clear(&u2);
  bn254_pair_fp2_clear(&t);
  bn254_pair_fp2_clear(&s1);
  bn254_pair_fp2_clear(&s2);
  bn254_pair_fp2_clear(&h);
  bn254_pair_fp2_clear(&i);
  bn254_pair_fp2_clear(&j);
  bn254_pair_fp2_clear(&r);
  bn254_pair_fp2_clear(&v);
  bn254_pair_fp2_clear(&t4);
  bn254_pair_fp2_clear(&t6);
}

static void bn254_pair_g2_double(bn254_pair_g2_t *out, const bn254_pair_g2_t *a,
                                 const mpz_t field_modulus) {
  bn254_pair_fp2_t A;
  bn254_pair_fp2_t B;
  bn254_pair_fp2_t C;
  bn254_pair_fp2_t t;
  bn254_pair_fp2_t t2;
  bn254_pair_fp2_t d;
  bn254_pair_fp2_t e;
  bn254_pair_fp2_t f;
  bn254_pair_fp2_init(&A);
  bn254_pair_fp2_init(&B);
  bn254_pair_fp2_init(&C);
  bn254_pair_fp2_init(&t);
  bn254_pair_fp2_init(&t2);
  bn254_pair_fp2_init(&d);
  bn254_pair_fp2_init(&e);
  bn254_pair_fp2_init(&f);

  bn254_pair_fp2_square(&A, &a->x, field_modulus);
  bn254_pair_fp2_square(&B, &a->y, field_modulus);
  bn254_pair_fp2_square(&C, &B, field_modulus);

  bn254_pair_fp2_add(&t, &a->x, &B, field_modulus);
  bn254_pair_fp2_square(&t2, &t, field_modulus);
  bn254_pair_fp2_sub(&t, &t2, &A, field_modulus);
  bn254_pair_fp2_sub(&t2, &t, &C, field_modulus);
  bn254_pair_fp2_double(&d, &t2, field_modulus);
  bn254_pair_fp2_double(&t, &A, field_modulus);
  bn254_pair_fp2_add(&e, &t, &A, field_modulus);
  bn254_pair_fp2_square(&f, &e, field_modulus);

  bn254_pair_fp2_double(&t, &d, field_modulus);
  bn254_pair_fp2_sub(&out->x, &f, &t, field_modulus);

  bn254_pair_fp2_double(&t, &C, field_modulus);
  bn254_pair_fp2_double(&t2, &t, field_modulus);
  bn254_pair_fp2_double(&t, &t2, field_modulus);
  bn254_pair_fp2_sub(&out->y, &d, &out->x, field_modulus);
  bn254_pair_fp2_mul(&t2, &e, &out->y, field_modulus);
  bn254_pair_fp2_sub(&out->y, &t2, &t, field_modulus);

  bn254_pair_fp2_mul(&t, &a->y, &a->z, field_modulus);
  bn254_pair_fp2_double(&out->z, &t, field_modulus);

  bn254_pair_fp2_clear(&A);
  bn254_pair_fp2_clear(&B);
  bn254_pair_fp2_clear(&C);
  bn254_pair_fp2_clear(&t);
  bn254_pair_fp2_clear(&t2);
  bn254_pair_fp2_clear(&d);
  bn254_pair_fp2_clear(&e);
  bn254_pair_fp2_clear(&f);
}

static void bn254_pair_g2_mul(bn254_pair_g2_t *out, const bn254_pair_g2_t *a,
                              const mpz_t scalar, const mpz_t field_modulus) {
  bn254_pair_g2_t sum;
  bn254_pair_g2_t t;
  bn254_pair_g2_init(&sum);
  bn254_pair_g2_init(&t);
  bn254_pair_g2_set_infinity(&sum);

  size_t bit_len = mpz_sizeinbase(scalar, 2U);
  for (ptrdiff_t bit = (ptrdiff_t)bit_len - 1; bit >= 0; --bit) {
    bn254_pair_g2_double(&t, &sum, field_modulus);
    if (mpz_tstbit(scalar, (mp_bitcnt_t)bit) != 0U) {
      bn254_pair_g2_add(&sum, &t, a, field_modulus);
    } else {
      bn254_pair_g2_set(&sum, &t);
    }
  }

  bn254_pair_g2_set(out, &sum);
  bn254_pair_g2_clear(&sum);
  bn254_pair_g2_clear(&t);
}

static bool bn254_pair_read_fp(const uint8_t *input, size_t input_size,
                               size_t offset, const mpz_t field_modulus,
                               mpz_t out) {
  if (input == nullptr || offset > input_size || (input_size - offset) < 32U) {
    return false;
  }

  mpz_import(out, 32U, 1, 1, 1, 0, input + offset);
  return mpz_cmp(out, field_modulus) < 0;
}

static bool bn254_pair_parse_g1(const uint8_t *input, size_t input_size,
                                size_t offset, const bn254_pair_ctx_t *ctx,
                                bn254_pair_g1_t *out_point) {
  if (!bn254_pair_read_fp(input, input_size, offset, ctx->field_modulus,
                          out_point->x) ||
      !bn254_pair_read_fp(input, input_size, offset + 32U, ctx->field_modulus,
                          out_point->y)) {
    return false;
  }

  if (mpz_sgn(out_point->x) == 0 && mpz_sgn(out_point->y) == 0) {
    bn254_pair_g1_set_infinity(out_point);
    return true;
  }

  mpz_set_ui(out_point->z, 1U);
  mpz_set_ui(out_point->t, 1U);
  return bn254_pair_g1_is_on_curve(out_point, ctx->field_modulus);
}

static bool bn254_pair_parse_g2(const uint8_t *input, size_t input_size,
                                size_t offset, const bn254_pair_ctx_t *ctx,
                                bn254_pair_g2_t *out_point) {
  if (!bn254_pair_read_fp(input, input_size, offset, ctx->field_modulus,
                          out_point->x.x) ||
      !bn254_pair_read_fp(input, input_size, offset + 32U, ctx->field_modulus,
                          out_point->x.y) ||
      !bn254_pair_read_fp(input, input_size, offset + 64U, ctx->field_modulus,
                          out_point->y.x) ||
      !bn254_pair_read_fp(input, input_size, offset + 96U, ctx->field_modulus,
                          out_point->y.y)) {
    return false;
  }

  if (mpz_sgn(out_point->x.x) == 0 && mpz_sgn(out_point->x.y) == 0 &&
      mpz_sgn(out_point->y.x) == 0 && mpz_sgn(out_point->y.y) == 0) {
    bn254_pair_g2_set_infinity(out_point);
    return true;
  }

  bn254_pair_fp2_set_one(&out_point->z);
  bn254_pair_fp2_set_one(&out_point->t);
  if (!bn254_pair_g2_is_on_curve(out_point, &ctx->twist_b,
                                 ctx->field_modulus)) {
    return false;
  }

  bn254_pair_g2_t check;
  bn254_pair_g2_init(&check);
  bn254_pair_g2_mul(&check, out_point, ctx->group_order, ctx->field_modulus);
  bool in_subgroup = bn254_pair_g2_is_infinity(&check);
  bn254_pair_g2_clear(&check);
  return in_subgroup;
}

static void bn254_pair_line_function_add(
    bn254_pair_fp2_t *out_a, bn254_pair_fp2_t *out_b, bn254_pair_fp2_t *out_c,
    bn254_pair_g2_t *out_r, const bn254_pair_g2_t *r, const bn254_pair_g2_t *p,
    const bn254_pair_g1_t *q, const bn254_pair_fp2_t *r2,
    const mpz_t field_modulus) {
  bn254_pair_fp2_t B;
  bn254_pair_fp2_t D;
  bn254_pair_fp2_t H;
  bn254_pair_fp2_t I;
  bn254_pair_fp2_t E;
  bn254_pair_fp2_t J;
  bn254_pair_fp2_t L1;
  bn254_pair_fp2_t V;
  bn254_pair_fp2_t t;
  bn254_pair_fp2_t t2;
  bn254_pair_fp2_init(&B);
  bn254_pair_fp2_init(&D);
  bn254_pair_fp2_init(&H);
  bn254_pair_fp2_init(&I);
  bn254_pair_fp2_init(&E);
  bn254_pair_fp2_init(&J);
  bn254_pair_fp2_init(&L1);
  bn254_pair_fp2_init(&V);
  bn254_pair_fp2_init(&t);
  bn254_pair_fp2_init(&t2);

  bn254_pair_fp2_mul(&B, &p->x, &r->t, field_modulus);

  bn254_pair_fp2_add(&D, &p->y, &r->z, field_modulus);
  bn254_pair_fp2_square(&D, &D, field_modulus);
  bn254_pair_fp2_sub(&D, &D, r2, field_modulus);
  bn254_pair_fp2_sub(&D, &D, &r->t, field_modulus);
  bn254_pair_fp2_mul(&D, &D, &r->t, field_modulus);

  bn254_pair_fp2_sub(&H, &B, &r->x, field_modulus);
  bn254_pair_fp2_square(&I, &H, field_modulus);

  bn254_pair_fp2_double(&E, &I, field_modulus);
  bn254_pair_fp2_double(&E, &E, field_modulus);

  bn254_pair_fp2_mul(&J, &H, &E, field_modulus);

  bn254_pair_fp2_sub(&L1, &D, &r->y, field_modulus);
  bn254_pair_fp2_sub(&L1, &L1, &r->y, field_modulus);

  bn254_pair_fp2_mul(&V, &r->x, &E, field_modulus);

  bn254_pair_fp2_square(&out_r->x, &L1, field_modulus);
  bn254_pair_fp2_sub(&out_r->x, &out_r->x, &J, field_modulus);
  bn254_pair_fp2_sub(&out_r->x, &out_r->x, &V, field_modulus);
  bn254_pair_fp2_sub(&out_r->x, &out_r->x, &V, field_modulus);

  bn254_pair_fp2_add(&out_r->z, &r->z, &H, field_modulus);
  bn254_pair_fp2_square(&out_r->z, &out_r->z, field_modulus);
  bn254_pair_fp2_sub(&out_r->z, &out_r->z, &r->t, field_modulus);
  bn254_pair_fp2_sub(&out_r->z, &out_r->z, &I, field_modulus);

  bn254_pair_fp2_sub(&t, &V, &out_r->x, field_modulus);
  bn254_pair_fp2_mul(&t, &t, &L1, field_modulus);
  bn254_pair_fp2_mul(&t2, &r->y, &J, field_modulus);
  bn254_pair_fp2_double(&t2, &t2, field_modulus);
  bn254_pair_fp2_sub(&out_r->y, &t, &t2, field_modulus);

  bn254_pair_fp2_square(&out_r->t, &out_r->z, field_modulus);

  bn254_pair_fp2_add(&t, &p->y, &out_r->z, field_modulus);
  bn254_pair_fp2_square(&t, &t, field_modulus);
  bn254_pair_fp2_sub(&t, &t, r2, field_modulus);
  bn254_pair_fp2_sub(&t, &t, &out_r->t, field_modulus);

  bn254_pair_fp2_mul_scalar(&t2, &L1, q->x, field_modulus);
  bn254_pair_fp2_double(&t2, &t2, field_modulus);
  bn254_pair_fp2_sub(out_a, &t2, &t, field_modulus);

  bn254_pair_fp2_mul_scalar(out_c, &out_r->z, q->y, field_modulus);
  bn254_pair_fp2_double(out_c, out_c, field_modulus);

  bn254_pair_fp2_set_zero(out_b);
  bn254_pair_fp2_sub(out_b, out_b, &L1, field_modulus);
  bn254_pair_fp2_mul_scalar(out_b, out_b, q->x, field_modulus);
  bn254_pair_fp2_double(out_b, out_b, field_modulus);

  bn254_pair_fp2_clear(&B);
  bn254_pair_fp2_clear(&D);
  bn254_pair_fp2_clear(&H);
  bn254_pair_fp2_clear(&I);
  bn254_pair_fp2_clear(&E);
  bn254_pair_fp2_clear(&J);
  bn254_pair_fp2_clear(&L1);
  bn254_pair_fp2_clear(&V);
  bn254_pair_fp2_clear(&t);
  bn254_pair_fp2_clear(&t2);
}

static void bn254_pair_line_function_double(
    bn254_pair_fp2_t *out_a, bn254_pair_fp2_t *out_b, bn254_pair_fp2_t *out_c,
    bn254_pair_g2_t *out_r, const bn254_pair_g2_t *r, const bn254_pair_g1_t *q,
    const mpz_t field_modulus) {
  bn254_pair_fp2_t A;
  bn254_pair_fp2_t B;
  bn254_pair_fp2_t C;
  bn254_pair_fp2_t D;
  bn254_pair_fp2_t E;
  bn254_pair_fp2_t G;
  bn254_pair_fp2_t t;
  bn254_pair_fp2_init(&A);
  bn254_pair_fp2_init(&B);
  bn254_pair_fp2_init(&C);
  bn254_pair_fp2_init(&D);
  bn254_pair_fp2_init(&E);
  bn254_pair_fp2_init(&G);
  bn254_pair_fp2_init(&t);

  bn254_pair_fp2_square(&A, &r->x, field_modulus);
  bn254_pair_fp2_square(&B, &r->y, field_modulus);
  bn254_pair_fp2_square(&C, &B, field_modulus);

  bn254_pair_fp2_add(&D, &r->x, &B, field_modulus);
  bn254_pair_fp2_square(&D, &D, field_modulus);
  bn254_pair_fp2_sub(&D, &D, &A, field_modulus);
  bn254_pair_fp2_sub(&D, &D, &C, field_modulus);
  bn254_pair_fp2_double(&D, &D, field_modulus);

  bn254_pair_fp2_double(&E, &A, field_modulus);
  bn254_pair_fp2_add(&E, &E, &A, field_modulus);

  bn254_pair_fp2_square(&G, &E, field_modulus);

  bn254_pair_fp2_sub(&out_r->x, &G, &D, field_modulus);
  bn254_pair_fp2_sub(&out_r->x, &out_r->x, &D, field_modulus);

  bn254_pair_fp2_add(&out_r->z, &r->y, &r->z, field_modulus);
  bn254_pair_fp2_square(&out_r->z, &out_r->z, field_modulus);
  bn254_pair_fp2_sub(&out_r->z, &out_r->z, &B, field_modulus);
  bn254_pair_fp2_sub(&out_r->z, &out_r->z, &r->t, field_modulus);

  bn254_pair_fp2_sub(&out_r->y, &D, &out_r->x, field_modulus);
  bn254_pair_fp2_mul(&out_r->y, &out_r->y, &E, field_modulus);
  bn254_pair_fp2_double(&t, &C, field_modulus);
  bn254_pair_fp2_double(&t, &t, field_modulus);
  bn254_pair_fp2_double(&t, &t, field_modulus);
  bn254_pair_fp2_sub(&out_r->y, &out_r->y, &t, field_modulus);

  bn254_pair_fp2_square(&out_r->t, &out_r->z, field_modulus);

  bn254_pair_fp2_mul(&t, &E, &r->t, field_modulus);
  bn254_pair_fp2_double(&t, &t, field_modulus);
  bn254_pair_fp2_set_zero(out_b);
  bn254_pair_fp2_sub(out_b, out_b, &t, field_modulus);
  bn254_pair_fp2_mul_scalar(out_b, out_b, q->x, field_modulus);

  bn254_pair_fp2_add(out_a, &r->x, &E, field_modulus);
  bn254_pair_fp2_square(out_a, out_a, field_modulus);
  bn254_pair_fp2_sub(out_a, out_a, &A, field_modulus);
  bn254_pair_fp2_sub(out_a, out_a, &G, field_modulus);
  bn254_pair_fp2_double(&t, &B, field_modulus);
  bn254_pair_fp2_double(&t, &t, field_modulus);
  bn254_pair_fp2_sub(out_a, out_a, &t, field_modulus);

  bn254_pair_fp2_mul(out_c, &out_r->z, &r->t, field_modulus);
  bn254_pair_fp2_double(out_c, out_c, field_modulus);
  bn254_pair_fp2_mul_scalar(out_c, out_c, q->y, field_modulus);

  bn254_pair_fp2_clear(&A);
  bn254_pair_fp2_clear(&B);
  bn254_pair_fp2_clear(&C);
  bn254_pair_fp2_clear(&D);
  bn254_pair_fp2_clear(&E);
  bn254_pair_fp2_clear(&G);
  bn254_pair_fp2_clear(&t);
}

static void bn254_pair_mul_line(bn254_pair_fp12_t *ret,
                                const bn254_pair_fp2_t *a,
                                const bn254_pair_fp2_t *b,
                                const bn254_pair_fp2_t *c,
                                const mpz_t field_modulus) {
  bn254_pair_fp6_t a2;
  bn254_pair_fp6_t t3;
  bn254_pair_fp2_t t;
  bn254_pair_fp6_t t2;
  bn254_pair_fp6_init(&a2);
  bn254_pair_fp6_init(&t3);
  bn254_pair_fp2_init(&t);
  bn254_pair_fp6_init(&t2);

  bn254_pair_fp2_set_zero(&a2.x);
  bn254_pair_fp2_set(&a2.y, a);
  bn254_pair_fp2_set(&a2.z, b);
  bn254_pair_fp6_mul(&a2, &a2, &ret->x, field_modulus);

  bn254_pair_fp6_mul_scalar_fp2(&t3, &ret->y, c, field_modulus);

  bn254_pair_fp2_add(&t, b, c, field_modulus);
  bn254_pair_fp2_set_zero(&t2.x);
  bn254_pair_fp2_set(&t2.y, a);
  bn254_pair_fp2_set(&t2.z, &t);
  bn254_pair_fp6_add(&ret->x, &ret->x, &ret->y, field_modulus);

  bn254_pair_fp6_set(&ret->y, &t3);

  bn254_pair_fp6_mul(&ret->x, &ret->x, &t2, field_modulus);
  bn254_pair_fp6_sub(&ret->x, &ret->x, &a2, field_modulus);
  bn254_pair_fp6_sub(&ret->x, &ret->x, &ret->y, field_modulus);
  bn254_pair_fp6_mul_tau(&a2, &a2, field_modulus);
  bn254_pair_fp6_add(&ret->y, &ret->y, &a2, field_modulus);

  bn254_pair_fp6_clear(&a2);
  bn254_pair_fp6_clear(&t3);
  bn254_pair_fp2_clear(&t);
  bn254_pair_fp6_clear(&t2);
}

static void bn254_pair_miller(bn254_pair_fp12_t *out, const bn254_pair_g2_t *q,
                              const bn254_pair_g1_t *p,
                              const bn254_pair_ctx_t *ctx) {
  bn254_pair_fp12_set_one(out);

  bn254_pair_g2_t a_affine;
  bn254_pair_g1_t b_affine;
  bn254_pair_g2_t minus_a;
  bn254_pair_g2_t r;
  bn254_pair_fp2_t r2;
  bn254_pair_g2_init(&a_affine);
  bn254_pair_g1_init(&b_affine);
  bn254_pair_g2_init(&minus_a);
  bn254_pair_g2_init(&r);
  bn254_pair_fp2_init(&r2);

  bn254_pair_g2_set(&a_affine, q);
  (void)bn254_pair_g2_make_affine(&a_affine, ctx->field_modulus);
  bn254_pair_g1_set(&b_affine, p);
  (void)bn254_pair_g1_make_affine(&b_affine, ctx->field_modulus);

  bn254_pair_g2_negative(&minus_a, &a_affine, ctx->field_modulus);
  bn254_pair_g2_set(&r, &a_affine);
  bn254_pair_fp2_square(&r2, &a_affine.y, ctx->field_modulus);

  for (ptrdiff_t i = (ptrdiff_t)ctx->six_u_plus_2_naf_len - 1; i > 0; --i) {
    bn254_pair_fp2_t a_line;
    bn254_pair_fp2_t b_line;
    bn254_pair_fp2_t c_line;
    bn254_pair_g2_t new_r;
    bn254_pair_fp2_init(&a_line);
    bn254_pair_fp2_init(&b_line);
    bn254_pair_fp2_init(&c_line);
    bn254_pair_g2_init(&new_r);

    bn254_pair_line_function_double(&a_line, &b_line, &c_line, &new_r, &r,
                                    &b_affine, ctx->field_modulus);
    if (i != (ptrdiff_t)ctx->six_u_plus_2_naf_len - 1) {
      bn254_pair_fp12_square(out, out, ctx->field_modulus);
    }
    bn254_pair_mul_line(out, &a_line, &b_line, &c_line, ctx->field_modulus);
    bn254_pair_g2_set(&r, &new_r);

    int8_t step = ctx->six_u_plus_2_naf[(size_t)i - 1U];
    if (step != 0) {
      const bn254_pair_g2_t *addend = (step > 0) ? &a_affine : &minus_a;
      bn254_pair_line_function_add(&a_line, &b_line, &c_line, &new_r, &r,
                                   addend, &b_affine, &r2, ctx->field_modulus);
      bn254_pair_mul_line(out, &a_line, &b_line, &c_line, ctx->field_modulus);
      bn254_pair_g2_set(&r, &new_r);
    }

    bn254_pair_fp2_clear(&a_line);
    bn254_pair_fp2_clear(&b_line);
    bn254_pair_fp2_clear(&c_line);
    bn254_pair_g2_clear(&new_r);
  }

  bn254_pair_g2_t q1;
  bn254_pair_g2_t minus_q2;
  bn254_pair_g2_init(&q1);
  bn254_pair_g2_init(&minus_q2);

  bn254_pair_fp2_conjugate(&q1.x, &a_affine.x, ctx->field_modulus);
  bn254_pair_fp2_mul(&q1.x, &q1.x, &ctx->xi_to_p_minus_1_over_3,
                     ctx->field_modulus);
  bn254_pair_fp2_conjugate(&q1.y, &a_affine.y, ctx->field_modulus);
  bn254_pair_fp2_mul(&q1.y, &q1.y, &ctx->xi_to_p_minus_1_over_2,
                     ctx->field_modulus);
  bn254_pair_fp2_set_one(&q1.z);
  bn254_pair_fp2_set_one(&q1.t);

  bn254_pair_fp2_mul(&minus_q2.x, &a_affine.x,
                     &ctx->xi_to_psquared_minus_1_over_3, ctx->field_modulus);
  bn254_pair_fp2_set(&minus_q2.y, &a_affine.y);
  bn254_pair_fp2_set_one(&minus_q2.z);
  bn254_pair_fp2_set_one(&minus_q2.t);

  bn254_pair_fp2_t a_line;
  bn254_pair_fp2_t b_line;
  bn254_pair_fp2_t c_line;
  bn254_pair_g2_t new_r;
  bn254_pair_fp2_init(&a_line);
  bn254_pair_fp2_init(&b_line);
  bn254_pair_fp2_init(&c_line);
  bn254_pair_g2_init(&new_r);

  bn254_pair_fp2_square(&r2, &q1.y, ctx->field_modulus);
  bn254_pair_line_function_add(&a_line, &b_line, &c_line, &new_r, &r, &q1,
                               &b_affine, &r2, ctx->field_modulus);
  bn254_pair_mul_line(out, &a_line, &b_line, &c_line, ctx->field_modulus);
  bn254_pair_g2_set(&r, &new_r);

  bn254_pair_fp2_square(&r2, &minus_q2.y, ctx->field_modulus);
  bn254_pair_line_function_add(&a_line, &b_line, &c_line, &new_r, &r, &minus_q2,
                               &b_affine, &r2, ctx->field_modulus);
  bn254_pair_mul_line(out, &a_line, &b_line, &c_line, ctx->field_modulus);

  bn254_pair_fp2_clear(&a_line);
  bn254_pair_fp2_clear(&b_line);
  bn254_pair_fp2_clear(&c_line);
  bn254_pair_g2_clear(&new_r);

  bn254_pair_g2_clear(&a_affine);
  bn254_pair_g1_clear(&b_affine);
  bn254_pair_g2_clear(&minus_a);
  bn254_pair_g2_clear(&r);
  bn254_pair_fp2_clear(&r2);
  bn254_pair_g2_clear(&q1);
  bn254_pair_g2_clear(&minus_q2);
}

static void bn254_pair_final_exponentiation(bn254_pair_fp12_t *out,
                                            const bn254_pair_fp12_t *in,
                                            const bn254_pair_ctx_t *ctx) {
  bn254_pair_fp12_t t1;
  bn254_pair_fp12_t inv;
  bn254_pair_fp12_t t2;
  bn254_pair_fp12_t fp;
  bn254_pair_fp12_t fp2;
  bn254_pair_fp12_t fp3;
  bn254_pair_fp12_t fu;
  bn254_pair_fp12_t fu2;
  bn254_pair_fp12_t fu3;
  bn254_pair_fp12_t y0;
  bn254_pair_fp12_t y1;
  bn254_pair_fp12_t y2;
  bn254_pair_fp12_t y3;
  bn254_pair_fp12_t y4;
  bn254_pair_fp12_t y5;
  bn254_pair_fp12_t y6;
  bn254_pair_fp12_t fu2p;
  bn254_pair_fp12_t fu3p;
  bn254_pair_fp12_t t0;
  bn254_pair_fp12_init(&t1);
  bn254_pair_fp12_init(&inv);
  bn254_pair_fp12_init(&t2);
  bn254_pair_fp12_init(&fp);
  bn254_pair_fp12_init(&fp2);
  bn254_pair_fp12_init(&fp3);
  bn254_pair_fp12_init(&fu);
  bn254_pair_fp12_init(&fu2);
  bn254_pair_fp12_init(&fu3);
  bn254_pair_fp12_init(&y0);
  bn254_pair_fp12_init(&y1);
  bn254_pair_fp12_init(&y2);
  bn254_pair_fp12_init(&y3);
  bn254_pair_fp12_init(&y4);
  bn254_pair_fp12_init(&y5);
  bn254_pair_fp12_init(&y6);
  bn254_pair_fp12_init(&fu2p);
  bn254_pair_fp12_init(&fu3p);
  bn254_pair_fp12_init(&t0);

  bn254_pair_fp6_negative(&t1.x, &in->x, ctx->field_modulus);
  bn254_pair_fp6_set(&t1.y, &in->y);

  (void)bn254_pair_fp12_invert(&inv, in, ctx->field_modulus);
  bn254_pair_fp12_mul(&t1, &t1, &inv, ctx->field_modulus);

  bn254_pair_fp12_frobenius_p2(&t2, &t1, ctx);
  bn254_pair_fp12_mul(&t1, &t1, &t2, ctx->field_modulus);

  bn254_pair_fp12_frobenius(&fp, &t1, ctx);
  bn254_pair_fp12_frobenius_p2(&fp2, &t1, ctx);
  bn254_pair_fp12_frobenius(&fp3, &fp2, ctx);

  bn254_pair_fp12_exp(&fu, &t1, ctx->bn_u, ctx->field_modulus);
  bn254_pair_fp12_exp(&fu2, &fu, ctx->bn_u, ctx->field_modulus);
  bn254_pair_fp12_exp(&fu3, &fu2, ctx->bn_u, ctx->field_modulus);

  bn254_pair_fp12_frobenius(&y3, &fu, ctx);
  bn254_pair_fp12_frobenius(&fu2p, &fu2, ctx);
  bn254_pair_fp12_frobenius(&fu3p, &fu3, ctx);
  bn254_pair_fp12_frobenius_p2(&y2, &fu2, ctx);

  bn254_pair_fp12_mul(&y0, &fp, &fp2, ctx->field_modulus);
  bn254_pair_fp12_mul(&y0, &y0, &fp3, ctx->field_modulus);

  bn254_pair_fp12_conjugate(&y1, &t1, ctx->field_modulus);
  bn254_pair_fp12_conjugate(&y5, &fu2, ctx->field_modulus);
  bn254_pair_fp12_conjugate(&y3, &y3, ctx->field_modulus);
  bn254_pair_fp12_mul(&y4, &fu, &fu2p, ctx->field_modulus);
  bn254_pair_fp12_conjugate(&y4, &y4, ctx->field_modulus);

  bn254_pair_fp12_mul(&y6, &fu3, &fu3p, ctx->field_modulus);
  bn254_pair_fp12_conjugate(&y6, &y6, ctx->field_modulus);

  bn254_pair_fp12_square(&t0, &y6, ctx->field_modulus);
  bn254_pair_fp12_mul(&t0, &t0, &y4, ctx->field_modulus);
  bn254_pair_fp12_mul(&t0, &t0, &y5, ctx->field_modulus);
  bn254_pair_fp12_mul(&t1, &y3, &y5, ctx->field_modulus);
  bn254_pair_fp12_mul(&t1, &t1, &t0, ctx->field_modulus);
  bn254_pair_fp12_mul(&t0, &t0, &y2, ctx->field_modulus);
  bn254_pair_fp12_square(&t1, &t1, ctx->field_modulus);
  bn254_pair_fp12_mul(&t1, &t1, &t0, ctx->field_modulus);
  bn254_pair_fp12_square(&t1, &t1, ctx->field_modulus);
  bn254_pair_fp12_mul(&t0, &t1, &y1, ctx->field_modulus);
  bn254_pair_fp12_mul(&t1, &t1, &y0, ctx->field_modulus);
  bn254_pair_fp12_square(&t0, &t0, ctx->field_modulus);
  bn254_pair_fp12_mul(&t0, &t0, &t1, ctx->field_modulus);

  bn254_pair_fp12_set(out, &t0);

  bn254_pair_fp12_clear(&t1);
  bn254_pair_fp12_clear(&inv);
  bn254_pair_fp12_clear(&t2);
  bn254_pair_fp12_clear(&fp);
  bn254_pair_fp12_clear(&fp2);
  bn254_pair_fp12_clear(&fp3);
  bn254_pair_fp12_clear(&fu);
  bn254_pair_fp12_clear(&fu2);
  bn254_pair_fp12_clear(&fu3);
  bn254_pair_fp12_clear(&y0);
  bn254_pair_fp12_clear(&y1);
  bn254_pair_fp12_clear(&y2);
  bn254_pair_fp12_clear(&y3);
  bn254_pair_fp12_clear(&y4);
  bn254_pair_fp12_clear(&y5);
  bn254_pair_fp12_clear(&y6);
  bn254_pair_fp12_clear(&fu2p);
  bn254_pair_fp12_clear(&fu3p);
  bn254_pair_fp12_clear(&t0);
}

static void bn254_pair_optimal_ate(bn254_pair_fp12_t *out,
                                   const bn254_pair_g2_t *a,
                                   const bn254_pair_g1_t *b,
                                   const bn254_pair_ctx_t *ctx) {
  bn254_pair_fp12_t e;
  bn254_pair_fp12_init(&e);
  bn254_pair_miller(&e, a, b, ctx);
  bn254_pair_final_exponentiation(out, &e, ctx);
  bn254_pair_fp12_clear(&e);

  if (bn254_pair_g2_is_infinity(a) || bn254_pair_g1_is_infinity(b)) {
    bn254_pair_fp12_set_one(out);
  }
}

static void bn254_pair_ctx_init(bn254_pair_ctx_t *ctx) {
  mpz_init_set_str(ctx->field_modulus,
                   "21888242871839275222246405745257275088696311157297823662689"
                   "037894645226208583",
                   10);
  mpz_init_set_str(ctx->group_order,
                   "21888242871839275222246405745257275088548364400416034343698"
                   "204186575808495617",
                   10);
  mpz_init_set_str(ctx->bn_u, "4965661367192848881", 10);

  bn254_pair_fp2_init(&ctx->xi);
  bn254_pair_fp2_init(&ctx->xi_to_p_minus_1_over_6);
  bn254_pair_fp2_init(&ctx->xi_to_p_minus_1_over_3);
  bn254_pair_fp2_init(&ctx->xi_to_p_minus_1_over_2);
  bn254_pair_fp2_init(&ctx->xi_to_2p_minus_2_over_3);
  bn254_pair_fp2_init(&ctx->xi_to_psquared_minus_1_over_3);
  bn254_pair_fp2_init(&ctx->xi_to_2psquared_minus_2_over_3);
  bn254_pair_fp2_init(&ctx->xi_to_psquared_minus_1_over_6);
  bn254_pair_fp2_init(&ctx->twist_b);

  // xi = i + 9.
  mpz_set_ui(ctx->xi.x, 1U);
  mpz_set_ui(ctx->xi.y, 9U);

  mpz_t exponent;
  mpz_t tmp;
  mpz_t psquared;
  mpz_init(exponent);
  mpz_init(tmp);
  mpz_init(psquared);

  mpz_sub_ui(exponent, ctx->field_modulus, 1U);
  mpz_fdiv_q_ui(exponent, exponent, 6U);
  bn254_pair_fp2_exp(&ctx->xi_to_p_minus_1_over_6, &ctx->xi, exponent,
                     ctx->field_modulus);

  mpz_sub_ui(exponent, ctx->field_modulus, 1U);
  mpz_fdiv_q_ui(exponent, exponent, 3U);
  bn254_pair_fp2_exp(&ctx->xi_to_p_minus_1_over_3, &ctx->xi, exponent,
                     ctx->field_modulus);

  mpz_sub_ui(exponent, ctx->field_modulus, 1U);
  mpz_fdiv_q_ui(exponent, exponent, 2U);
  bn254_pair_fp2_exp(&ctx->xi_to_p_minus_1_over_2, &ctx->xi, exponent,
                     ctx->field_modulus);

  mpz_mul_ui(exponent, ctx->field_modulus, 2U);
  mpz_sub_ui(exponent, exponent, 2U);
  mpz_fdiv_q_ui(exponent, exponent, 3U);
  bn254_pair_fp2_exp(&ctx->xi_to_2p_minus_2_over_3, &ctx->xi, exponent,
                     ctx->field_modulus);

  mpz_mul(psquared, ctx->field_modulus, ctx->field_modulus);

  mpz_sub_ui(exponent, psquared, 1U);
  mpz_fdiv_q_ui(exponent, exponent, 3U);
  bn254_pair_fp2_exp(&ctx->xi_to_psquared_minus_1_over_3, &ctx->xi, exponent,
                     ctx->field_modulus);

  mpz_mul_ui(exponent, psquared, 2U);
  mpz_sub_ui(exponent, exponent, 2U);
  mpz_fdiv_q_ui(exponent, exponent, 3U);
  bn254_pair_fp2_exp(&ctx->xi_to_2psquared_minus_2_over_3, &ctx->xi, exponent,
                     ctx->field_modulus);

  mpz_sub_ui(exponent, psquared, 1U);
  mpz_fdiv_q_ui(exponent, exponent, 6U);
  bn254_pair_fp2_exp(&ctx->xi_to_psquared_minus_1_over_6, &ctx->xi, exponent,
                     ctx->field_modulus);

  // twist_b = 3 / xi.
  bn254_pair_fp2_t three;
  bn254_pair_fp2_init(&three);
  bn254_pair_fp2_set_zero(&three);
  mpz_set_ui(three.y, 3U);
  bn254_pair_fp2_t xi_inv;
  bn254_pair_fp2_init(&xi_inv);
  (void)bn254_pair_fp2_invert(&xi_inv, &ctx->xi, ctx->field_modulus);
  bn254_pair_fp2_mul(&ctx->twist_b, &three, &xi_inv, ctx->field_modulus);
  bn254_pair_fp2_clear(&three);
  bn254_pair_fp2_clear(&xi_inv);

  // six_u_plus_2 NAF.
  mpz_mul_ui(tmp, ctx->bn_u, 6U);
  mpz_add_ui(tmp, tmp, 2U);
  ctx->six_u_plus_2_naf_len = 0U;
  while (mpz_sgn(tmp) > 0) {
    int8_t digit = 0;
    if (mpz_odd_p(tmp) != 0) {
      unsigned long mod4 = mpz_fdiv_ui(tmp, 4U);
      digit = (mod4 == 1U) ? 1 : -1;
      if (digit > 0) {
        mpz_sub_ui(tmp, tmp, 1U);
      } else {
        mpz_add_ui(tmp, tmp, 1U);
      }
    }
    if (ctx->six_u_plus_2_naf_len <
        (sizeof(ctx->six_u_plus_2_naf) / sizeof(ctx->six_u_plus_2_naf[0]))) {
      ctx->six_u_plus_2_naf[ctx->six_u_plus_2_naf_len++] = digit;
    }
    mpz_fdiv_q_2exp(tmp, tmp, 1U);
  }

  mpz_clear(exponent);
  mpz_clear(tmp);
  mpz_clear(psquared);
}

static void bn254_pair_ctx_clear(bn254_pair_ctx_t *ctx) {
  mpz_clear(ctx->field_modulus);
  mpz_clear(ctx->group_order);
  mpz_clear(ctx->bn_u);
  bn254_pair_fp2_clear(&ctx->xi);
  bn254_pair_fp2_clear(&ctx->xi_to_p_minus_1_over_6);
  bn254_pair_fp2_clear(&ctx->xi_to_p_minus_1_over_3);
  bn254_pair_fp2_clear(&ctx->xi_to_p_minus_1_over_2);
  bn254_pair_fp2_clear(&ctx->xi_to_2p_minus_2_over_3);
  bn254_pair_fp2_clear(&ctx->xi_to_psquared_minus_1_over_3);
  bn254_pair_fp2_clear(&ctx->xi_to_2psquared_minus_2_over_3);
  bn254_pair_fp2_clear(&ctx->xi_to_psquared_minus_1_over_6);
  bn254_pair_fp2_clear(&ctx->twist_b);
}

bool bn254_pairing_check(const uint8_t *input, size_t input_size,
                         bool *out_is_one) {
  if (out_is_one == nullptr) {
    return false;
  }
  *out_is_one = false;

  if (input_size > 0U && input == nullptr) {
    return false;
  }
  if ((input_size % 192U) != 0U) {
    return false;
  }

  bn254_pair_ctx_t ctx;
  bn254_pair_ctx_init(&ctx);

  bn254_pair_fp12_t acc;
  bn254_pair_fp12_init(&acc);
  bn254_pair_fp12_set_one(&acc);

  bool valid = true;
  const uint8_t *pair_input = input;
  size_t remaining = input_size;
  while (remaining > 0U) {
    bn254_pair_g1_t g1;
    bn254_pair_g2_t g2;
    bn254_pair_g1_init(&g1);
    bn254_pair_g2_init(&g2);

    valid = bn254_pair_parse_g1(pair_input, 192U, 0U, &ctx, &g1) &&
            bn254_pair_parse_g2(pair_input, 192U, 64U, &ctx, &g2);
    if (!valid) {
      bn254_pair_g1_clear(&g1);
      bn254_pair_g2_clear(&g2);
      break;
    }

    bn254_pair_fp12_t pair_value;
    bn254_pair_fp12_init(&pair_value);
    bn254_pair_optimal_ate(&pair_value, &g2, &g1, &ctx);
    bn254_pair_fp12_mul(&acc, &acc, &pair_value, ctx.field_modulus);
    bn254_pair_fp12_clear(&pair_value);

    bn254_pair_g1_clear(&g1);
    bn254_pair_g2_clear(&g2);

    pair_input += 192U;
    remaining -= 192U;
  }

  if (valid) {
    *out_is_one = bn254_pair_fp12_is_one(&acc);
  }

  bn254_pair_fp12_clear(&acc);
  bn254_pair_ctx_clear(&ctx);
  return valid;
}
