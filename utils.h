#ifndef NCR_UTILS_H
#define  NCR_UTILS_H

#include <linux/kernel.h>
#include <linux/netlink.h>

#define NCR_MAX_ATTR_SIZE 4096

struct nlattr;

struct ncr_out {
	void *buf, *p;
	size_t left;
	void __user *arg;
	size_t output_size_offset, fixed_size;
	u32 orig_output_size;
};

#define __NCR_VERIFY_FIXED_SIZE(fixed)					\
	(BUILD_BUG_ON(sizeof(*(fixed)) != NLA_ALIGN(sizeof(*(fixed)))))
#define __NCR_VERIFY_TB(tb) (BUILD_BUG_ON(ARRAY_SIZE(tb) != NCR_ATTR_MAX + 1))

extern u32 __ncr_u32_type_check;
#define __OUT_SIZE_OFF(fixed)						\
	((void)(&(fixed)->output_size == &__ncr_u32_type_check),	\
	 (char *)&(fixed)->output_size - (char *)(fixed))

/**
 * Load *@fixed and a sequence of netlink-like attributes from @arg.  @fixed
 * contains "input_size", which is an u32 filled with total input size,
 * including the attributes, which are parsed into @tb.
 */
#if 0
#define NCR_GET_INPUT_ARGS(fixed, tb, arg)			\
	(__NCR_VERIFY_FIXED_SIZE(fixed),			\
	 __NCR_VERIFY_TB(tb),					\
	 __ncr_get_input_args(fixed, tb, sizeof(*(fixed)),	\
			      &(fixed)->input_size, arg))
#else
#define NCR_GET_INPUT_ARGS(fixed, tb, arg)			\
	 __ncr_get_input_args(fixed, tb, sizeof(*(fixed)),	\
			      &(fixed)->input_size, arg)
#endif
void *__ncr_get_input_args(void *fixed, struct nlattr *tb[], size_t fixed_size,
			   u32 * input_size_ptr, const void __user * arg);

/**
 * Load *@fixed and a sequence of netlink-like attributes from @arg.  @fixed
 * contains "input_size", which is an u32 filled with total input size,
 * including the attributes, which are parsed into @tb.  In addition, indicate
 * to the user through u32 "output_size" that no output attributes will be
 * returned.
 */
#if 0
#define NCR_GET_INPUT_ARGS_NO_OUTPUT(fixed, tb, arg)			\
	(__NCR_VERIFY_FIXED_SIZE(fixed),				\
	 __NCR_VERIFY_TB(tb),						\
	 __ncr_get_input_args_no_output(fixed, tb, sizeof(*(fixed)),	\
					&(fixed)->input_size,		\
					__OUT_SIZE_OFF(fixed), arg))
#else
#define NCR_GET_INPUT_ARGS_NO_OUTPUT(fixed, tb, arg)			\
	 __ncr_get_input_args_no_output(fixed, tb, sizeof(*(fixed)),	\
					&(fixed)->input_size,		\
					__OUT_SIZE_OFF(fixed), arg)
#endif
void *__ncr_get_input_args_no_output(void *fixed, struct nlattr *tb[],
				     size_t fixed_size, u32 * input_size_ptr,
				     size_t output_size_offset,
				     void __user * arg);

/**
 * Return a new output attribute context for attributes of *@fixed.  @fixed
 * contains "output_size", an u32 containing total output size, including
 * @fixed.  Store @arg for later ncr_out_finish().
 */
#if 0
#define NCR_OUT_INIT(out, fixed, arg)				\
	(__NCR_VERIFY_FIXED_SIZE(fixed),			\
	 __ncr_out_init((out), (fixed), sizeof(*(fixed)),	\
			__OUT_SIZE_OFF(fixed), (arg)))
#else
#define NCR_OUT_INIT(out, fixed, arg)				\
	 __ncr_out_init((out), (fixed), sizeof(*(fixed)),	\
			__OUT_SIZE_OFF(fixed), (arg))
#endif
int __ncr_out_init(struct ncr_out *out, const void *fixed, size_t fixed_size,
		   size_t output_size_offset, void __user * arg);

/**
 * Write attributes from @out to user space and update user-space output_size.
 */
int ncr_out_finish(struct ncr_out *out);

void ncr_out_free(struct ncr_out *out);

int ncr_out_put(struct ncr_out *out, int attrtype, int attrlen,
		const void *data);

static inline int ncr_out_put_u32(struct ncr_out *out, int attrtype, u32 value)
{
	return ncr_out_put(out, attrtype, sizeof(value), &value);
}

static inline int ncr_out_put_string(struct ncr_out *out, int attrtype,
				     const char *value)
{
	return ncr_out_put(out, attrtype, strlen(value) + 1, value);
}

struct nlattr *ncr_out_reserve(struct ncr_out *out, int attrtype, int attrlen);

struct nlattr *ncr_out_begin_buffer(struct ncr_out *out, int attrtype);
void ncr_out_commit_buffer(struct ncr_out *out, int attrlen);

#endif
