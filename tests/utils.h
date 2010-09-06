#ifndef UTILS_H__
#define UTILS_H__

#include <string.h>
#include <stdint.h>

#include <linux/netlink.h>

#define NCR_MAX_REQUEST 4096

#define NCR_STRUCT(NAME) union {			\
		struct NAME f;				\
		unsigned char space[NCR_MAX_REQUEST];	\
	}

#define NCR_INIT(STRUCT)						\
	({								\
		memset(&(STRUCT).f, 0, sizeof((STRUCT).f));		\
		(struct nlattr *)((STRUCT).space + sizeof((STRUCT).f)); \
	})

static inline void *
ncr_reserve(struct nlattr **nla_p, uint16_t type, size_t size)
{
	struct nlattr *nla, x;
	void *ptr;
	size_t total_size;

	total_size = NLA_HDRLEN + size;
	x.nla_len = total_size;
	x.nla_type = type;
	nla = *nla_p;
	memcpy(nla, &x, sizeof(x));
	ptr = nla + 1;
	*nla_p = (struct nlattr *)((char *)nla + NLA_ALIGN(total_size));
	return ptr;
}

static inline void
ncr_put(struct nlattr **nla_p, uint16_t type, const void *value, size_t size)
{
	void *ptr;

	ptr = ncr_reserve(nla_p, type, size);
	memcpy(ptr, value, size);
}

static inline void
ncr_put_u32(struct nlattr **nla_p, uint16_t type, uint32_t value)
{
	return ncr_put(nla_p, type, &value, sizeof(value));
}

static inline void
ncr_put_string(struct nlattr **nla_p, uint16_t type, const char *value)
{
	return ncr_put(nla_p, type, value, strlen(value) + 1);
}

static inline void
ncr_put_session_input_data(struct nlattr **nla_p, uint16_t type,
			   const void *data, size_t data_size)
{
	struct ncr_session_input_data *in, x;

	in = ncr_reserve(nla_p, type, sizeof(*in));
	x.data = data;
	x.data_size = data_size;
	memcpy(in, &x, sizeof(x));
}

static inline void
ncr_put_session_output_buffer(struct nlattr **nla_p, uint16_t type,
			      void *buffer, size_t buffer_size,
			      size_t *result_size_ptr)
{
	struct ncr_session_output_buffer *out, x;

	out = ncr_reserve(nla_p, type, sizeof(*out));
	x.buffer = buffer;
	x.buffer_size = buffer_size;
	x.result_size_ptr = result_size_ptr;
	memcpy(out, &x, sizeof(x));
}

#define NCR_FINISH(STRUCT, NLA) do {					\
		(STRUCT).f.input_size = (char *)nla - (char *)&(STRUCT); \
	} while (0)

#endif
